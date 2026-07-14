<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\Exception\OidcAuthenticationServiceException;
use Guild\Access\Authentication\OIDC\Exception\OidcProviderErrorException;
use Guild\Access\Authentication\OIDC\Internal\CapturingOidcClient;
use Jumbojett\OpenIDConnectClientException as OidcClientException;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\HttpHandlerRunner\Emitter\SapiEmitter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final readonly class OidcAuthenticationService
{
    private CapturingOidcClient $client;
    private LoggerInterface $logger;

    public function __construct(
        private OidcConfiguration $configuration,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();

        $client = new CapturingOidcClient(
            $configuration->providerUrl,
            $configuration->clientId,
            $configuration->clientSecret
        );

        $client->addScope($configuration->scopes);
        $client->setRedirectURL($configuration->redirectUri);

        if ($configuration->codeChallengeMethod !== '') {
            $client->setCodeChallengeMethod($configuration->codeChallengeMethod);

            // IU's discovery document omits `code_challenge_methods_supported`, and
            // jumbojett only sends PKCE when the configured method is listed there —
            // otherwise it silently skips PKCE. Inject the value to force the
            // code_challenge to be sent regardless of discovery.
            //
            // Verified against IU's IdP: S256 login succeeds, confirming IU supports
            // PKCE even though it isn't advertised in discovery. To disable PKCE,
            // set codeChallengeMethod: '' on the configuration.
            $client->providerConfigParam([
                'code_challenge_methods_supported' => [$configuration->codeChallengeMethod],
            ]);
        }

        $this->client = $client;
    }

    /**
     * The complete OIDC guard, exit-free and PSR-15-friendly.
     *
     * Returns null when the caller may proceed (an unexpired login already
     * exists in the session). Otherwise it returns a RedirectResponse the caller
     * must send: on the first leg, to the IdP; after a successful callback, to
     * the originally-requested URL. Request data (error/code/return-to) is read
     * from $request, falling back to the current PHP globals when none is given.
     *
     * @throws OidcProviderErrorException if the IdP redirected back with an error
     * @throws OidcClientException on a token/JWT validation failure
     * @throws OidcAuthenticationServiceException if authentication otherwise fails
     */
    public function guard(?ServerRequestInterface $request = null): ?ResponseInterface
    {
        $request ??= ServerRequestFactory::fromGlobals();

        if ($this->isAuthenticated()) {
            return null;
        }

        $query = $request->getQueryParams();

        // The IdP redirected back with an error (e.g. the user denied consent).
        if (isset($query['error'])) {
            $error = is_scalar($query['error']) ? (string) $query['error'] : '';
            $description = isset($query['error_description']) && is_scalar($query['error_description'])
                ? (string) $query['error_description']
                : null;

            // Log the full detail here; the exception message carries it too, but
            // callers must NOT echo it to the client — these values are
            // attacker-controllable query params (see the middleware).
            $this->logger->warning('OIDC provider returned an error', [
                'error' => $error,
                'error_description' => $description,
            ]);

            $message = $error . ($description !== null ? ': ' . $description : '');
            throw new OidcProviderErrorException($message);
        }

        // First leg: no authorization code yet. Remember where the user was
        // headed before we bounce them to the IdP (origin-form path?query).
        if (!isset($query['code'])) {
            $_SESSION['guild_oidc_return_to'] = $request->getRequestTarget();
        }

        // authenticate() returns true only after the code, state, and ID token
        // have all been verified. On the first leg it returns false *after* the
        // capturing client has stashed the IdP redirect URL (jumbojett would
        // otherwise header()+exit there), so a false return with a captured URL
        // is the redirect-to-IdP leg; a false return with none is a real failure.
        if (!$this->client->authenticate()) {
            $redirectUrl = $this->client->takeCapturedRedirect();
            if ($redirectUrl !== null) {
                return new RedirectResponse($redirectUrl);
            }

            $this->logger->error('OIDC authenticate() returned false without throwing');
            throw new OidcAuthenticationServiceException('Authentication failed');
        }

        // Callback leg succeeded. Regenerate the session ID before recording the
        // login so a pre-login (potentially fixated) ID can never carry over into
        // an authenticated session. Safe here: state/nonce validation is already
        // done, and regeneration preserves existing $_SESSION data (incl.
        // guild_oidc_return_to, read below).
        session_regenerate_id(true);

        // The client still holds the access and ID tokens in memory — a fresh
        // client on later requests will not. Persist what those requests need
        // before redirecting away.

        // The user info from the IdP's userinfo endpoint (authorized with the
        // access token, available only now), so getUserInfo() can serve it
        // from the session on later requests instead of re-calling the IdP.
        $_SESSION['guild_oidc_user_info'] = $this->client->requestUserInfo();

        // Bound the local login window to the ID token's own `exp`. Fail-safe: a
        // missing `exp` is treated as already-expired (re-validate next request)
        // rather than granting an unbounded session.
        $_SESSION['guild_oidc_authenticated_until'] = $this->client->getVerifiedClaims('exp') ?? time();

        // The raw ID token, needed as the `id_token_hint` for RP-initiated logout.
        $_SESSION['guild_oidc_id_token'] = $this->client->getIdToken();

        $this->logger->info('OIDC login established');

        $returnTo = $_SESSION['guild_oidc_return_to'] ?? null;
        unset($_SESSION['guild_oidc_return_to']);

        // Defense in depth: sanitize even though return-to is our own captured
        // origin-form request target, so it can never become an open redirect.
        return new RedirectResponse(
            $this->configuration->sanitizeRedirect(is_string($returnTo) ? $returnTo : null)
        );
    }

    /**
     * Legacy, self-emitting guard for traditional (non-PSR-15) scripts: drives
     * the flow with header()+exit and returns only once an unexpired login
     * exists. A thin wrapper over {@see guard()} for callers that don't work
     * with response objects.
     *
     * @throws OidcProviderErrorException if the IdP redirected back with an error
     * @throws OidcClientException on a token/JWT validation failure
     * @throws OidcAuthenticationServiceException if authentication otherwise fails
     */
    public function requireAuthentication(?ServerRequestInterface $request = null): void
    {
        $response = $this->guard($request);
        if ($response !== null) {
            $this->emit($response);
        }
    }

    /**
     * Start the PHP session if one is not already active, hardening the session
     * cookie first. Guarded on there being no active session, so it never
     * overrides an application that manages its own session/cookie params.
     */
    private function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        if (!headers_sent()) {
            session_set_cookie_params([
                'httponly' => true,
                'samesite' => 'Lax',
                'secure' => true,
            ]);
        }

        session_start();
    }

    /**
     * Whether an unexpired login already exists in the session, meaning the
     * caller may proceed without contacting the IdP again.
     */
    public function isAuthenticated(): bool
    {
        $this->startSession();

        return ($_SESSION['guild_oidc_authenticated_until'] ?? 0) > time();
    }

    /**
     * Returns the authenticated user's info, fetched from the IdP's userinfo
     * endpoint at login and persisted in the session (the per-request client no
     * longer holds the access token needed to fetch it). With no argument, returns
     * the full user info object; with an attribute name, returns that attribute.
     * Returns null if no user info is stored (the user is not authenticated) or
     * the requested attribute is absent.
     */
    public function getUserInfo(?string $attribute = null): mixed
    {
        $this->startSession();

        $userInfo = $_SESSION['guild_oidc_user_info'] ?? null;

        if ($userInfo === null || $attribute === null) {
            return $userInfo;
        }

        return $userInfo->$attribute ?? null;
    }

    /**
     * Ends the login and returns the redirect the caller must send (exit-free).
     * Reads the ID token persisted at authentication time (the fresh per-request
     * client never holds it) and, if present, returns an RP-initiated logout
     * redirect to the IdP's end_session_endpoint; otherwise a plain redirect.
     * Clears the local session either way.
     *
     * @throws OidcClientException
     */
    public function logoutResponse(?string $redirectUrl = null): ResponseInterface
    {
        $this->startSession();

        $idToken = $_SESSION['guild_oidc_id_token'] ?? null;
        unset(
            $_SESSION['guild_oidc_authenticated_until'],
            $_SESSION['guild_oidc_id_token'],
            $_SESSION['guild_oidc_user_info'],
            $_SESSION['guild_oidc_return_to'],
        );

        // Only an allowlisted absolute https URL is a valid post_logout_redirect_uri;
        // any other caller-supplied value is dropped so it can't become an open
        // redirect via the IdP (logout still proceeds, just without redirect-back).
        $postLogout = $this->configuration->postLogoutRedirect($redirectUrl);
        if ($postLogout === null && $redirectUrl !== null && !str_starts_with($redirectUrl, '/')) {
            $this->logger->warning('Ignoring post-logout redirect target not in allowedRedirectHosts', [
                'requested' => $redirectUrl,
            ]);
        }

        // RP-initiated logout requires the ID token as `id_token_hint`; it only
        // exists if the user actually completed a login. signOut() builds the
        // end_session URL and, via the capturing client, stashes it rather than
        // redirecting — so we wrap it in a response instead.
        if (is_string($idToken)) {
            $this->client->signOut($idToken, $postLogout);
            $endSessionUrl = $this->client->takeCapturedRedirect();
            if ($endSessionUrl !== null) {
                return new RedirectResponse($endSessionUrl);
            }
        }

        // Nothing to hand the IdP — just end the local session and redirect
        // (relative paths allowed; unsafe absolute targets fall back to default).
        return new RedirectResponse($this->configuration->sanitizeRedirect($redirectUrl));
    }

    /**
     * Legacy, self-emitting logout for traditional (non-PSR-15) scripts: ends
     * the login, redirects, and exits. A thin wrapper over {@see logoutResponse()}.
     *
     * @throws OidcClientException
     */
    public function logout(?string $redirectUrl = null): never
    {
        $this->emit($this->logoutResponse($redirectUrl));
    }

    /**
     * Emit a PSR-7 response to the SAPI (via SapiEmitter) and terminate. This is
     * the single place in the library that emits + exits; the legacy self-emitting
     * wrappers ({@see requireAuthentication()}, {@see logout()}) route through it
     * so the modern guard()/logoutResponse() path stays exit-free.
     */
    private function emit(ResponseInterface $response): never
    {
        (new SapiEmitter())->emit($response);
        exit;
    }
}