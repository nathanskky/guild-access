<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

use Jumbojett\OpenIDConnectClient as OidcClient;
use Jumbojett\OpenIDConnectClientException as OidcClientException;

final readonly class OidcAuthenticationService
{
    private OidcClient $client;

    public function __construct(private OidcConfiguration $configuration)
    {
        $client = new OidcClient(
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
            // PROVISIONAL, pending live verification against IU's IdP: if IU supports
            // PKCE (even unadvertised) this hardens the flow; if IU rejects the
            // unexpected parameter and login breaks, set codeChallengeMethod: '' on
            // the configuration to disable it.
            $client->providerConfigParam([
                'code_challenge_methods_supported' => [$configuration->codeChallengeMethod],
            ]);
        }

        $this->client = $client;
    }

    /**
     * The complete OIDC guard, usable on its own without the middleware.
     *
     * Returns normally only when the caller may proceed (an unexpired login
     * already exists in the session). Otherwise it drives the flow and never
     * returns: it either redirects the browser to the IdP (first leg) or, once
     * the IdP redirects back with a code, validates it, records the login, and
     * redirects to the originally-requested URL (both via header()+exit).
     *
     * @throws OidcProviderErrorException if the IdP redirected back with an error
     * @throws OidcClientException on a token/JWT validation failure
     * @throws OidcAuthenticationServiceException if authentication otherwise fails
     */
    public function requireAuthentication(): void
    {
        if ($this->isAuthenticated()) {
            return;
        }

        // The IdP redirected back with an error (e.g. the user denied consent).
        if (isset($_GET['error'])) {
            $message = (string) $_GET['error'];
            if (isset($_GET['error_description'])) {
                $message .= ': ' . $_GET['error_description'];
            }
            throw new OidcProviderErrorException($message);
        }

        // First leg: no authorization code yet. Remember where the user was
        // headed before authenticate() bounces them to the IdP — that call
        // redirects and exits, so this is the only chance to capture it.
        if (!isset($_GET['code'])) {
            $_SESSION['guild_oidc_return_to'] = $_SERVER['REQUEST_URI'] ?? $this->configuration->defaultReturnUrl;
        }

        // Either exits to the IdP (no code) or validates the returned code.
        // authenticate() returns true only after the code, state, and ID token
        // have all been verified; guard the falsy path defensively.
        if (!$this->client->authenticate()) {
            throw new OidcAuthenticationServiceException('Authentication failed');
        }

        // Callback leg succeeded, and the client still holds the access and ID
        // tokens in memory — a fresh client on later requests will not. Persist
        // what those requests need before redirecting away.

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

        $returnTo = $_SESSION['guild_oidc_return_to'] ?? $this->configuration->defaultReturnUrl;
        unset($_SESSION['guild_oidc_return_to']);

        header('Location: ' . $returnTo);
        exit;
    }

    /**
     * Whether an unexpired login already exists in the session, meaning the
     * caller may proceed without contacting the IdP again.
     */
    public function isAuthenticated(): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

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
    public function getUserInfo(?string $attribute = null)
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $userInfo = $_SESSION['guild_oidc_user_info'] ?? null;

        if ($userInfo === null || $attribute === null) {
            return $userInfo;
        }

        return $userInfo->$attribute ?? null;
    }

    /**
     * Ends the login. Reads the ID token persisted at authentication time (the
     * fresh per-request client never holds it) and, if present, performs an
     * RP-initiated logout at the IdP's end_session_endpoint. Clears the local
     * session either way. Never returns — it redirects and exits.
     *
     * @throws OidcClientException
     */
    public function logout(?string $redirectUrl = null): never
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $idToken = $_SESSION['guild_oidc_id_token'] ?? null;
        unset(
            $_SESSION['guild_oidc_authenticated_until'],
            $_SESSION['guild_oidc_id_token'],
            $_SESSION['guild_oidc_user_info'],
            $_SESSION['guild_oidc_return_to'],
        );

        // RP-initiated logout requires the ID token as `id_token_hint`; it only
        // exists if the user actually completed a login. signOut() redirects to
        // the IdP and exits.
        if ($idToken !== null) {
            $this->client->signOut($idToken, $redirectUrl);
        }

        // Nothing to hand the IdP — just end the local session and redirect.
        header('Location: ' . ($redirectUrl ?? $this->configuration->defaultReturnUrl));
        exit;
    }
}