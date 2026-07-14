<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\Exception\OidcConfigurationException;

final readonly class OidcConfiguration
{
    private const CODE_CHALLENGE_METHODS = ['S256', 'plain', ''];

    /**
     * @param string[] $scopes               Additional OIDC scopes; `openid` is always included.
     * @param string[] $allowedRedirectHosts Hosts permitted as absolute post-login/post-logout
     *                                        redirect targets. Relative paths are always allowed;
     *                                        absolute URLs are only honored when https and their
     *                                        host is listed here (everything else falls back to
     *                                        defaultReturnUrl).
     */
    public function __construct(
        // Identity & endpoint — the essentials
        public string $providerUrl,
        public string $clientId,
        public string $clientSecret,
        /** OIDC redirect_uri. Empty string = let the client auto-derive it from the request. */
        public string $redirectUri = '',
        public array $scopes = [],

        // Wrapper behavior
        /** PKCE method: 'S256', 'plain', or '' to disable. */
        public string $codeChallengeMethod = 'S256',
        /** Fallback landing URL after login when no original destination was captured. */
        public string $defaultReturnUrl = '/',
        public array $allowedRedirectHosts = [],
    ) {
        if (trim($providerUrl) === '') {
            throw new OidcConfigurationException('providerUrl must not be empty.');
        }
        if (trim($clientId) === '') {
            throw new OidcConfigurationException('clientId must not be empty.');
        }
        if (trim($clientSecret) === '') {
            throw new OidcConfigurationException('clientSecret must not be empty.');
        }
        if (!in_array($codeChallengeMethod, self::CODE_CHALLENGE_METHODS, true)) {
            throw new OidcConfigurationException(
                "codeChallengeMethod must be one of 'S256', 'plain', or '' (given: '$codeChallengeMethod')."
            );
        }
        // A non-empty redirectUri must have a host — jumbojett silently ignores a
        // hostless value and falls back to auto-derive, which would be surprising.
        if ($redirectUri !== '') {
            if (parse_url($redirectUri, PHP_URL_HOST) === null) {
                throw new OidcConfigurationException("redirectUri must be a valid URL with a host (given: '$redirectUri').");
            }
            // Require https; IU serves over TLS only, and anything else (http://,
            // ftp://, javascript:, …) would be handed to the browser as a redirect
            // target — a downgrade or injection risk.
            $scheme = strtolower((string) parse_url($redirectUri, PHP_URL_SCHEME));
            if ($scheme !== 'https') {
                throw new OidcConfigurationException("redirectUri must use https (given: '$redirectUri').");
            }
        }
        // The fallback must itself be a safe target, or a rejected redirect would
        // just land on an unsafe default. (A relative path, or an allowlisted
        // https URL; the default '/' passes trivially.)
        if (!$this->isRelativePath($defaultReturnUrl) && !$this->isAllowedAbsolute($defaultReturnUrl)) {
            throw new OidcConfigurationException(
                "defaultReturnUrl must be a local path or an https URL whose host is in allowedRedirectHosts (given: '$defaultReturnUrl')."
            );
        }
    }

    /**
     * The candidate if it is a safe local-redirect target — a relative path, or
     * an allowlisted https URL — otherwise the trusted defaultReturnUrl. Used for
     * the redirects this library emits itself (post-login return, post-logout
     * landing), so attacker-influenced values can't become open redirects.
     */
    public function sanitizeRedirect(?string $candidate): string
    {
        if ($candidate !== null && ($this->isRelativePath($candidate) || $this->isAllowedAbsolute($candidate))) {
            return $candidate;
        }

        return $this->defaultReturnUrl;
    }

    /**
     * The candidate if it is valid as an OIDC `post_logout_redirect_uri` — an
     * allowlisted absolute https URL — otherwise null (logout proceeds without a
     * redirect-back). A relative path is never a valid post_logout_redirect_uri.
     */
    public function postLogoutRedirect(?string $candidate): ?string
    {
        if ($candidate !== null && $this->isAllowedAbsolute($candidate)) {
            return $candidate;
        }

        return null;
    }

    /**
     * A safe same-site relative path: begins with a single '/', ruling out
     * protocol-relative ('//host') and backslash ('/\host') forms that browsers
     * resolve to an absolute, off-site URL.
     */
    private function isRelativePath(string $target): bool
    {
        return str_starts_with($target, '/')
            && !str_starts_with($target, '//')
            && !str_starts_with($target, '/\\');
    }

    /**
     * An absolute https URL whose host is in the allowlist (case-insensitive).
     */
    private function isAllowedAbsolute(string $target): bool
    {
        $scheme = strtolower((string) parse_url($target, PHP_URL_SCHEME));
        $host = parse_url($target, PHP_URL_HOST);

        return $scheme === 'https'
            && is_string($host)
            && in_array(strtolower($host), array_map('strtolower', $this->allowedRedirectHosts), true);
    }
}
