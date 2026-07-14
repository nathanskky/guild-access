<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\Exception\OidcConfigurationException;

final readonly class OidcConfiguration
{
    private const CODE_CHALLENGE_METHODS = ['S256', 'plain', ''];

    /**
     * @param string[] $scopes Additional OIDC scopes; `openid` is always included.
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
        /** Fallback landing after login/logout; must be a local path beginning with '/'. */
        public string $defaultReturnUrl = '/',
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
        // The fallback must itself be safe, or a rejected redirect would just land
        // on an unsafe default. Only local paths are permitted ('/' passes trivially).
        if (!$this->isRelativePath($defaultReturnUrl)) {
            throw new OidcConfigurationException(
                "defaultReturnUrl must be a local path beginning with '/' (given: '$defaultReturnUrl')."
            );
        }
    }

    /**
     * The candidate if it is a safe local-redirect target (a relative path),
     * otherwise the trusted defaultReturnUrl. Only local paths are accepted:
     * absolute URLs — attacker-influenced or not — are never emitted as redirect
     * targets, so this library cannot become an open redirect.
     */
    public function sanitizeRedirect(?string $candidate): string
    {
        if ($candidate !== null && $this->isRelativePath($candidate)) {
            return $candidate;
        }

        return $this->defaultReturnUrl;
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
}
