<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\Exception\OidcConfigurationException;

final readonly class OidcConfiguration
{
    private const CODE_CHALLENGE_METHODS = ['S256', 'plain', ''];

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
    }
}
