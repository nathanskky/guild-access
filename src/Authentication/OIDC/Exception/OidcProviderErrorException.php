<?php

declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC\Exception;

/**
 * Thrown when the identity provider redirects back with an `error`
 * (e.g. the user denied consent) instead of an authorization code.
 */
class OidcProviderErrorException extends OidcAuthenticationServiceException
{
}
