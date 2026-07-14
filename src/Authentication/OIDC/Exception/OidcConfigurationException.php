<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC\Exception;

use InvalidArgumentException;

/**
 * Thrown when an OidcConfiguration is constructed with invalid values.
 * A configuration error is a setup mistake caught at construction, distinct
 * from the runtime OidcAuthenticationServiceException hierarchy.
 */
final class OidcConfigurationException extends InvalidArgumentException
{}
