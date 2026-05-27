<?php
declare(strict_types=1);

namespace Shadow\Access\Authentication\CAS;

use phpCAS;

final readonly class CasAuthenticationService
{
    public function __construct(CasConfiguration $configuration)
    {
        if ($configuration->debug && $configuration->logger) {
            phpCAS::setLogger($configuration->logger);
            phpCAS::setVerbose(true);
        }

        phpCAS::client(
            $configuration->protocol,
            $configuration->host,
            $configuration->port,
            $configuration->context,
            $configuration->serviceBaseUrl
        );

        if ($configuration->sslValidate) {
            phpCAS::setCasServerCACert($configuration->caFile);
        } else {
            phpCAS::setNoCasServerValidation();
        }
    }

    /**
     * @throws CasAuthenticationServiceException
     */
    public function authenticate(): void
    {
        $successful = phpCAS::forceAuthentication();
        if (!$successful) {
            throw new CasAuthenticationServiceException('Authentication failed');
        }
    }

    public static function getUser(): string
    {
        return phpCAS::getUser();
    }

    // TODO: Probably don't need. Likely always empty for CAS.
    public static function getAttributes(): array
    {
        return phpCAS::getAttributes();
    }
}