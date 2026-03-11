<?php
declare(strict_types=1);

namespace Shadow\Access\Authentication;

use phpCAS;

/**
 * Authentication via IU Login, using the CAS protocol.
 */
class CasAuthenticate implements AuthenticationInterface
{
    public function __construct(private readonly CasAuthenticationConfiguration $config)
    {
        $this->configure();
    }

    private function configure(): void
    {
        if ($this->config->debug && $this->config->logger) {
            phpCAS::setLogger($this->config->logger);
            phpCAS::setVerbose(true);
        }

        phpCAS::client(
            $this->config->protocol,
            $this->config->host,
            $this->config->port,
            $this->config->context,
            $this->config->serviceBaseUrl
        );

        if ($this->config->sslValidate) {
            phpCAS::setCasServerCACert($this->config->caFile);
        } else {
            phpCAS::setNoCasServerValidation();
        }
    }

    public function authenticate(): void
    {
        phpCAS::forceAuthentication(); // TODO: still the right option?
    }

    public function isAuthenticated(): bool
    {
        return phpCAS::isSessionAuthenticated(); // TODO: still the right option?
    }

    // TODO
    public function getAuthenticatedUser(): ?AuthenticatedUser
    {
        throw new \Exception('Not implemented');
    }
}