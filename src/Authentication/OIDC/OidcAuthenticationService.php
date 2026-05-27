<?php declare(strict_types=1);

namespace Shadow\Access\Authentication\OIDC;

use Jumbojett\OpenIDConnectClient as OidcClient;
use Jumbojett\OpenIDConnectClientException as OidcClientException;

final readonly class OidcAuthenticationService
{
    private OidcClient $client;

    public function __construct(OidcConfiguration $configuration)
    {
        $client = new OidcClient(
            $configuration->providerUrl,
            $configuration->clientId,
            $configuration->clientSecret
        );

        $client->addScope($configuration->scopes);
        $client->setCertPath($configuration->certPath);

        // TODO: additional client config

        $this->client = $client;
    }

    /**
     * @throws OidcClientException
     * @throws OidcAuthenticationServiceException
     */
    public function authenticate(): void
    {
        $successful = $this->client->authenticate();
        if (!$successful) {
            throw new OidcAuthenticationServiceException('Authentication failed');
        }
    }

    public function getVerifiedClaims(string $attribute = null)
    {
        return $this->client?->getVerifiedClaims($attribute);
    }
}