<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

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
        $client->setRedirectURL($configuration->redirectUrl);
        $client->setVerifyHost($configuration->verifyHost);
        $client->setVerifyPeer($configuration->verifyPeer);
        $client->setHttpUpgradeInsecureRequests($configuration->httpUpgradeInsecureRequests);

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

    /**
     * @throws OidcClientException
     */
    public function requestUserInfo(string $attribute = null) {
        return $this->client?->requestUserInfo($attribute);
    }
}