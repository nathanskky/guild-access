<?php declare(strict_types=1);

namespace Shadow\Access\Authentication\OIDC;

final readonly class OidcConfiguration
{
    public function __construct(
        public string $providerUrl,
        public string $clientId,
        public string $clientSecret,
        public array $scopes = [],
        public string $certPath = '',
        public string $redirectUrl = '',
        public bool $verifyPeer = true,
        public bool $verifyHost = true,
        public bool $httpUpgradeInsecureRequests = true,
    ) {}
}