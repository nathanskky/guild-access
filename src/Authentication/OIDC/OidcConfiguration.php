<?php declare(strict_types=1);

namespace Shadow\Access\Authentication\OIDC;

final readonly class OidcConfiguration
{
    public function __construct(
        public string $providerUrl,
        public string $clientId,
        public string $clientSecret,
        public array $scopes = [],
        public string $certPath = ''
    ) {}
}