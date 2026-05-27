<?php declare(strict_types=1);

namespace Shadow\Access\Authentication\CAS;

use Psr\Log\LoggerInterface;

final class CasConfiguration
{
    public string $protocol = '2.0';

    public string $host;

    public int $port = 443;

    public string $context = '/idp/profile/cas/';

    public string $serviceBaseUrl;

    public bool $sslValidate = true;

    public ?string $caFile = null;

    public bool $debug = false;

    public ?LoggerInterface $logger = null;

    public function __construct(
        string $host,
        string $serviceBaseUrl,
        ?string $caFile = null,
        ?LoggerInterface $logger = null,
    ) {
        $this->host = $host;
        $this->serviceBaseUrl = $serviceBaseUrl;
        $this->caFile = $caFile;
        $this->logger = $logger;
    }
}