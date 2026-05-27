<?php declare(strict_types=1);

use Shadow\Access\Authentication\CAS\CasConfiguration;

$config = new CasConfiguration(
    host: 'idp-stg.login.iu.edu',
    serviceBaseUrl: 'http://localhost',
);

$config->sslValidate = false;
$config->debug = true;

return $config;