<?php declare(strict_types=1);

namespace Shadow\Access\Authentication;

interface AuthenticationConfigurationInterface
{
    public function getAuthenticationProtocol(): AuthenticationProtocol;
}