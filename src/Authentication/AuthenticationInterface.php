<?php declare(strict_types=1);

namespace Shadow\Access\Authentication;

interface AuthenticationInterface
{
    public function authenticate();

    public function isAuthenticated(): bool;

    public function getAuthenticatedUser(): ?AuthenticatedUser;
}