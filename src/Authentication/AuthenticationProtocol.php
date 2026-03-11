<?php declare(strict_types=1);

namespace Shadow\Access\Authentication;

enum AuthenticationProtocol
{
    case CAS;
    case OIDC;
    // case SAML;
}