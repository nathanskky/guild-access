<?php declare(strict_types=1);

namespace Shadow\Access\Authentication;

use League\Route\Http\Exception\UnauthorizedException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

readonly class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(private AuthenticationConfigurationInterface $configuration)
    {}

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // TODO: consider moving the instantiation of concrete classes into a factory, or similar?
        $authenticator = match ($this->configuration->getAuthenticationProtocol()) {
            AuthenticationProtocol::CAS => new CasAuthenticate($this->configuration),
            AuthenticationProtocol::OIDC => new OidcAuthenticate($this->configuration),
            default => throw new \Exception(), // TODO
        };

        $authenticator->authenticate();

        if ($authenticator->isAuthenticated()) {
            return $handler->handle($request);
        }

        // TODO: has to be handled by a strategy
        // TODO: actually, should probably just compose a 401 response and return it. (removes Router dependency)
        throw new UnauthorizedException();
    }
}