<?php declare(strict_types=1);

namespace Shadow\Access\Authentication\OIDC;

use Exception;
use Laminas\Diactoros\Response\EmptyResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class OidcAuthenticationMiddleware implements MiddlewareInterface
{
    public OidcAuthenticationService $authenticationService;

    public function __construct(OidcConfiguration $configuration)
    {
        $this->authenticationService = new OidcAuthenticationService($configuration);
    }

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $this->authenticationService->authenticate();
            return $handler->handle($request);
        } catch (Exception $exception) {
            return new EmptyResponse(401);
        }
    }
}