<?php declare(strict_types=1);

namespace Guild\Access\Authentication\CAS;

use Exception;
use Laminas\Diactoros\Response\EmptyResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class CasAuthenticationMiddleware implements MiddlewareInterface
{
    public CasAuthenticationService $authenticationService;

    public function __construct(CasConfiguration $configuration)
    {
        $this->authenticationService = new CasAuthenticationService($configuration);
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