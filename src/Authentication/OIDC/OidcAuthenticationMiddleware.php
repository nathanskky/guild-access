<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

use Exception;
use Guild\Access\Authentication\OIDC\Exception\OidcProviderErrorException;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\Response\TextResponse;
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
     * A thin PSR-15 adapter over OidcAuthenticationService::requireAuthentication().
     * All of the flow logic (session window, error handling, return-to capture,
     * token exchange, redirects) lives in the service; this just maps failures to
     * HTTP responses. On the redirect legs the service exits before this returns.
     *
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $this->authenticationService->requireAuthentication();
            return $handler->handle($request);
        } catch (OidcProviderErrorException $exception) {
            return new TextResponse('OIDC login failed: ' . $exception->getMessage(), 400);
        } catch (Exception $exception) {
            return new EmptyResponse(401);
        }
    }
}