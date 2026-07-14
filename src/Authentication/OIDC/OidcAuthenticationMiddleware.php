<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\Exception\OidcAuthenticationServiceException;
use Guild\Access\Authentication\OIDC\Exception\OidcProviderErrorException;
use Jumbojett\OpenIDConnectClientException as OidcClientException;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\Response\TextResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

final readonly class OidcAuthenticationMiddleware implements MiddlewareInterface
{
    public OidcAuthenticationService $authenticationService;

    public function __construct(
        OidcConfiguration $configuration,
        private ?LoggerInterface $logger = null,
    ) {
        $this->authenticationService = new OidcAuthenticationService($configuration, $logger);
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
            // The detail (attacker-controllable error/error_description) is logged
            // in the service; the client body stays generic to avoid reflecting it.
            return new TextResponse('OIDC login failed.', 400);
        } catch (OidcAuthenticationServiceException | OidcClientException $exception) {
            $this->logger?->warning('OIDC authentication failed', ['exception' => $exception]);
            return new EmptyResponse(401);
        } catch (\Throwable $exception) {
            // Not an authentication failure — a real fault (misconfig, network,
            // bug). Log it and let it propagate rather than masking it as a 401.
            $this->logger?->error('Unexpected error during OIDC authentication', ['exception' => $exception]);
            throw $exception;
        }
    }
}