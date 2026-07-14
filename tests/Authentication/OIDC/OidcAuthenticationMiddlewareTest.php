<?php declare(strict_types=1);

namespace Guild\Access\Test\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\OidcAuthenticationMiddleware;
use Guild\Access\Authentication\OIDC\OidcConfiguration;
use Laminas\Diactoros\Response\TextResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

#[CoversClass(OidcAuthenticationMiddleware::class)]
final class OidcAuthenticationMiddlewareTest extends TestCase
{
    private function middleware(): OidcAuthenticationMiddleware
    {
        return new OidcAuthenticationMiddleware(
            new OidcConfiguration('https://idp.login.iu.edu', 'id', 'secret', 'https://app.iu.edu/cb')
        );
    }

    /**
     * A handler that records whether it ran and returns a recognizable response.
     */
    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public bool $ran = false;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->ran = true;

                return new TextResponse('DOWNSTREAM', 200);
            }
        };
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testProviderErrorBecomesGeneric400WithoutReflectingInput(): void
    {
        session_start();

        $injection = '<script>alert(1)</script>';
        $request = (new ServerRequest())->withQueryParams([
            'error' => 'access_denied',
            'error_description' => $injection,
        ]);
        $handler = $this->handler();

        $response = $this->middleware()->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('OIDC login failed.', (string) $response->getBody());
        self::assertStringNotContainsString(
            $injection,
            (string) $response->getBody(),
            'attacker-controllable error_description must not be reflected'
        );
        self::assertFalse($handler->ran, 'the downstream handler must not run on failure');
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAuthenticatedRequestPassesToDownstreamHandler(): void
    {
        session_start();
        $_SESSION['guild_oidc_authenticated_until'] = time() + 3600;

        $handler = $this->handler();
        $response = $this->middleware()->process((new ServerRequest())->withQueryParams([]), $handler);

        self::assertTrue($handler->ran, 'an authenticated request continues down the pipeline');
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('DOWNSTREAM', (string) $response->getBody());
    }
}
