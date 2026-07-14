<?php declare(strict_types=1);

namespace Guild\Access\Test\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\Exception\OidcProviderErrorException;
use Guild\Access\Authentication\OIDC\OidcAuthenticationService;
use Guild\Access\Authentication\OIDC\OidcConfiguration;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * Only the branches that do not depend on jumbojett's networked authenticate()
 * are unit-tested here; the client-driven flows (first-leg redirect capture,
 * callback success, RP-initiated logout) are exercised against the live IdP.
 *
 * Every test runs in a separate process because the service starts and mutates
 * the PHP session; isolation keeps session state from leaking between tests.
 */
#[CoversClass(OidcAuthenticationService::class)]
final class OidcAuthenticationServiceTest extends TestCase
{
    private function config(): OidcConfiguration
    {
        return new OidcConfiguration('https://idp.login.iu.edu', 'id', 'secret', 'https://app.iu.edu/cb');
    }

    private function service(?LoggerInterface $logger = null): OidcAuthenticationService
    {
        return new OidcAuthenticationService($this->config(), $logger);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testIsAuthenticatedReflectsTheSessionWindow(): void
    {
        session_start();

        $_SESSION['guild_oidc_authenticated_until'] = time() + 3600;
        self::assertTrue($this->service()->isAuthenticated(), 'a future window means authenticated');

        $_SESSION['guild_oidc_authenticated_until'] = time() - 1;
        self::assertFalse($this->service()->isAuthenticated(), 'an expired window means not authenticated');

        unset($_SESSION['guild_oidc_authenticated_until']);
        self::assertFalse($this->service()->isAuthenticated(), 'no window means not authenticated');
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testGuardReturnsNullWhenAlreadyAuthenticated(): void
    {
        session_start();
        $_SESSION['guild_oidc_authenticated_until'] = time() + 3600;

        $request = (new ServerRequest())->withQueryParams([]);

        self::assertNull($this->service()->guard($request), 'an authenticated caller may proceed');
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testGuardThrowsAndLogsOnProviderError(): void
    {
        session_start();

        $handler = new TestHandler();
        $logger = new Logger('test', [$handler]);

        $request = (new ServerRequest())->withQueryParams([
            'error' => 'access_denied',
            'error_description' => 'The user denied consent',
        ]);

        try {
            $this->service($logger)->guard($request);
            self::fail('Expected OidcProviderErrorException was not thrown.');
        } catch (OidcProviderErrorException $exception) {
            self::assertStringContainsString('access_denied', $exception->getMessage());
            self::assertStringContainsString('The user denied consent', $exception->getMessage());
        }

        self::assertTrue(
            $handler->hasWarningThatContains('OIDC provider returned an error'),
            'the provider error must be logged'
        );

        $context = $handler->getRecords()[0]['context'];
        self::assertSame('access_denied', $context['error']);
        self::assertSame('The user denied consent', $context['error_description']);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testGetUserInfoServesFromSession(): void
    {
        session_start();
        $service = $this->service();

        self::assertNull($service->getUserInfo(), 'null before any login');

        $info = (object) ['username' => 'jdoe', 'email' => 'jdoe@iu.edu'];
        $_SESSION['guild_oidc_user_info'] = $info;

        self::assertSame($info, $service->getUserInfo(), 'no argument returns the whole object');
        self::assertSame('jdoe', $service->getUserInfo('username'), 'a named attribute is returned');
        self::assertNull($service->getUserInfo('does_not_exist'), 'a missing attribute is null');
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testLogoutResponseWithoutIdTokenClearsSessionAndRedirects(): void
    {
        session_start();
        $_SESSION['guild_oidc_authenticated_until'] = time() + 3600;
        $_SESSION['guild_oidc_user_info'] = (object) ['username' => 'jdoe'];

        // A relative path is always a safe local redirect target (no allowlist needed).
        $response = $this->service()->logoutResponse('/goodbye');

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame(302, $response->getStatusCode());
        self::assertSame('/goodbye', $response->getHeaderLine('Location'));
        self::assertArrayNotHasKey('guild_oidc_authenticated_until', $_SESSION);
        self::assertArrayNotHasKey('guild_oidc_user_info', $_SESSION);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testLogoutResponseFallsBackToConfiguredReturnUrl(): void
    {
        session_start();

        $response = $this->service()->logoutResponse();

        self::assertSame('/', $response->getHeaderLine('Location'), 'defaultReturnUrl is used when none is given');
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testLogoutResponseRejectsDisallowedAbsoluteRedirectAndLogs(): void
    {
        session_start();
        $handler = new TestHandler();
        $logger = new Logger('test', [$handler]);

        // No id token → local fallback path; a non-allowlisted absolute target
        // must fall back to defaultReturnUrl and be logged (S5).
        $response = $this->service($logger)->logoutResponse('https://evil.example/phish');

        self::assertSame('/', $response->getHeaderLine('Location'));
        self::assertTrue($handler->hasWarningThatContains('Ignoring post-logout redirect target'));
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testLogoutResponseHonorsAllowlistedAbsoluteRedirect(): void
    {
        session_start();
        $config = new OidcConfiguration(
            'https://idp.login.iu.edu',
            'id',
            'secret',
            'https://app.iu.edu/cb',
            allowedRedirectHosts: ['app.iu.edu'],
        );

        // No id token → local fallback path; an allowlisted absolute target is kept.
        $response = (new OidcAuthenticationService($config))->logoutResponse('https://app.iu.edu/bye');

        self::assertSame('https://app.iu.edu/bye', $response->getHeaderLine('Location'));
    }
}
