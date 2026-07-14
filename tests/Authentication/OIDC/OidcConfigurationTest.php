<?php declare(strict_types=1);

namespace Guild\Access\Test\Authentication\OIDC;

use Guild\Access\Authentication\OIDC\Exception\OidcConfigurationException;
use Guild\Access\Authentication\OIDC\OidcConfiguration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(OidcConfiguration::class)]
final class OidcConfigurationTest extends TestCase
{
    public function testValidFullConfigExposesAllValues(): void
    {
        $config = new OidcConfiguration(
            providerUrl: 'https://idp.login.iu.edu',
            clientId: 'client-id',
            clientSecret: 'client-secret',
            redirectUri: 'https://app.iu.edu/signin-oidc',
            scopes: ['profile', 'email'],
            codeChallengeMethod: 'S256',
            defaultReturnUrl: '/home',
        );

        self::assertSame('https://idp.login.iu.edu', $config->providerUrl);
        self::assertSame('client-id', $config->clientId);
        self::assertSame('client-secret', $config->clientSecret);
        self::assertSame('https://app.iu.edu/signin-oidc', $config->redirectUri);
        self::assertSame(['profile', 'email'], $config->scopes);
        self::assertSame('S256', $config->codeChallengeMethod);
        self::assertSame('/home', $config->defaultReturnUrl);
    }

    public function testMinimalConfigAppliesDefaults(): void
    {
        $config = new OidcConfiguration('https://idp.login.iu.edu', 'id', 'secret');

        self::assertSame('', $config->redirectUri, 'redirectUri defaults to empty (auto-derive)');
        self::assertSame([], $config->scopes);
        self::assertSame('S256', $config->codeChallengeMethod);
        self::assertSame('/', $config->defaultReturnUrl);
    }

    /**
     * @param array{0: string, 1: string, 2: string} $args providerUrl, clientId, clientSecret
     */
    #[DataProvider('blankRequiredFieldProvider')]
    public function testBlankRequiredFieldsAreRejected(array $args, string $expectedFragment): void
    {
        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expectedFragment, '/') . '/');

        new OidcConfiguration($args[0], $args[1], $args[2]);
    }

    /**
     * @return iterable<string, array{array{0: string, 1: string, 2: string}, string}>
     */
    public static function blankRequiredFieldProvider(): iterable
    {
        yield 'empty providerUrl'      => [['', 'id', 'secret'], 'providerUrl'];
        yield 'whitespace providerUrl' => [['   ', 'id', 'secret'], 'providerUrl'];
        yield 'empty clientId'         => [['https://idp', '', 'secret'], 'clientId'];
        yield 'whitespace clientId'    => [['https://idp', "\t", 'secret'], 'clientId'];
        yield 'empty clientSecret'     => [['https://idp', 'id', ''], 'clientSecret'];
        yield 'whitespace clientSecret' => [['https://idp', 'id', '  '], 'clientSecret'];
    }

    #[DataProvider('validCodeChallengeMethodProvider')]
    public function testValidCodeChallengeMethodsAreAccepted(string $method): void
    {
        $config = new OidcConfiguration('https://idp', 'id', 'secret', codeChallengeMethod: $method);

        self::assertSame($method, $config->codeChallengeMethod);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validCodeChallengeMethodProvider(): iterable
    {
        yield 'S256'     => ['S256'];
        yield 'plain'    => ['plain'];
        yield 'disabled' => [''];
    }

    public function testInvalidCodeChallengeMethodIsRejected(): void
    {
        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessageMatches('/codeChallengeMethod/');

        new OidcConfiguration('https://idp', 'id', 'secret', codeChallengeMethod: 'RS256');
    }

    public function testHttpsRedirectUriIsAccepted(): void
    {
        $config = new OidcConfiguration('https://idp', 'id', 'secret', redirectUri: 'https://app.iu.edu/cb');

        self::assertSame('https://app.iu.edu/cb', $config->redirectUri);
    }

    #[DataProvider('invalidRedirectUriProvider')]
    public function testInvalidRedirectUriIsRejected(string $redirectUri, string $expectedFragment): void
    {
        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expectedFragment, '/') . '/');

        new OidcConfiguration('https://idp', 'id', 'secret', redirectUri: $redirectUri);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidRedirectUriProvider(): iterable
    {
        yield 'http scheme'    => ['http://app.iu.edu/cb', 'must use https'];
        yield 'ftp scheme'     => ['ftp://app.iu.edu/cb', 'must use https'];
        yield 'no host'        => ['/relative/path', 'valid URL with a host'];
        yield 'bare string'    => ['not-a-url', 'valid URL with a host'];
    }

    // --- Redirect allowlist (S5) ---------------------------------------------

    private static function configWithAllowedHosts(string ...$hosts): OidcConfiguration
    {
        return new OidcConfiguration('https://idp', 'id', 'secret', allowedRedirectHosts: $hosts);
    }

    #[DataProvider('sanitizeRedirectProvider')]
    public function testSanitizeRedirectKeepsSafeTargetsAndFallsBackOtherwise(
        ?string $candidate,
        string $expected,
    ): void {
        // allowlist contains app.iu.edu; defaultReturnUrl is '/'
        self::assertSame($expected, self::configWithAllowedHosts('app.iu.edu')->sanitizeRedirect($candidate));
    }

    /**
     * @return iterable<string, array{?string, string}>
     */
    public static function sanitizeRedirectProvider(): iterable
    {
        yield 'relative path kept'          => ['/dashboard?tab=1', '/dashboard?tab=1'];
        yield 'allowlisted https kept'      => ['https://app.iu.edu/home', 'https://app.iu.edu/home'];
        yield 'allowlisted host any-case'   => ['https://APP.iu.edu/x', 'https://APP.iu.edu/x'];
        yield 'protocol-relative rejected'  => ['//evil.example/x', '/'];
        yield 'backslash trick rejected'    => ['/\\evil.example', '/'];
        yield 'non-allowlisted host reject' => ['https://evil.example/x', '/'];
        yield 'http downgrade rejected'     => ['http://app.iu.edu/x', '/'];
        yield 'null falls back'             => [null, '/'];
        yield 'empty falls back'            => ['', '/'];
    }

    #[DataProvider('postLogoutRedirectProvider')]
    public function testPostLogoutRedirectOnlyAllowsAllowlistedAbsoluteUrls(
        ?string $candidate,
        ?string $expected,
    ): void {
        self::assertSame($expected, self::configWithAllowedHosts('app.iu.edu')->postLogoutRedirect($candidate));
    }

    /**
     * @return iterable<string, array{?string, ?string}>
     */
    public static function postLogoutRedirectProvider(): iterable
    {
        yield 'allowlisted https kept'   => ['https://app.iu.edu/bye', 'https://app.iu.edu/bye'];
        yield 'relative path is not valid' => ['/bye', null];
        yield 'non-allowlisted rejected' => ['https://evil.example/bye', null];
        yield 'http rejected'            => ['http://app.iu.edu/bye', null];
        yield 'null stays null'          => [null, null];
    }

    public function testDefaultReturnUrlMustBeSafe(): void
    {
        // relative default is fine
        self::assertSame('/back', (new OidcConfiguration(
            'https://idp', 'id', 'secret', defaultReturnUrl: '/back'
        ))->defaultReturnUrl);

        // allowlisted absolute default is fine
        self::assertSame('https://app.iu.edu/', (new OidcConfiguration(
            'https://idp', 'id', 'secret', defaultReturnUrl: 'https://app.iu.edu/', allowedRedirectHosts: ['app.iu.edu']
        ))->defaultReturnUrl);
    }

    #[DataProvider('unsafeDefaultReturnUrlProvider')]
    public function testUnsafeDefaultReturnUrlIsRejected(string $defaultReturnUrl): void
    {
        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessageMatches('/defaultReturnUrl/');

        new OidcConfiguration('https://idp', 'id', 'secret', defaultReturnUrl: $defaultReturnUrl);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsafeDefaultReturnUrlProvider(): iterable
    {
        yield 'non-allowlisted absolute' => ['https://evil.example/'];
        yield 'protocol-relative'        => ['//evil.example'];
        yield 'http scheme'              => ['http://app.iu.edu/'];
    }
}
