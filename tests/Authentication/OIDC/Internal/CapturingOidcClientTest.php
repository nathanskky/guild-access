<?php declare(strict_types=1);

namespace Guild\Access\Test\Authentication\OIDC\Internal;

use Guild\Access\Authentication\OIDC\Internal\CapturingOidcClient;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CapturingOidcClient::class)]
final class CapturingOidcClientTest extends TestCase
{
    private function client(): CapturingOidcClient
    {
        // Construction is offline — jumbojett's constructor performs no discovery.
        return new CapturingOidcClient('https://idp.login.iu.edu', 'id', 'secret');
    }

    public function testNoRedirectCapturedInitially(): void
    {
        self::assertNull($this->client()->takeCapturedRedirect());
    }

    public function testRedirectCapturesUrlInsteadOfExiting(): void
    {
        $client = $this->client();

        $client->redirect('https://idp.example/authorize?state=abc');

        // Reaching this line at all proves redirect() did not exit.
        self::assertSame('https://idp.example/authorize?state=abc', $client->takeCapturedRedirect());
    }

    public function testTakeClearsTheCapturedUrl(): void
    {
        $client = $this->client();
        $client->redirect('https://idp.example/authorize');

        self::assertSame('https://idp.example/authorize', $client->takeCapturedRedirect());
        self::assertNull($client->takeCapturedRedirect(), 'a second take must not see a stale value');
    }

    public function testLatestRedirectWins(): void
    {
        $client = $this->client();

        $client->redirect('https://first.example');
        $client->redirect('https://second.example');

        self::assertSame('https://second.example', $client->takeCapturedRedirect());
    }
}
