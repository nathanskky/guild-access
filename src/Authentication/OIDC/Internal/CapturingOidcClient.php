<?php declare(strict_types=1);

namespace Guild\Access\Authentication\OIDC\Internal;

use Jumbojett\OpenIDConnectClient;

/**
 * Internal jumbojett client whose only change is to *capture* redirect URLs
 * instead of emitting them with header()+exit.
 *
 * jumbojett drives every redirect (to the IdP on the auth-request leg, and to
 * the end_session endpoint on logout) through {@see OpenIDConnectClient::redirect()},
 * which calls `header('Location: …')` and `exit`. That makes the surrounding
 * PSR-15 middleware impossible to satisfy: it can never return a response.
 *
 * Overriding redirect() to stash the URL rather than exit lets the caller turn
 * it into a PSR-7 RedirectResponse. Because the private requestAuthorization()
 * calls `$this->redirect()`, this override intercepts that leg too; once it
 * returns without exiting, authenticate() simply falls through to `return false`,
 * and the caller distinguishes "first leg, redirect captured" from a genuine
 * failure by whether {@see takeCapturedRedirect()} yields a URL.
 *
 * This reuses all of jumbojett's URL construction and its state/nonce/PKCE
 * generation and session commit — none of that security-sensitive logic is
 * reimplemented here.
 *
 * @internal Not part of the public API.
 */
final class CapturingOidcClient extends OpenIDConnectClient
{
    private ?string $capturedRedirectUrl = null;

    /**
     * Capture the URL instead of `header()`+`exit`. Signature intentionally
     * matches the parent (no return type declared there).
     *
     * @return void
     *
     * {@inheritDoc}
     */
    public function redirect(string $url)
    {
        $this->capturedRedirectUrl = $url;
    }

    /**
     * Return the most recently captured redirect URL and clear it, so a later
     * call on the same client instance cannot see a stale value. Null when no
     * redirect was captured since the last call.
     */
    public function takeCapturedRedirect(): ?string
    {
        $url = $this->capturedRedirectUrl;
        $this->capturedRedirectUrl = null;

        return $url;
    }
}
