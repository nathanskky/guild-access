# guild/access

IU Login (OIDC) authentication service and middleware for PHP.

ACM/Grouper-based authorization and IU external (Guest) account functionality are
planned for future releases.

## Requirements

- PHP `>=8.2 <8.6`
- A registered OIDC client (id + secret) with a redirect URI for your app.

## Installation

Add the repository, then require the package:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/nathanskky/guild-access.git"
        }
    ]
}
```

```bash
composer require guild/access:^1.0
```

## Configuration

Construct an `OidcConfiguration` with named arguments:

```php
use Guild\Access\Authentication\OIDC\OidcConfiguration;

$config = new OidcConfiguration(
    providerUrl:  $_ENV['OIDC_ISSUER'], // e.g. 'https://idp.login.iu.edu'
    clientId:     $_ENV['OIDC_CLIENT_ID'],
    clientSecret: $_ENV['OIDC_CLIENT_SECRET'],
    redirectUri:  $_ENV['OIDC_REDIRECT_URI'], // e.g. 'https://your-app.webapps.iu.edu/signin-oidc'
    scopes:       ['profile', 'email'],
);
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `providerUrl` | `string` | *(required)* | Base URL of the OIDC provider. |
| `clientId` | `string` | *(required)* | Your client id. |
| `clientSecret` | `string` | *(required)* | Your client secret. |
| `redirectUri` | `string` | `''` | Registered redirect URI; must be an `https` URL when set. Empty = auto-derived from the request. |
| `scopes` | `string[]` | `[]` | Extra scopes; `openid` is always included. |
| `codeChallengeMethod` | `string` | `'S256'` | PKCE method: `'S256'`, `'plain'`, or `''` to disable. |
| `defaultReturnUrl` | `string` | `'/'` | Where to land after login if no original URL was captured. Must be a local path or an allowlisted https URL. |
| `allowedRedirectHosts` | `string[]` | `[]` | Hosts permitted as **absolute** post-login/post-logout redirect targets (see Redirects). |

Invalid configuration throws `OidcConfigurationException`.

### Redirects

Redirect targets this library emits (post-login landing, post-logout landing) are
validated to prevent open redirects:

- **Relative paths** (`/dashboard`) are always allowed.
- **Absolute URLs** are honored only when they are `https` and their host is listed in
  `allowedRedirectHosts`; anything else falls back to `defaultReturnUrl`.
- For RP-initiated logout, the `post_logout_redirect_uri` sent to the IdP must be an
  allowlisted absolute https URL. A non-allowlisted value is dropped — logout still
  completes, just without redirect-back — and logged if a logger is set. (Separately, the
  OIDC RP-Initiated Logout spec expects this URI to be pre-registered with the IdP, so an
  unregistered value may be rejected on the IdP side; confirm what IU Login requires.)

## Usage

### PSR-15 middleware

```php
use Guild\Access\Authentication\OIDC\OidcAuthenticationMiddleware;

$middleware = new OidcAuthenticationMiddleware($config);
// Add to your PSR-15 pipeline on the routes you want to protect.
```

Unauthenticated visitors are sent to the IdP and returned to the page they
requested. The request continues once authenticated; on failure it responds
`400` (IdP returned an error) or `401` (authentication failed).

### Standalone (no middleware)

The service exposes two styles, both first-class — pick the one that fits your app.

**Legacy / traditional scripts** — the service drives the redirect itself with
`header()` + `exit`, and returns only once the user is authenticated. Best for older
codebases that don't work with request/response objects:

```php
use Guild\Access\Authentication\OIDC\OidcAuthenticationService;

$auth = new OidcAuthenticationService($config);
$auth->requireAuthentication();   // redirects+exits as needed; returns once authenticated

$username = $auth->getUserInfo('username');
```

**Modern / response-returning** — `guard()` never exits. It returns a PSR-7
`ResponseInterface` you emit yourself (to the IdP on the first leg, or back to the
original URL after login), or `null` when the user may proceed:

```php
$auth = new OidcAuthenticationService($config);

if ($response = $auth->guard($request)) {
    // emit $response with your framework / SapiEmitter, then stop
    return $response;
}

$username = $auth->getUserInfo('username');
```

`guard()` accepts an optional `ServerRequestInterface`; omit it and the current PHP
globals are used.

### Logout

```php
// Legacy: redirects and exits.
$auth->logout('https://your-app.webapps.iu.edu');

// Modern: returns the redirect response for you to emit.
$response = $auth->logoutResponse('https://your-app.webapps.iu.edu');
```

An absolute logout target must be in `allowedRedirectHosts`, otherwise it's ignored and
logout falls back to `defaultReturnUrl`. See [Redirects](#redirects).

## Sessions

The service owns PHP session startup. When no session is already active it starts one
with hardened cookie flags — `HttpOnly`, `SameSite=Lax`, and `Secure` (IU serves over
HTTPS only, so the session cookie is never sent over plaintext). On a successful login the
session ID is regenerated to prevent session fixation. If your application starts its own
session first, the library uses it as-is and does not override your cookie settings —
configure `HttpOnly`/`Secure`/`SameSite` yourself in that case.

## Logging

`OidcAuthenticationService` and `OidcAuthenticationMiddleware` accept an optional PSR-3
`LoggerInterface` as their second constructor argument. When supplied, provider errors and
authentication failures are logged (IdP `error`/`error_description` detail is logged rather
than returned to the browser). Without a logger, nothing is logged.

```php
$auth = new OidcAuthenticationService($config, $logger);
$middleware = new OidcAuthenticationMiddleware($config, $logger);
```

## API

```php
// Modern (exit-free, PSR-15-friendly) — return the response, or null to proceed:
guard(?ServerRequestInterface $request = null): ?ResponseInterface
logoutResponse(?string $redirectUrl = null): ResponseInterface

// Legacy (self-emitting; header()+exit) — for traditional scripts:
requireAuthentication(?ServerRequestInterface $request = null): void
logout(?string $redirectUrl = null): never

isAuthenticated(): bool                       // is there a current login?
getUserInfo(?string $attribute = null): mixed // a user claim, or all claims; null if not authenticated
```

> **Note on sessions + emitters:** the library uses native PHP sessions, so the session
> cookie is sent through PHP's own `session_start()` machinery rather than the returned
> PSR-7 response. This is fine in a normal SAPI setup; just don't flush output before the
> response is emitted.

## Errors

| Exception | When |
|-----------|------|
| `OidcConfigurationException` | Invalid configuration (at construction). |
| `OidcProviderErrorException` | The IdP returned an error (e.g. consent denied). |
| `OidcAuthenticationServiceException` | Authentication failed. |

These are under the `Guild\Access\Authentication\OIDC\Exception` namespace
(`OidcProviderErrorException` extends `OidcAuthenticationServiceException`). In addition,
`Jumbojett\OpenIDConnectClientException` may surface from the guard/logout methods on a
token or JWT validation failure. The middleware maps `OidcProviderErrorException` to `400`
and both `OidcAuthenticationServiceException` and `Jumbojett\OpenIDConnectClientException`
to `401`; if you call `guard()`/`logoutResponse()` directly, catch them yourself.
