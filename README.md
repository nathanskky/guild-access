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
| `redirectUri` | `string` | `''` | Registered redirect URI. Empty = auto-derived from the request. |
| `scopes` | `string[]` | `[]` | Extra scopes; `openid` is always included. |
| `codeChallengeMethod` | `string` | `'S256'` | PKCE method: `'S256'`, `'plain'`, or `''` to disable. |
| `defaultReturnUrl` | `string` | `'/'` | Where to land after login if no original URL was captured. |

Invalid configuration throws `OidcConfigurationException`.

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

```php
use Guild\Access\Authentication\OIDC\OidcAuthenticationService;

$auth = new OidcAuthenticationService($config);
$auth->requireAuthentication();   // returns once the user is authenticated

$username = $auth->getUserInfo('username');
```

### Logout

```php
$auth = new OidcAuthenticationService($config);
$auth->logout('https://your-app.webapps.iu.edu');
```

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
requireAuthentication(): void            // guard a request; sends the user to log in if needed
isAuthenticated(): bool                  // is there a current login?
getUserInfo(?string $attribute = null)   // a user claim, or all claims; null if not authenticated
logout(?string $redirectUrl = null)      // log out and redirect
```

## Errors

| Exception | When |
|-----------|------|
| `OidcConfigurationException` | Invalid configuration (at construction). |
| `OidcProviderErrorException` | The IdP returned an error (e.g. consent denied). |
| `OidcAuthenticationServiceException` | Authentication failed. |

All are under the `Guild\Access\Authentication\OIDC\Exception` namespace.
