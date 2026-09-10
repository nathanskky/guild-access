# AGENTS.md

Guidance for AI coding agents (and new humans) working in this repository.

## What this is

`guild/access` — IU Login (OIDC) authentication for PHP: a validating configuration object, an
authentication service, and a PSR-15 middleware, built on `jumbojett/openid-connect-php`. Namespace
`Guild\Access\`, autoloaded from `src/`. Consumed as a Composer dependency; not runnable on its own.

- **PHP:** `>=8.2 <8.6`
- **Remote:** `https://github.com/nathanskky/guild-access.git` (HTTPS)
- **Default branch:** `develop` (`origin/HEAD` points there). A `main` branch also exists. **Work targets
  `develop`** — see [Branching and pull requests](#branching-and-pull-requests).
- **`composer.lock` is gitignored** here, so there is no lock to keep in sync.
- **Authentication is OIDC-only.** CAS support was removed from this library. (Apache's `mod_auth_cas` is
  still a valid *deployment-level* auth choice for some apps — see `starter/AGENTS.md` — but it does not
  involve this package.)

ACM/Grouper authorization and IU external (Guest) account support are described as planned in
`composer.json`, but **no such code exists in this package today**.

> **`README.md` is the authoritative reference for this library's public API** — config fields,
> redirect-safety behavior, session handling, logging, and error types. Read it before touching
> `src/Authentication/OIDC/*`. This file covers *developing* the package; the README covers *using* it.

## Sibling packages

These four repos are developed side by side but are **four independent git repos**. There is no root
`composer.json` and no root git repository, so each is cloned and installed on its own. Do not invent
root-level tooling or a shared root autoloader.

| Package | Namespace | Role |
|---|---|---|
| `guild/access` *(this one)* | `Guild\Access\` | IU Login (OIDC) authentication library |
| `guild/framework` | `Guild\Framework\` | Application kernel / DI container. **Depends on this package** (`^1.0`) and exposes it via `ApplicationBuilder::addAuthentication()` |
| `guild/starter` | `Guild\Starter\` | Runnable example app. Also depends on this package **directly** (`^1.0`), so a version bump must satisfy two constraints |
| `iu/notifications` | `IU\Notifications\` | IU Notifications API client. Fully independent — different GitHub host and an incompatible PHP constraint |

This package has **no first-party dependencies** — it is the bottom of the stack. If you change auth
behavior, trace the consumer side too: `framework/src/ServiceProvider/AuthenticationServiceProvider.php`
and `starter/config/authentication.php`.

## Verify your change

**Dependencies are not installed in a fresh clone, and `vendor/bin/` will be empty until you install.**
Nothing here can be verified before that.

```bash
composer install    # required first; see the note below
composer test       # phpunit, suite "guild-access"
composer analyse    # phpstan, level max, scoped to src/
composer check      # test then analyse; stops at the first failure
```

**This package is fully green, and it is the only one in the workspace that is. Keep it that way.**
On a clean checkout with dependencies installed, both checks pass:

```
composer test      →  OK (42 tests, 85 assertions)
composer analyse   →  [OK] No errors
```

That makes the bar here unambiguous: unlike the sibling packages, you do **not** need to take a baseline
first to tell your failures from pre-existing ones. Any failure is yours. Note that PHPStan runs at level
`max` — the strictest setting in the workspace — so it will reject imprecise types that `framework` (10) or
`notification` (5) would let through.

**If `composer install` fails to authenticate against github.com**, that is a credential problem on your
machine, not a repository problem. Composer downloads dependency archives through the GitHub API and needs a
valid token in `~/.composer/auth.json` (or `COMPOSER_AUTH`). Symptom:

```
Failed to download <package> from dist: Could not authenticate against github.com
```

An expired or revoked personal access token produces this even for public packages. Fix the token rather
than working around it — and note that the global `source-fallback` setting may be `false`, in which case
`--prefer-source` will not rescue you.

`phpunit.xml.dist` is strict: `failOnWarning`, `failOnRisky`, `failOnEmptyTestSuite`, and
`beStrictAboutOutputDuringTests` are all on. It sets `ignoreIndirectDeprecations="true"` on purpose — to
swallow `jumbojett`'s implicitly-nullable-parameter deprecations on PHP 8.4+ so only this package's own
deprecations surface.

## Architecture

```
src/Authentication/OIDC/
├── OidcConfiguration.php              final readonly · validating constructor, sanitizeRedirect()
├── OidcAuthenticationService.php      final readonly · the engine
├── OidcAuthenticationMiddleware.php   final readonly · thin PSR-15 adapter
├── Internal/
│   └── CapturingOidcClient.php        final · @internal · extends Jumbojett\OpenIDConnectClient
└── Exception/
    ├── OidcAuthenticationServiceException.php   extends Exception (root of the runtime chain)
    ├── OidcProviderErrorException.php           extends the above
    └── OidcConfigurationException.php           final · extends InvalidArgumentException
```

Layout is **feature-first and deeply nested**, with `Internal/` for classes outside the public API. Every
class is prefixed `Oidc`; note the directory is `OIDC` (uppercase) while the classes are `Oidc` (studly) —
PSR-4 resolves on the directory name, so `Guild\Access\Authentication\OIDC\OidcConfiguration`.

**Exception hierarchy is deliberate:** setup errors extend `InvalidArgumentException`; runtime errors form
a chain rooted at `OidcAuthenticationServiceException`. `OidcConfigurationException` is `final`, but the
other two are *not* — because one extends the other. Exceptions carry only a docblock and `{}`: no custom
methods, no named constructors.

**Two API styles coexist** (see `README.md` for signatures): a legacy self-exiting style
(`requireAuthentication()`, `logout()`, with `logout(): never`) and a modern PSR-7-returning style
(`guard()`, `logoutResponse()`). Prefer the modern one in new code.

`CapturingOidcClient` exists to work around IU's discovery document around PKCE; its 22-line class docblock
explains why. Read it before changing anything in the client path.

## Conventions

**Match the file you are editing. Do not reformat existing code as a side effect of your change.** The
patterns below are *observed*, not a style guide — they emerged organically rather than by decision. When a
formatter/linter lands in this repo, its config becomes authoritative and this section should shrink to a
pointer at it.

- **`<?php declare(strict_types=1);` on one line.** Every PHP file in the workspace does this, with no
  exceptions. It departs from PSR-12 §3 deliberately; an agent that "fixes" it touches every file.
- **Empty class/method bodies use hugged `{}`** on the line after the signature. Do not expand them.
- **Everything here is `final`** (and mostly `final readonly`), unlike `guild/framework`, where only
  `Application` is final because consumers are expected to extend it. The only non-final classes here are
  the two exceptions that form an inheritance chain. Do not homogenize the two packages.
- **Comment density is high, and deliberately so.** This package carries explanatory block comments that
  record *rationale*, not restatement — the PKCE workaround, the local-only redirect policy, why a strict
  test flag is set. Match that density when editing; a subtle security decision here needs its reason
  written down.
- **PHPStan level is `max` here** — the strictest in the workspace (`framework` is 10, `notification` is 5,
  `starter` has none). Do not assume one bar.

**Test conventions — `tests/` here is the reference suite for the whole workspace.** 4 files covering
`Authentication/OIDC/**`, namespaced `Guild\Access\Test\` mirroring `src/`. If you need a model for how to
write a test in any Guild package, copy from here:

- `final class XxxTest extends TestCase` — plain PHPUnit `TestCase`; there is no project base class
- **attributes only**, never docblock annotations: `#[CoversClass]`, `#[DataProvider]`,
  `#[RunInSeparateProcess]`, `#[PreserveGlobalState(false)]`
- **static assertions** (`self::assertSame(...)`), nearly always with a third-argument message explaining
  the intent
- test method names are long prose sentences
- data providers are `public static` returning `iterable`, yielding `'label' => [...]`, with a
  `@return iterable<string, array{...}>` docblock
- fixtures are **private instance helper methods** on the test class (`config()`, `service()`,
  `middleware()`, `client()`)
- **no PHPUnit mocks at all.** Instead: real `Monolog\Handler\TestHandler` + `Logger` for log assertions
  (this is why `monolog/monolog` is a dev dependency), **anonymous classes** for PSR-15 collaborators, and
  real `Laminas\Diactoros\ServerRequest` built with `->withQueryParams([...])`
- **every session-touching test is `#[RunInSeparateProcess]` + `#[PreserveGlobalState(false)]`**, because
  the tests manipulate `$_SESSION` directly after `session_start()`
- network-dependent paths are explicitly scoped out in a class docblock rather than mocked

## Landmines

- **Session keys are a hard contract.** `guild_oidc_return_to`, `guild_oidc_user_info`,
  `guild_oidc_authenticated_until`, and `guild_oidc_id_token` are read and written across the service and
  asserted on directly in the tests. Never rename one piecemeal — and remember that renaming any of them is
  a breaking change for already-authenticated sessions in deployed apps.
- **Redirects are local-only by policy, not by accident.** `OidcConfiguration::sanitizeRedirect()` rejects
  non-local targets and falls back to `defaultReturnUrl`, and RP-initiated logout omits
  `post_logout_redirect_uri` on purpose. This is open-redirect hardening with tests asserting the warning
  log line. Do not "fix" it by allowing absolute URLs; read `README.md` first.
- **IU external (Guest) account support is parked work, not missing work.** A `Guild\Access\Guest`
  namespace (`Api`, `ExternalAccountService`, `ExternalAccountServiceFactory`, `Middleware`,
  `OAuthProvider`, plus an exception) was written and then set aside; it is untested, was never wired into
  `composer.json`, and needs `league/oauth2-client` and Guzzle — **neither of which is declared as a
  dependency**. Don't re-implement it from scratch without asking, and don't assume it works.
  It survives only as a **git stash on the original author's machine** (titled *"Guest external-account API
  (on hold)"*), so a fresh clone will not have it and `git stash list` will be empty for you. If you do have
  it, don't `git stash pop` casually — that drops non-installable code into a clean tree.
- **`.gitignore` has `*.env*` with no negation**, so you cannot commit an `.env.example` to this repo
  without changing `.gitignore` first.
- **`logs/` and `tmp/` may hold local request/session detail.** They are gitignored, but avoid pasting their
  contents into transcripts or issues.

## Branching and pull requests

**Do not commit directly to `develop` or `main`.** Work on a feature branch and open a pull request against
`develop`.

```bash
git checkout develop && git pull        # start from an up-to-date develop
git checkout -b <short-descriptive-name>
# ... commit your work ...
git push -u origin <short-descriptive-name>
```

Then open a PR **targeting `develop`**, not `main`. Nothing routine should land on `main` directly.

`composer check` should be green before you open the PR — this package is the only one in the workspace
where green is the normal state, so there is no excuse for a red PR here.

### Branch and release model

Three stages, and **tags live on `main`, never on `develop`**:

```
feature branch  --PR-->  develop  --PR-->  main  --> tag (release)
```

- **`develop`** accumulates day-to-day work. This is where your feature PR goes.
- **`main`** is the released state. `develop` is merged into it **via its own pull request** when the
  accumulated work is ready to release.
- **Tags are applied to `main`** after that merge. A tag is what makes a release visible to Composer.

This is the intended model across all four Guild packages. Not every package has reached v1 yet, so `main`
and tagging are not in use everywhere — but where they are, this is the flow, and new work should assume it.

## Getting a change to consumers

Consumers pull this package as a *downloaded zipball* from GitHub — there is no path repository and no
symlink. Editing `src/` here changes nothing in `framework` or `starter`, silently.

**This package is the one with a tag constraint, which makes it the fiddliest to publish.** Both
`guild/framework` and `guild/starter` require `^1.0` — a *tag* constraint, not a branch — so merging your
feature PR is **not enough**. A change only becomes visible to consumers once it is tagged, and tags are
cut from `main`:

1. Land your change on `develop` via a pull request.
2. **Merge `develop` into `main` via its own pull request** when the accumulated work is ready to release.
3. **Tag the release on `main`:**
   ```bash
   git checkout main && git pull
   git tag <next-version> && git push --tags
   ```
4. In each consumer, `composer update guild/access`. Remember `starter` requires it *directly* as well as
   transitively through `framework`, so both constraints must be satisfiable.

Steps 2 and 3 are release activities, not part of shipping a feature — so **"merged into `develop`" and
"released" are two different states**, usually separated in time. A consumer that appears not to see your
change has almost always hit exactly this: the code is on `develop`, but no new tag exists for `^1.0` to
resolve to.

While you are waiting on a release, use the path-repository loop below to develop against your local copy.

For a quick local iteration loop instead, temporarily add a path repository to the consumer's
`composer.json` above its VCS entries, and revert it before committing:

```json
{ "type": "path", "url": "../access", "options": { "symlink": true } }
```

**Never hand-edit `starter/vendor/guild/access/`** — the next `composer install` reverts it and your change
never reaches the real package.
