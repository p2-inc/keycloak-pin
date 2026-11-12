# keycloak-pin

<!-- phasetwo:banner:start - managed by p2-inc/shared-github-actions, edit there -->
[![build](https://img.shields.io/github/actions/workflow/status/p2-inc/keycloak-pin/ci.yml?branch=main&label=build)](https://github.com/p2-inc/keycloak-pin/actions/workflows/ci.yml) [![Maven Central](https://img.shields.io/maven-central/v/io.phasetwo.keycloak/keycloak-pin?label=maven%20central)](https://central.sonatype.com/artifact/io.phasetwo.keycloak/keycloak-pin) [![license](https://img.shields.io/badge/license-ELv2-blue)](COPYING)
<!-- phasetwo:banner:end -->

PIN codes for Keycloak: a `phasetwo-pin` credential, a browser authenticator, a set-PIN required action, a reset-credentials authenticator and account-console integration. A PIN is a short numeric secret used as a second factor or as the factor of a step-up. The extension leans on Keycloak's built-ins wherever they exist: PINs are hashed with Keycloak's own `argon2` password hash provider, configuration lives in the required-action config and the authenticator execution config, enrollment uses the built-in `Condition - user configured`, and resets use the built-in reset credentials flow and execute-actions email.

It is also the PIN service for Phase Two's native login (`native-auth-pin` in the native-apps project), which depends on this jar and calls the same API, so browser and native logins share one credential, one attempt counter and one lock.

Inspired by please-open.it's [PIN Code Authenticator](https://github.com/ldesroch/keycloak-pin-code-authenticator).

This extension is used in the [Phase Two](https://phasetwo.io) cloud offering, and is released here as part of its commitment to making its [core extensions](https://phasetwo.io/docs/introduction/open-source) open source. Please consult the [license](COPYING) for information regarding use.

## Compatibility

Keycloak 26.4 through 26.8. Built against 26.8; the integration tests run against both 26.8 and 26.4. Requires Keycloak's `argon2` password hash provider, which is present in every non-FIPS distribution.

## Install

Build with `mvn -B -DskipTests package` and copy `target/keycloak-pin-<version>.jar` into Keycloak's `providers/` directory, then run `kc.sh build` (or start with `start-dev`). The jar has no runtime dependencies beyond Keycloak.

Maven coordinates, for extensions that use the API: `io.phasetwo.keycloak:keycloak-pin`.

## Set up

### 1. Register the required action

In **Authentication → Required actions**, enable **Configure PIN** (`phasetwo-configure-pin`). The account console only offers PIN set-up when this action is enabled.

### 2. Add the PIN to the browser flow

Duplicate the **browser** flow and, inside the forms sub-flow after the step that identifies the user (for example **Username Password Form**), add a sub-flow:

```
Browser - PIN (copy of browser)
├── Cookie                                   ALTERNATIVE
└── Forms                                    ALTERNATIVE
    ├── Username Password Form               REQUIRED
    └── PIN sub-flow                         CONDITIONAL
        ├── Condition - user configured      REQUIRED
        └── PIN                              REQUIRED
```

With `Condition - user configured`, users who have a PIN must enter it and users without one skip the step. To make a PIN mandatory for everyone, set the **PIN** execution (or its sub-flow) to REQUIRED without the condition: users without a PIN then get the **Configure PIN** required action during login (standard Keycloak user setup through `isUserSetupAllowed`). Bind the new flow as the browser flow.

### 3. Add PIN reset to the reset credentials flow

Duplicate the **reset credentials** flow and add **Reset PIN** (`phasetwo-pin-reset`) as REQUIRED after **Send Reset Email**. When a user resets their credentials, Reset PIN removes their PIN (which also unlocks it) and sets the **Configure PIN** required action, so they choose a new PIN before the flow completes. Users without a PIN pass through untouched, so the execution needs no condition. Bind the flow as the reset credentials flow.

## Configuration

All configuration is per realm, through Keycloak's own configuration screens. There are no `Config.Scope` / `KC_SPI_*` settings.

**Configure PIN required action** (Authentication → Required actions → gear icon on Configure PIN):

| Key | Default | Description |
|---|---|---|
| `length` | `4` | Number of digits for new PINs, 4 to 12. Login uses the length stored with each user's PIN, so changing this does not break existing PINs. |
| `reject-weak` | `true` | Reject PINs made of one repeated digit (`1111`) or a simple ascending or descending run (`1234`, `9876`). |
| `max_auth_age` | Keycloak default | Keycloak's standard maximum authentication age for application-initiated actions. |

**PIN authenticator** (gear icon on the PIN execution):

| Key | Default | Description |
|---|---|---|
| `max-attempts` | `5` | Consecutive wrong PINs before the PIN is locked. `0` disables the PIN-specific limit (realm brute-force detection still applies). |

## Attempts and lockout

Each wrong PIN increments a failure counter stored on the credential and is also reported to realm brute-force detection as a normal failed login. The authenticator emits a `LOGIN_ERROR` event with error `invalid_user_credentials` and detail `credential_type=phasetwo-pin`. A correct PIN resets the counter. The page tells the user how many attempts remain.

When the counter reaches `max-attempts`, the PIN is locked: every later attempt fails without checking the hash (the event also carries `reason=pin_locked`) and the login page shows the locked state with instructions instead of the PIN field. A lock is never lifted by time. It is cleared only by a reset (below).

On every successful verification the PIN is re-hashed if Keycloak's argon2 parameters changed since it was set.

## Reset paths

- **The user**: "Forgot password?" on the sign-in page runs the reset credentials flow. With **Reset PIN** in that flow the PIN is removed and the user sets a new one.
- **An administrator**: delete the PIN on the user's **Credentials** tab (the user then signs in without a PIN when the flow uses `Condition - user configured`, or is asked to set one when the PIN is REQUIRED), or send the user an **execute actions** email with **Configure PIN** from the user's **Details** tab, or add **Configure PIN** to the user's required actions.
- **The application**: start a login with `kc_action=phasetwo-configure-pin` (application-initiated action) to let a signed-in user set or change their PIN.

## Account console

The PIN appears on the account console's *Signing in* page as a two-factor credential when the PIN authenticator is in an enabled flow and **Configure PIN** is enabled. Users without a PIN see "Set up PIN"; users with one see "Update" and can delete it. Set-up and update run the **Configure PIN** required action as an application-initiated action.

## Migrating from please-open.it's PIN Code Authenticator

We recommend switching to this extension rather than running both. Migration is best effort:

- When a user has no `phasetwo-pin` credential but has a `pin-code` credential hashed with `argon2`, the PIN authenticator verifies the entered PIN against it with Keycloak's argon2 provider. On success it creates a `phasetwo-pin` credential with the same PIN (and the length that PIN has) and removes the `pin-code` credential. The attempt counter and lock apply to `pin-code` credentials too until they are migrated.
- `pin-code` credentials are accepted on user and realm import, so a realm exported from a server running their extension can be imported into one that runs only this extension.
- Setting a new PIN removes any `pin-code` credential.
- Not migrated: their configuration (PIN format, custom regex, server-wide `Config.Scope` settings), their reset endpoint and action token, their custom hash SPI, and credentials hashed with anything other than `argon2`. Users with such credentials need a new PIN (reset credentials flow or an administrator).

Replace their authenticator, condition and required action in your flows with **PIN**, `Condition - user configured` and **Configure PIN**, then remove their jar.

## Developer API

`io.phasetwo.keycloak.pin.credential.PinCredentialProvider` is the PIN service used by the browser authenticator and required action and by native login. Use it rather than touching the credential directly; it never emits events (the caller does).

```java
PinCredentialProvider pins = PinCredentialProvider.get(session);

boolean has = pins.hasPin(realm, user);                 // phasetwo-pin, or a migratable pin-code
OptionalInt length = pins.getStoredLength(realm, user); // digits of the user's PIN, if known
boolean locked = pins.isLocked(realm, user);

int max = PinConfig.maxAttempts(context.getAuthenticatorConfig()); // the caller's execution config
PinVerification v = pins.verify(realm, user, pin, max);
switch (v.outcome()) {
  case VALID -> ...;                    // counter reset, re-hashed or migrated as needed
  case INVALID -> v.remainingAttempts(); // or PinVerification.UNLIMITED (-1) when max is 0
  case LOCKED -> ...;                    // remainingAttempts() == 0
  case NOT_CONFIGURED -> ...;
}

int required = pins.getRequiredLength(realm);           // Configure PIN's realm config, default 4
boolean rejectWeak = pins.isWeakPinRejected(realm);
PinSetResult r = pins.setPin(realm, user, pin, confirm); // OK, INVALID_FORMAT, WEAK, MISMATCH
pins.removePin(realm, user);
```

| Class | Purpose |
|---|---|
| `PinCredentialProvider` | The service above, plus the `CredentialProvider` for `phasetwo-pin`. |
| `PinVerification` | `verify` result: `outcome()` (`VALID`, `INVALID`, `LOCKED`, `NOT_CONFIGURED`) and `remainingAttempts()`. The wrong attempt that reaches `max-attempts` returns `LOCKED`. |
| `PinSetResult` | `setPin` result. Checks run in order: format (exactly the required number of ASCII digits), strength, confirmation. |
| `PinConfig` | Reads `max-attempts` from an execution config and `length` / `reject-weak` from the required-action config; `AUTHENTICATOR_PROPERTIES` and `REQUIRED_ACTION_PROPERTIES` for factories that expose the same settings. |
| `PinConstants` | Provider ids (`phasetwo-pin`, `phasetwo-configure-pin`, `phasetwo-pin-reset`), the credential type, config keys, defaults, form parameter names (`pin`, `pin_confirm`) and the `pin_locked` event reason. |
| `PinPolicy` | Pure format and weak-PIN rules. |

Authenticators that verify PINs should return `PinConstants.CREDENTIAL_TYPE` from `getReferenceCategory()` so the account console keeps offering the PIN when only they are in a flow, and report failures through `failureChallenge` so realm brute-force detection counts them.

### Credential layout

`credentialData`: `{"algorithm":"argon2","hashIterations":5,"additionalParameters":{"type":["id"],"version":["1.3"],"hashLength":["32"],"memory":["7168"],"parallelism":["1"]},"length":4,"failures":0,"locked":false}`. `secretData`: `{"value":"<base64 hash>","salt":"<base64 salt>"}`. One PIN per user; setting a new PIN updates the credential in place.

## Building and testing

```sh
mvn -B verify                               # unit + Testcontainers integration tests (Docker required)
mvn -B verify -Dkeycloak-version=26.4.7     # same suite against another Keycloak server image
mvn spotless:apply                          # google-java-format
```

Java 21. The integration tests start `quay.io/phasetwo/keycloak-crdb:<keycloak-version>` and MailHog with Testcontainers and drive the login pages over HTTP.

## Releases

Every merge to `main` is released to Maven Central; the PR title becomes the release note.

## License

[Elastic License 2.0](COPYING).
