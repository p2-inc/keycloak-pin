# CLAUDE.md

## Build & Test Commands

```bash
mvn -B verify                                # unit + Testcontainers integration tests (Docker required)
mvn -B verify -Pcypress-tests,integration-tests  # what CI runs (adds JaCoCo; there are no Cypress tests)
mvn -B verify -Dkeycloak-version=26.4.7      # integration tests against another server image
mvn test -Dtest=PinBrowserFlowTest#setPin_validatesLengthMismatchAndWeak_thenStores
mvn spotless:apply                           # google-java-format, enforced at compile (ratchet from origin/main)
```

Java 21. Test image `quay.io/phasetwo/keycloak-crdb:<keycloak-version>` plus MailHog.

## Architecture Overview

A Keycloak provider jar (`@AutoService`, no framework). Spec: native-apps `spec/20-pin.md` (D1–D6 here; D7 is `native-auth-pin`, which depends on this jar).

- `PinConstants` — provider ids, credential type `phasetwo-pin`, config keys, defaults, form fields.
- `PinConfig` — reads `length`/`reject-weak` from the `phasetwo-configure-pin` required-action config and `max-attempts` from an authenticator execution config; config property lists.
- `PinPolicy`, `PinAttempts` — pure rules (format, weak PINs, counter/lock arithmetic).
- `PinVerification`, `PinSetResult` — results of the public API.
- `credential/PinCredentialProvider` (+Factory, id `phasetwo-pin`) — the public PIN service (`hasPin`, `getStoredLength`, `isLocked`, `verify`, `getRequiredLength`, `isWeakPinRejected`, `setPin`, `removePin`) and the `CredentialProvider`. Also claims the legacy `pin-code` type so it survives import.
- `credential/PinCredentialModel`, `PinCredentialData`, `PinSecretData` — stored layout; the hash is Keycloak's `argon2` `PasswordHashProvider` output.
- `credential/LegacyPinCredential` — read-only view of please-open.it `pin-code` credentials for migration (D6).
- `auth/PinAuthenticator` (+Factory, `phasetwo-pin`) — browser authenticator, thin over `verify`.
- `auth/PinResetAuthenticator` (`phasetwo-pin-reset`) — reset credentials flow step.
- `action/ConfigurePinRequiredAction` (+Factory, `phasetwo-configure-pin`) — set-PIN required action / AIA, thin over `setPin`.
- Templates `theme-resources/templates/phasetwo-pin-{login,setup}.ftl`, messages in `messages_en.properties`.

## Key Design Constraints

- No `Config.Scope`, no custom hash SPI, no REST endpoint, no action token: built-in config surfaces, `argon2`, reset credentials flow and execute-actions email only.
- The service never emits events; authenticators and required actions do.
- `CredentialTypeMetadata` may carry a create or an update action, never both: chosen by whether the user already has a PIN.
- Lock is cleared only by removing the credential (reset flow, admin delete) or setting a new PIN.

## Test Infrastructure

`it/AbstractPinIntegrationTest` — Keycloak + MailHog containers on one network, fresh `pin-test` realm from `realms/pin-realm.json` per test, cookie-aware `Browser` (custom cookie jar because Keycloak's cookies are `Secure`), MailHog polling. `Argon2Fixtures` builds stored credentials with BouncyCastle, independent of Keycloak's provider.
