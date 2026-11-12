package io.phasetwo.keycloak.pin.credential;

import io.phasetwo.keycloak.pin.PinAttempts;
import io.phasetwo.keycloak.pin.PinConfig;
import io.phasetwo.keycloak.pin.PinConstants;
import io.phasetwo.keycloak.pin.PinPolicy;
import io.phasetwo.keycloak.pin.PinSetResult;
import io.phasetwo.keycloak.pin.PinVerification;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * Credential provider for {@code phasetwo-pin} and the PIN service used by every PIN
 * authenticator and required action, browser or native. Obtain it with {@link
 * #get(KeycloakSession)}.
 *
 * <p>Public API (stable for {@code native-auth-pin}):
 *
 * <ul>
 *   <li>{@link #hasPin(RealmModel, UserModel)}, {@link #getStoredLength(RealmModel, UserModel)},
 *       {@link #isLocked(RealmModel, UserModel)}
 *   <li>{@link #verify(RealmModel, UserModel, String, int)} — applies the attempt counter, lockout,
 *       re-hash and please-open.it migration
 *   <li>{@link #getRequiredLength(RealmModel)}, {@link #isWeakPinRejected(RealmModel)}
 *   <li>{@link #setPin(RealmModel, UserModel, String, String)}, {@link #removePin(RealmModel,
 *       UserModel)}
 * </ul>
 *
 * <p>The service never emits events; callers do (authenticators: {@code INVALID_USER_CREDENTIALS}
 * with {@code credential_type=phasetwo-pin}; required actions: {@code UPDATE_CREDENTIAL}).
 */
@JBossLog
public class PinCredentialProvider
    implements CredentialProvider<PinCredentialModel>, CredentialInputValidator {

  private final KeycloakSession session;

  /**
   * Creates the provider for a session.
   *
   * @param session the Keycloak session
   */
  public PinCredentialProvider(KeycloakSession session) {
    this.session = session;
  }

  /**
   * The PIN credential provider of a session.
   *
   * @param session the Keycloak session
   * @return the provider
   */
  public static PinCredentialProvider get(KeycloakSession session) {
    return (PinCredentialProvider)
        session.getProvider(CredentialProvider.class, PinConstants.CREDENTIAL_TYPE);
  }

  // ---------------------------------------------------------------------------------------------
  // Public PIN API
  // ---------------------------------------------------------------------------------------------

  /**
   * Whether the user has a PIN: a {@code phasetwo-pin} credential, or a please-open.it {@code
   * pin-code} credential that can be migrated (argon2).
   *
   * @param realm the realm
   * @param user the user
   * @return true when the user has a PIN
   */
  public boolean hasPin(RealmModel realm, UserModel user) {
    return findStored(user).isPresent() || findLegacy(user).isPresent();
  }

  /**
   * The length of the user's PIN: the length stored on the credential, or the length implied by a
   * legacy {@code pin-code} format ({@code 4-digits} etc.). Empty when the user has no PIN or the
   * legacy format is a custom regex.
   *
   * @param realm the realm
   * @param user the user
   * @return the stored length if known
   */
  public OptionalInt getStoredLength(RealmModel realm, UserModel user) {
    Optional<PinCredentialModel> stored = findStored(user);
    if (stored.isPresent()) {
      int length = stored.get().getPinCredentialData().getLength();
      return length > 0 ? OptionalInt.of(length) : OptionalInt.empty();
    }
    return findLegacy(user).map(LegacyPinCredential::getLength).orElse(OptionalInt.empty());
  }

  /**
   * Whether the user's PIN is locked (spec D4). A locked PIN fails every attempt until it is reset.
   *
   * @param realm the realm
   * @param user the user
   * @return true when locked
   */
  public boolean isLocked(RealmModel realm, UserModel user) {
    Optional<PinCredentialModel> stored = findStored(user);
    if (stored.isPresent()) return stored.get().getPinCredentialData().isLocked();
    return findLegacy(user).map(LegacyPinCredential::isLocked).orElse(false);
  }

  /**
   * Verifies a PIN and applies spec D4: a wrong PIN increments the failure counter and locks the
   * PIN when the counter reaches {@code maxAttempts}; a locked PIN fails without checking the hash;
   * a correct PIN resets the counter and is re-hashed when Keycloak's argon2 parameters changed.
   * When the user has no {@code phasetwo-pin} but has a migratable please-open.it {@code pin-code}
   * credential, that is verified instead and, on success, replaced by a {@code phasetwo-pin}
   * credential with the same PIN (spec D6).
   *
   * <p>Realm brute-force protection is not touched here; authenticators report failures through
   * {@code failureChallenge} as usual.
   *
   * @param realm the realm
   * @param user the user
   * @param pin the PIN entered
   * @param maxAttempts the calling execution's {@code max-attempts} ({@link
   *     PinConfig#maxAttempts}); {@link PinConstants#UNLIMITED_ATTEMPTS} for no limit
   * @return the outcome and remaining attempts
   */
  public PinVerification verify(RealmModel realm, UserModel user, String pin, int maxAttempts) {
    Optional<PinCredentialModel> stored = findStored(user);
    if (stored.isPresent()) return verifyStored(realm, user, stored.get(), pin, maxAttempts);
    Optional<LegacyPinCredential> legacy = findLegacy(user);
    if (legacy.isPresent()) return verifyLegacy(realm, user, legacy.get(), pin, maxAttempts);
    return PinVerification.notConfigured();
  }

  /**
   * The number of digits a new PIN must have, from the {@code phasetwo-configure-pin} required
   * action's realm config ({@code length}, default 4).
   *
   * @param realm the realm
   * @return required length (4-12)
   */
  public int getRequiredLength(RealmModel realm) {
    return PinConfig.requiredLength(realm);
  }

  /**
   * Whether weak PINs are rejected, from the {@code phasetwo-configure-pin} required action's realm
   * config ({@code reject-weak}, default true).
   *
   * @param realm the realm
   * @return true when weak PINs are rejected
   */
  public boolean isWeakPinRejected(RealmModel realm) {
    return PinConfig.rejectWeak(realm);
  }

  /**
   * Validates and stores a new PIN. Checks, in order: exactly {@link #getRequiredLength} digits
   * ({@link PinSetResult#INVALID_FORMAT}), strength when {@link #isWeakPinRejected} ({@link
   * PinSetResult#WEAK}), confirmation equal to the PIN ({@link PinSetResult#MISMATCH}). On {@link
   * PinSetResult#OK} the user's {@code phasetwo-pin} credential is created or updated in place
   * (same id, failure counter and lock cleared) and any please-open.it {@code pin-code} credential
   * is removed.
   *
   * @param realm the realm
   * @param user the user
   * @param pin the new PIN
   * @param confirm the confirmation
   * @return the result
   */
  public PinSetResult setPin(RealmModel realm, UserModel user, String pin, String confirm) {
    if (!PinPolicy.isWellFormed(pin, getRequiredLength(realm))) return PinSetResult.INVALID_FORMAT;
    if (isWeakPinRejected(realm) && PinPolicy.isWeak(pin)) return PinSetResult.WEAK;
    if (confirm == null
        || !MessageDigest.isEqual(
            pin.getBytes(StandardCharsets.UTF_8), confirm.getBytes(StandardCharsets.UTF_8))) {
      return PinSetResult.MISMATCH;
    }
    storePin(realm, user, pin);
    return PinSetResult.OK;
  }

  /**
   * Removes the user's PIN: every {@code phasetwo-pin} and {@code pin-code} credential.
   *
   * @param realm the realm
   * @param user the user
   * @return true when something was removed
   */
  public boolean removePin(RealmModel realm, UserModel user) {
    List<String> ids =
        user.credentialManager()
            .getStoredCredentialsStream()
            .filter(
                c ->
                    PinConstants.CREDENTIAL_TYPE.equals(c.getType())
                        || PinConstants.LEGACY_CREDENTIAL_TYPE.equals(c.getType()))
            .map(CredentialModel::getId)
            .toList();
    ids.forEach(id -> user.credentialManager().removeStoredCredentialById(id));
    return !ids.isEmpty();
  }

  // ---------------------------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------------------------

  private PinVerification verifyStored(
      RealmModel realm, UserModel user, PinCredentialModel model, String pin, int maxAttempts) {
    PinCredentialData data = model.getPinCredentialData();
    if (data.isLocked()) return PinVerification.locked();

    PasswordCredentialModel hashed = model.toPasswordCredentialModel();
    PasswordHashProvider hash = hashProvider(data.getAlgorithm());
    boolean match = pin != null && !pin.isEmpty() && hash != null && hash.verify(pin, hashed);

    if (match) {
      boolean changed = data.getFailures() != 0;
      data.setFailures(0);
      if (needsRehash(realm, hash, data.getAlgorithm(), hashed)) {
        log.debugf("Re-hashing PIN of user %s", user.getId());
        model.applyHash(argon2().encodedCredential(pin, -1), data.getLength());
        changed = true;
      }
      if (changed) {
        model.writeData();
        user.credentialManager().updateStoredCredential(model);
      }
      return PinVerification.valid();
    }

    PinAttempts.AfterFailure after = PinAttempts.afterFailure(data.getFailures(), maxAttempts);
    data.setFailures(after.failures());
    data.setLocked(after.locked());
    model.writeData();
    user.credentialManager().updateStoredCredential(model);
    return after.locked() ? PinVerification.locked() : PinVerification.invalid(after.remaining());
  }

  private PinVerification verifyLegacy(
      RealmModel realm, UserModel user, LegacyPinCredential legacy, String pin, int maxAttempts) {
    if (legacy.isLocked()) return PinVerification.locked();
    PasswordHashProvider hash = argon2();
    boolean match =
        pin != null && !pin.isEmpty() && hash.verify(pin, legacy.toPasswordCredentialModel());
    if (match) {
      log.infof(
          "Migrating please-open.it pin-code credential of user %s to %s",
          user.getId(), PinConstants.CREDENTIAL_TYPE);
      storePin(realm, user, pin);
      return PinVerification.valid();
    }
    PinAttempts.AfterFailure after = PinAttempts.afterFailure(legacy.getFailures(), maxAttempts);
    user.credentialManager()
        .updateStoredCredential(legacy.withFailureState(after.failures(), after.locked()));
    return after.locked() ? PinVerification.locked() : PinVerification.invalid(after.remaining());
  }

  private boolean needsRehash(
      RealmModel realm, PasswordHashProvider current, String algorithm, PasswordCredentialModel m) {
    if (!PinConstants.HASH_ALGORITHM.equals(algorithm)) return true;
    try {
      return !current.policyCheck(realm.getPasswordPolicy(), m);
    } catch (RuntimeException e) {
      log.warnf(e, "Could not check PIN hash parameters; re-hashing");
      return true;
    }
  }

  private void storePin(RealmModel realm, UserModel user, String pin) {
    PasswordCredentialModel hashed = argon2().encodedCredential(pin, -1);
    Optional<PinCredentialModel> existing = findStored(user);
    if (existing.isPresent()) {
      PinCredentialModel model = existing.get();
      model.applyHash(hashed, pin.length());
      user.credentialManager().updateStoredCredential(model);
    } else {
      createCredential(realm, user, PinCredentialModel.create(hashed, pin.length()));
    }
    user.credentialManager()
        .getStoredCredentialsByTypeStream(PinConstants.LEGACY_CREDENTIAL_TYPE)
        .map(CredentialModel::getId)
        .toList()
        .forEach(id -> user.credentialManager().removeStoredCredentialById(id));
  }

  private Optional<PinCredentialModel> findStored(UserModel user) {
    return user.credentialManager()
        .getStoredCredentialsByTypeStream(PinConstants.CREDENTIAL_TYPE)
        .findFirst()
        .map(PinCredentialModel::createFromCredentialModel);
  }

  private Optional<LegacyPinCredential> findLegacy(UserModel user) {
    return user.credentialManager()
        .getStoredCredentialsByTypeStream(PinConstants.LEGACY_CREDENTIAL_TYPE)
        .map(LegacyPinCredential::parse)
        .filter(c -> c != null && c.isSupported())
        .findFirst();
  }

  private PasswordHashProvider hashProvider(String algorithm) {
    if (algorithm == null) return null;
    PasswordHashProvider p = session.getProvider(PasswordHashProvider.class, algorithm);
    if (p == null) log.warnf("PIN hash algorithm '%s' is not available", algorithm);
    return p;
  }

  private PasswordHashProvider argon2() {
    PasswordHashProvider p =
        session.getProvider(PasswordHashProvider.class, PinConstants.HASH_ALGORITHM);
    if (p == null) {
      throw new IllegalStateException(
          "Keycloak's argon2 password hash provider is not available; PINs cannot be hashed");
    }
    return p;
  }

  // ---------------------------------------------------------------------------------------------
  // CredentialProvider / CredentialInputValidator
  // ---------------------------------------------------------------------------------------------

  @Override
  public String getType() {
    return PinConstants.CREDENTIAL_TYPE;
  }

  /**
   * Also claims please-open.it's {@code pin-code} type, so those credentials survive a user or
   * realm import into a server that runs only this extension, and are listed in the consoles.
   */
  @Override
  public boolean supportsCredentialType(String type) {
    return PinConstants.CREDENTIAL_TYPE.equals(type)
        || PinConstants.LEGACY_CREDENTIAL_TYPE.equals(type);
  }

  @Override
  public CredentialModel createCredential(
      RealmModel realm, UserModel user, PinCredentialModel credentialModel) {
    if (credentialModel.getCreatedDate() == null) {
      credentialModel.setCreatedDate(Time.currentTimeMillis());
    }
    if (PinConstants.CREDENTIAL_TYPE.equals(credentialModel.getType())) {
      // one PIN per user
      findStored(user)
          .ifPresent(c -> user.credentialManager().removeStoredCredentialById(c.getId()));
    }
    return user.credentialManager().createStoredCredential(credentialModel);
  }

  @Override
  public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
    return user.credentialManager().removeStoredCredentialById(credentialId);
  }

  @Override
  public PinCredentialModel getCredentialFromModel(CredentialModel model) {
    return PinCredentialModel.createFromCredentialModel(model);
  }

  /**
   * Account console metadata. Keycloak allows either a create or an update action, not both: users
   * without a PIN get {@code createAction} ("Set up PIN"), users with one get {@code updateAction}
   * ("Update"); both point at {@link PinConstants#REQUIRED_ACTION_ID}.
   */
  @Override
  public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext ctx) {
    UserModel user = ctx == null ? null : ctx.getUser();
    RealmModel realm = session.getContext().getRealm();
    boolean hasPin = user != null && realm != null && hasPin(realm, user);
    return CredentialTypeMetadata.builder()
        .type(getType())
        .category(CredentialTypeMetadata.Category.TWO_FACTOR)
        .displayName("PIN")
        .helpText("Sign in with a short numeric PIN.")
        .iconCssClass("kcAuthenticatorDefaultClass")
        .createAction(hasPin ? null : PinConstants.REQUIRED_ACTION_ID)
        .updateAction(hasPin ? PinConstants.REQUIRED_ACTION_ID : null)
        .removeable(true)
        .build(session);
  }

  @Override
  public boolean supportsCredentialType(CredentialModel credential) {
    return supportsCredentialType(credential.getType());
  }

  @Override
  public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
    return supportsCredentialType(credentialType) && hasPin(realm, user);
  }

  /**
   * Verifies without a PIN-specific attempt limit (the lock is still honored and failures are
   * still counted). Authenticators should call {@link #verify(RealmModel, UserModel, String, int)}
   * with their execution's {@code max-attempts} instead.
   */
  @Override
  public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
    if (input == null || !supportsCredentialType(input.getType())) return false;
    return verify(realm, user, input.getChallengeResponse(), PinConstants.UNLIMITED_ATTEMPTS)
        .isValid();
  }

  @Override
  public void close() {}
}
