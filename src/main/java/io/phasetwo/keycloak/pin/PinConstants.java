package io.phasetwo.keycloak.pin;

/**
 * Provider ids, configuration keys, form parameter names and defaults shared by the PIN
 * credential, authenticators and required action. Other extensions (for example native login)
 * should reference these constants instead of repeating the literals.
 */
public final class PinConstants {

  private PinConstants() {}

  /**
   * Credential type and credential provider id. Also the reference category of every
   * authenticator that verifies a PIN, so the account console shows the credential when such an
   * authenticator is in an enabled flow.
   */
  public static final String CREDENTIAL_TYPE = "phasetwo-pin";

  /** Browser authenticator provider id ("PIN"). */
  public static final String AUTHENTICATOR_ID = "phasetwo-pin";

  /** Set-PIN required action provider id and alias ("Configure PIN"). */
  public static final String REQUIRED_ACTION_ID = "phasetwo-configure-pin";

  /** Reset-credentials flow authenticator provider id ("Reset PIN"). */
  public static final String RESET_AUTHENTICATOR_ID = "phasetwo-pin-reset";

  /**
   * Credential type written by please-open.it's PIN Code Authenticator. Read for best-effort
   * migration only.
   */
  public static final String LEGACY_CREDENTIAL_TYPE = "pin-code";

  /** Keycloak password hash provider id used to hash PINs. */
  public static final String HASH_ALGORITHM = "argon2";

  /** Required-action config key: number of digits a new PIN must have. */
  public static final String CONFIG_LENGTH = "length";

  /** Required-action config key: reject weak PINs (repeated digits, simple runs). */
  public static final String CONFIG_REJECT_WEAK = "reject-weak";

  /** Authenticator execution config key: wrong attempts before the PIN locks (0 = unlimited). */
  public static final String CONFIG_MAX_ATTEMPTS = "max-attempts";

  /** Default for {@link #CONFIG_LENGTH}. */
  public static final int DEFAULT_LENGTH = 4;

  /** Smallest allowed value for {@link #CONFIG_LENGTH}. */
  public static final int MIN_LENGTH = 4;

  /** Largest allowed value for {@link #CONFIG_LENGTH}. */
  public static final int MAX_LENGTH = 12;

  /** Default for {@link #CONFIG_REJECT_WEAK}. */
  public static final boolean DEFAULT_REJECT_WEAK = true;

  /** Default for {@link #CONFIG_MAX_ATTEMPTS}. */
  public static final int DEFAULT_MAX_ATTEMPTS = 5;

  /** {@link #CONFIG_MAX_ATTEMPTS} value meaning no PIN-specific limit. */
  public static final int UNLIMITED_ATTEMPTS = 0;

  /** Form parameter carrying the PIN. */
  public static final String FORM_PIN = "pin";

  /** Form parameter carrying the PIN confirmation when setting a PIN. */
  public static final String FORM_PIN_CONFIRM = "pin_confirm";

  /** Event {@code reason} detail value when an attempt is rejected because the PIN is locked. */
  public static final String EVENT_REASON_LOCKED = "pin_locked";
}
