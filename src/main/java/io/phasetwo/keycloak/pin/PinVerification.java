package io.phasetwo.keycloak.pin;

/**
 * Result of {@link io.phasetwo.keycloak.pin.credential.PinCredentialProvider#verify}.
 *
 * @param outcome what happened
 * @param remainingAttempts wrong attempts left before the PIN locks; {@link #UNLIMITED} when the
 *     caller passed max-attempts 0, and 0 when {@link Outcome#LOCKED}. Only meaningful for {@link
 *     Outcome#INVALID} and {@link Outcome#LOCKED}.
 */
public record PinVerification(Outcome outcome, int remainingAttempts) {

  /** {@link #remainingAttempts()} value when there is no PIN-specific limit. */
  public static final int UNLIMITED = -1;

  /** Verification outcomes. */
  public enum Outcome {
    /** The PIN matched. The failure counter was reset. */
    VALID,
    /** The PIN did not match. The failure counter was incremented; the PIN is not locked. */
    INVALID,
    /**
     * The PIN is locked: either it was already locked (the hash was not checked), or this wrong
     * attempt reached max-attempts. Only a reset unlocks it.
     */
    LOCKED,
    /** The user has no PIN (neither {@code phasetwo-pin} nor a migratable {@code pin-code}). */
    NOT_CONFIGURED
  }

  /**
   * A successful verification.
   *
   * @return VALID result
   */
  public static PinVerification valid() {
    return new PinVerification(Outcome.VALID, UNLIMITED);
  }

  /**
   * A wrong PIN that did not lock the credential.
   *
   * @param remaining attempts left, or {@link #UNLIMITED}
   * @return INVALID result
   */
  public static PinVerification invalid(int remaining) {
    return new PinVerification(Outcome.INVALID, remaining);
  }

  /**
   * A locked credential.
   *
   * @return LOCKED result
   */
  public static PinVerification locked() {
    return new PinVerification(Outcome.LOCKED, 0);
  }

  /**
   * The user has no PIN.
   *
   * @return NOT_CONFIGURED result
   */
  public static PinVerification notConfigured() {
    return new PinVerification(Outcome.NOT_CONFIGURED, UNLIMITED);
  }

  /**
   * Whether the PIN matched.
   *
   * @return true for VALID
   */
  public boolean isValid() {
    return outcome == Outcome.VALID;
  }

  /**
   * Whether there is no PIN-specific attempt limit.
   *
   * @return true when remaining attempts are unlimited
   */
  public boolean isUnlimited() {
    return remainingAttempts == UNLIMITED;
  }
}
