package io.phasetwo.keycloak.pin;

/**
 * Pure attempt-counting rules (spec D4): a wrong PIN increments the failure counter, and the
 * credential locks when the counter reaches max-attempts (unless max-attempts is 0).
 */
public final class PinAttempts {

  private PinAttempts() {}

  /**
   * State after a wrong attempt.
   *
   * @param failures new consecutive failure count
   * @param locked whether the credential is now locked
   * @param remaining attempts left ({@link PinVerification#UNLIMITED} when unlimited, 0 when
   *     locked)
   */
  public record AfterFailure(int failures, boolean locked, int remaining) {}

  /**
   * Applies one wrong attempt.
   *
   * @param failures consecutive failures before this attempt
   * @param maxAttempts configured limit, {@link PinConstants#UNLIMITED_ATTEMPTS} for none
   * @return the new state
   */
  public static AfterFailure afterFailure(int failures, int maxAttempts) {
    int next = Math.max(0, failures) + 1;
    if (maxAttempts <= PinConstants.UNLIMITED_ATTEMPTS) {
      return new AfterFailure(next, false, PinVerification.UNLIMITED);
    }
    if (next >= maxAttempts) {
      return new AfterFailure(next, true, 0);
    }
    return new AfterFailure(next, false, maxAttempts - next);
  }

  /**
   * Attempts left for a credential that is not locked.
   *
   * @param failures consecutive failures so far
   * @param maxAttempts configured limit, {@link PinConstants#UNLIMITED_ATTEMPTS} for none
   * @return remaining attempts, or {@link PinVerification#UNLIMITED}
   */
  public static int remaining(int failures, int maxAttempts) {
    if (maxAttempts <= PinConstants.UNLIMITED_ATTEMPTS) return PinVerification.UNLIMITED;
    return Math.max(0, maxAttempts - Math.max(0, failures));
  }
}
