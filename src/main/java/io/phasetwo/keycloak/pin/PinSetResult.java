package io.phasetwo.keycloak.pin;

/**
 * Result of {@link io.phasetwo.keycloak.pin.credential.PinCredentialProvider#setPin}. Checks run in
 * declaration order after {@link #OK}: format, then strength, then confirmation.
 */
public enum PinSetResult {
  /** The PIN was stored. */
  OK,
  /** Not exactly the required number of digits, or contains non-digits. */
  INVALID_FORMAT,
  /** Rejected as weak (repeated digit or simple run) while reject-weak is on. */
  WEAK,
  /** The confirmation is missing or differs from the PIN. */
  MISMATCH
}
