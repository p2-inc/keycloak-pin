package io.phasetwo.keycloak.pin;

/** Pure format and strength rules for PINs. No Keycloak state. */
public final class PinPolicy {

  private PinPolicy() {}

  /**
   * Whether {@code pin} consists of exactly {@code length} ASCII digits.
   *
   * @param pin the candidate PIN, may be null
   * @param length the required number of digits
   * @return true when well formed
   */
  public static boolean isWellFormed(String pin, int length) {
    if (pin == null || pin.length() != length) return false;
    for (int i = 0; i < pin.length(); i++) {
      char c = pin.charAt(i);
      if (c < '0' || c > '9') return false;
    }
    return true;
  }

  /**
   * Whether {@code pin} is weak: every digit the same (1111), or a simple ascending or descending
   * run without wrap-around (1234, 9876). Expects a well-formed PIN; returns false for anything
   * shorter than two characters.
   *
   * @param pin the candidate PIN
   * @return true when weak
   */
  public static boolean isWeak(String pin) {
    if (pin == null || pin.length() < 2) return false;
    boolean same = true;
    boolean ascending = true;
    boolean descending = true;
    for (int i = 1; i < pin.length(); i++) {
      int diff = pin.charAt(i) - pin.charAt(i - 1);
      same &= diff == 0;
      ascending &= diff == 1;
      descending &= diff == -1;
    }
    return same || ascending || descending;
  }

  /**
   * Clamps a configured length to {@link PinConstants#MIN_LENGTH}..{@link
   * PinConstants#MAX_LENGTH}.
   *
   * @param length configured length
   * @return clamped length
   */
  public static int clampLength(int length) {
    return Math.max(PinConstants.MIN_LENGTH, Math.min(PinConstants.MAX_LENGTH, length));
  }
}
