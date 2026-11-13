package io.phasetwo.keycloak.pin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PinPolicyTest {

  @Test
  void wellFormedRequiresExactDigitCount() {
    assertTrue(PinPolicy.isWellFormed("0123", 4));
    assertTrue(PinPolicy.isWellFormed("123456789012", 12));
    assertFalse(PinPolicy.isWellFormed("123", 4));
    assertFalse(PinPolicy.isWellFormed("12345", 4));
    assertFalse(PinPolicy.isWellFormed(null, 4));
    assertFalse(PinPolicy.isWellFormed("", 4));
  }

  @ParameterizedTest
  @ValueSource(strings = {"12a4", "12 4", "-123", "１２３４", "12.4"})
  void wellFormedRejectsNonAsciiDigits(String pin) {
    assertFalse(PinPolicy.isWellFormed(pin, 4));
  }

  @ParameterizedTest
  @ValueSource(strings = {"0000", "1111", "999999", "1234", "0123", "3456789", "9876", "543210"})
  void weakPins(String pin) {
    assertTrue(PinPolicy.isWeak(pin), pin);
  }

  @ParameterizedTest
  @ValueSource(strings = {"1357", "2580", "1212", "7890", "8901", "1243", "0912", "4321x"})
  void acceptablePins(String pin) {
    assertFalse(PinPolicy.isWeak(pin), pin);
  }

  @Test
  void clampLength() {
    assertEquals(4, PinPolicy.clampLength(1));
    assertEquals(6, PinPolicy.clampLength(6));
    assertEquals(12, PinPolicy.clampLength(40));
  }
}
