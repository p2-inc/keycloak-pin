package io.phasetwo.keycloak.pin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PinAttemptsTest {

  @Test
  void countsDownAndLocksAtMax() {
    var first = PinAttempts.afterFailure(0, 3);
    assertEquals(1, first.failures());
    assertFalse(first.locked());
    assertEquals(2, first.remaining());

    var second = PinAttempts.afterFailure(first.failures(), 3);
    assertEquals(1, second.remaining());
    assertFalse(second.locked());

    var third = PinAttempts.afterFailure(second.failures(), 3);
    assertTrue(third.locked());
    assertEquals(0, third.remaining());
    assertEquals(3, third.failures());
  }

  @Test
  void maxOneLocksImmediately() {
    assertTrue(PinAttempts.afterFailure(0, 1).locked());
  }

  @Test
  void loweredLimitLocksOnNextFailure() {
    var after = PinAttempts.afterFailure(7, 5);
    assertTrue(after.locked());
    assertEquals(8, after.failures());
  }

  @Test
  void unlimitedNeverLocks() {
    var after = PinAttempts.afterFailure(1000, PinConstants.UNLIMITED_ATTEMPTS);
    assertFalse(after.locked());
    assertEquals(1001, after.failures());
    assertEquals(PinVerification.UNLIMITED, after.remaining());
  }

  @Test
  void remaining() {
    assertEquals(5, PinAttempts.remaining(0, 5));
    assertEquals(2, PinAttempts.remaining(3, 5));
    assertEquals(0, PinAttempts.remaining(9, 5));
    assertEquals(PinVerification.UNLIMITED, PinAttempts.remaining(3, 0));
  }

  @Test
  void verificationFactories() {
    assertTrue(PinVerification.valid().isValid());
    assertEquals(PinVerification.Outcome.LOCKED, PinVerification.locked().outcome());
    assertEquals(0, PinVerification.locked().remainingAttempts());
    assertTrue(PinVerification.invalid(PinVerification.UNLIMITED).isUnlimited());
    assertFalse(PinVerification.invalid(2).isUnlimited());
  }
}
