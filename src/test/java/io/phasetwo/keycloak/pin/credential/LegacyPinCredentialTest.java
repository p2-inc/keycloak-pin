package io.phasetwo.keycloak.pin.credential;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.pin.Argon2Fixtures;
import io.phasetwo.keycloak.pin.PinConstants;
import java.util.OptionalInt;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;

class LegacyPinCredentialTest {

  private static CredentialModel stored(String secret, String data) {
    CredentialModel model = new CredentialModel();
    model.setType(PinConstants.LEGACY_CREDENTIAL_TYPE);
    model.setSecretData(secret);
    model.setCredentialData(data);
    return model;
  }

  @Test
  void parsesTheirLayout() {
    String[] json = Argon2Fixtures.legacyPinCode("2468", "6-digits");
    LegacyPinCredential legacy = LegacyPinCredential.parse(stored(json[0], json[1]));
    assertTrue(legacy.isSupported());
    assertEquals(OptionalInt.of(6), legacy.getLength());
    assertEquals(0, legacy.getFailures());
    assertFalse(legacy.isLocked());

    var pw = legacy.toPasswordCredentialModel();
    assertEquals("argon2", pw.getPasswordCredentialData().getAlgorithm());
    assertEquals(5, pw.getPasswordCredentialData().getHashIterations());
    var params = pw.getPasswordCredentialData().getAdditionalParameters();
    assertEquals("id", params.getFirst("type"));
    assertEquals("32", params.getFirst("hashLength"));
    assertEquals(16, pw.getPasswordSecretData().getSalt().length);
  }

  @Test
  void formatsToLength() {
    assertEquals(OptionalInt.of(4), lengthOf("4-digits"));
    assertEquals(OptionalInt.of(8), lengthOf("8-digits"));
    assertEquals(OptionalInt.empty(), lengthOf("custom"));
  }

  private static OptionalInt lengthOf(String format) {
    String[] json = Argon2Fixtures.legacyPinCode("1357", format);
    return LegacyPinCredential.parse(stored(json[0], json[1])).getLength();
  }

  @Test
  void missingParametersTakeDefaults() {
    LegacyPinCredential legacy =
        LegacyPinCredential.parse(
            stored(
                "{\"value\":\"aGFzaA==\",\"salt\":\"AQID\"}",
                "{\"algorithm\":\"argon2\",\"hashIterations\":3}"));
    var params = legacy.toPasswordCredentialModel().getPasswordCredentialData();
    assertEquals(3, params.getHashIterations());
    assertEquals("7168", params.getAdditionalParameters().getFirst("memory"));
    assertEquals("1.3", params.getAdditionalParameters().getFirst("version"));
  }

  @Test
  void failureStateIsWrittenIntoCredentialData() {
    String[] json = Argon2Fixtures.legacyPinCode("1357", "4-digits");
    CredentialModel model = stored(json[0], json[1]);
    LegacyPinCredential.parse(model).withFailureState(2, true);
    LegacyPinCredential again = LegacyPinCredential.parse(model);
    assertEquals(2, again.getFailures());
    assertTrue(again.isLocked());
    assertTrue(model.getCredentialData().contains("\"pinFormat\":\"4-digits\""));
  }

  @Test
  void unsupportedOrUnreadable() {
    assertFalse(
        LegacyPinCredential.parse(
                stored("{\"value\":\"x\",\"salt\":\"AQID\"}", "{\"algorithm\":\"pbkdf2\"}"))
            .isSupported());
    assertNull(LegacyPinCredential.parse(stored("nope", "{}")));
    CredentialModel other = stored("{}", "{}");
    other.setType("otp");
    assertNull(LegacyPinCredential.parse(other));
  }
}
