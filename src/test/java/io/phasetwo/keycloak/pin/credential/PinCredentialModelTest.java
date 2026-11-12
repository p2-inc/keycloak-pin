package io.phasetwo.keycloak.pin.credential;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.pin.Argon2Fixtures;
import io.phasetwo.keycloak.pin.PinConstants;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;

class PinCredentialModelTest {

  private static PasswordCredentialModel hashed() {
    return PasswordCredentialModel.createFromValues(
        "argon2",
        new byte[] {1, 2, 3, 4},
        5,
        Map.of("type", List.of("id"), "memory", List.of("7168")),
        "aGFzaA==");
  }

  @Test
  void createAndRoundTrip() {
    PinCredentialModel created = PinCredentialModel.create(hashed(), 6);
    assertEquals(PinConstants.CREDENTIAL_TYPE, created.getType());
    assertTrue(created.getCredentialData().contains("\"length\":6"));
    assertFalse(created.getSecretData().contains("length"));

    CredentialModel stored = new CredentialModel();
    stored.setId("id-1");
    stored.setType(created.getType());
    stored.setCreatedDate(created.getCreatedDate());
    stored.setCredentialData(created.getCredentialData());
    stored.setSecretData(created.getSecretData());

    PinCredentialModel read = PinCredentialModel.createFromCredentialModel(stored);
    assertEquals("id-1", read.getId());
    assertEquals(6, read.getPinCredentialData().getLength());
    assertEquals(0, read.getPinCredentialData().getFailures());
    assertFalse(read.getPinCredentialData().isLocked());

    PasswordCredentialModel back = read.toPasswordCredentialModel();
    assertEquals("argon2", back.getPasswordCredentialData().getAlgorithm());
    assertEquals(5, back.getPasswordCredentialData().getHashIterations());
    assertEquals(
        "7168", back.getPasswordCredentialData().getAdditionalParameters().getFirst("memory"));
    assertArrayEquals(new byte[] {1, 2, 3, 4}, back.getPasswordSecretData().getSalt());
    assertEquals("aGFzaA==", back.getPasswordSecretData().getValue());
  }

  @Test
  void applyHashResetsFailureState() {
    PinCredentialModel model = PinCredentialModel.create(hashed(), 4);
    model.getPinCredentialData().setFailures(4);
    model.getPinCredentialData().setLocked(true);
    model.writeData();
    assertTrue(model.getCredentialData().contains("\"locked\":true"));
    model.applyHash(hashed(), 8);
    assertEquals(0, model.getPinCredentialData().getFailures());
    assertFalse(model.getPinCredentialData().isLocked());
    assertTrue(model.getCredentialData().contains("\"length\":8"));
  }

  @Test
  void readsFixtureLayout() {
    String[] json = Argon2Fixtures.phasetwoPin("2580", 7168);
    CredentialModel stored = new CredentialModel();
    stored.setType(PinConstants.CREDENTIAL_TYPE);
    stored.setSecretData(json[0]);
    stored.setCredentialData(json[1]);
    PinCredentialModel read = PinCredentialModel.createFromCredentialModel(stored);
    assertEquals(4, read.getPinCredentialData().getLength());
    assertEquals(16, read.toPasswordCredentialModel().getPasswordSecretData().getSalt().length);
  }

  @Test
  void legacyTypeIsWrappedWithoutParsing() {
    CredentialModel stored = new CredentialModel();
    stored.setType(PinConstants.LEGACY_CREDENTIAL_TYPE);
    stored.setCredentialData("not json");
    PinCredentialModel read = PinCredentialModel.createFromCredentialModel(stored);
    assertTrue(read.isLegacy());
    assertNull(read.getPinCredentialData());
  }
}
