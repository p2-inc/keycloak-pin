package io.phasetwo.keycloak.pin.credential;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.pin.BcryptFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class BcryptPinHashTest {

  @ParameterizedTest
  @ValueSource(strings = {"2a", "2b", "2y"})
  void verifiesEveryVersion(String version) {
    String hash = BcryptFixtures.hash(version, "246813");
    assertTrue(BcryptPinHash.verify(hash, "246813"));
    assertFalse(BcryptPinHash.verify(hash, "246814"));
  }

  @Test
  void rejectsMissingInput() {
    String hash = BcryptFixtures.hash("2b", "1357");
    assertFalse(BcryptPinHash.verify(hash, null));
    assertFalse(BcryptPinHash.verify(hash, ""));
    assertFalse(BcryptPinHash.verify(null, "1357"));
    assertFalse(BcryptPinHash.verify("", "1357"));
  }

  @Test
  void unreadableHashFailsInsteadOfThrowing() {
    assertFalse(BcryptPinHash.verify("not-a-bcrypt-hash", "1357"));
    assertFalse(
        BcryptPinHash.verify(
            "$2b$99$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234", "1357"));
  }

  @Test
  void algorithmId() {
    assertTrue(BcryptPinHash.isBcrypt("bcrypt"));
    assertFalse(BcryptPinHash.isBcrypt("argon2"));
    assertFalse(BcryptPinHash.isBcrypt(null));
  }
}
