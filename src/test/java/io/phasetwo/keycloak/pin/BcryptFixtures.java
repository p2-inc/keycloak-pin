package io.phasetwo.keycloak.pin;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

/** Builds bcrypt-imported credential JSON for tests, as another system would export it. */
public final class BcryptFixtures {

  private BcryptFixtures() {}

  /** Modular-crypt bcrypt string, for example {@code $2b$04$...}. Cost 4 keeps tests fast. */
  public static String hash(String version, String pin) {
    return OpenBSDBCrypt.generate(version, pin.toCharArray(), Argon2Fixtures.salt(), 4);
  }

  /**
   * secretData and credentialData of a {@code phasetwo-pin} credential imported with a bcrypt
   * hash: only the algorithm, no length, failures or lock.
   */
  public static String[] phasetwoPin(String pin) {
    return new String[] {
      "{\"value\":\"%s\"}".formatted(hash("2b", pin)), "{\"algorithm\":\"bcrypt\"}"
    };
  }

  /** secretData and credentialData of a please-open.it {@code pin-code} credential with bcrypt. */
  public static String[] legacyPinCode(String pin) {
    return new String[] {
      "{\"value\":\"%s\"}".formatted(hash("2a", pin)), "{\"algorithm\":\"bcrypt\"}"
    };
  }
}
