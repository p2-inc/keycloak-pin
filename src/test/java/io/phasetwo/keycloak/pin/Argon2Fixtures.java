package io.phasetwo.keycloak.pin;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Builds credential JSON for tests with BouncyCastle directly, independent of Keycloak's argon2
 * provider, so the tests check that stored layouts are readable by Keycloak.
 */
public final class Argon2Fixtures {

  private Argon2Fixtures() {}

  /** Argon2id v1.3 hash, base64. */
  public static String hash(String pin, byte[] salt, int memory, int iterations) {
    Argon2Parameters params =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withParallelism(1)
            .withMemoryAsKB(memory)
            .withIterations(iterations)
            .build();
    Argon2BytesGenerator gen = new Argon2BytesGenerator();
    gen.init(params);
    byte[] out = new byte[32];
    gen.generateBytes(pin.getBytes(StandardCharsets.UTF_8), out);
    return Base64.getEncoder().encodeToString(out);
  }

  public static byte[] salt() {
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    return salt;
  }

  /** secretData and credentialData of a please-open.it {@code pin-code} credential. */
  public static String[] legacyPinCode(String pin, String pinFormat) {
    byte[] salt = salt();
    String secret =
        "{\"value\":\"%s\",\"salt\":\"%s\"}"
            .formatted(hash(pin, salt, 7168, 5), Base64.getEncoder().encodeToString(salt));
    String data =
        ("{\"algorithm\":\"argon2\",\"hashIterations\":5,\"pinFormat\":\"%s\","
                + "\"additionalParameters\":{\"type\":\"id\",\"version\":\"1.3\","
                + "\"hashLength\":\"32\",\"memory\":\"7168\",\"parallelism\":\"1\"}}")
            .formatted(pinFormat);
    return new String[] {secret, data};
  }

  /** secretData and credentialData of a {@code phasetwo-pin} credential. */
  public static String[] phasetwoPin(String pin, int memory) {
    byte[] salt = salt();
    String secret =
        "{\"value\":\"%s\",\"salt\":\"%s\"}"
            .formatted(hash(pin, salt, memory, 5), Base64.getEncoder().encodeToString(salt));
    String data =
        ("{\"algorithm\":\"argon2\",\"hashIterations\":5,\"additionalParameters\":{"
                + "\"type\":[\"id\"],\"version\":[\"1.3\"],\"hashLength\":[\"32\"],"
                + "\"memory\":[\"%d\"],\"parallelism\":[\"1\"]},"
                + "\"length\":%d,\"failures\":0,\"locked\":false}")
            .formatted(memory, pin.length());
    return new String[] {secret, data};
  }
}
