package io.phasetwo.keycloak.pin.credential;

import io.phasetwo.keycloak.pin.PinConstants;
import lombok.extern.jbosslog.JBossLog;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

/**
 * Verify-only bcrypt support for PINs imported from another system. A credential whose {@code
 * algorithm} is {@code bcrypt} carries the full modular-crypt string ({@code $2a$}, {@code $2b$}
 * or {@code $2y$}, cost and salt included) in {@code secretData.value}. A PIN that verifies is
 * re-hashed with argon2 by the caller, so bcrypt is never used to store a PIN.
 *
 * <p>This is deliberately not a Keycloak {@code PasswordHashProvider}: registering one would make
 * bcrypt available to the realm password policy and could clash with a community bcrypt provider.
 * It uses BouncyCastle's {@link OpenBSDBCrypt}, which ships with Keycloak's (non-FIPS)
 * distribution.
 */
@JBossLog
public final class BcryptPinHash {

  private BcryptPinHash() {}

  /**
   * Whether an algorithm id names bcrypt.
   *
   * @param algorithm the credential's {@code algorithm}
   * @return true for {@code bcrypt}
   */
  public static boolean isBcrypt(String algorithm) {
    return PinConstants.BCRYPT_ALGORITHM.equals(algorithm);
  }

  /**
   * Checks a PIN against a bcrypt hash in constant time.
   *
   * @param storedHash the modular-crypt string, for example {@code $2b$10$...}
   * @param pin the PIN entered
   * @return true when the PIN matches; false for a wrong PIN or an unreadable hash
   */
  public static boolean verify(String storedHash, String pin) {
    if (storedHash == null || storedHash.isEmpty() || pin == null || pin.isEmpty()) return false;
    try {
      return OpenBSDBCrypt.checkPassword(storedHash, pin.toCharArray());
    } catch (IllegalArgumentException e) {
      log.warnf("Unreadable bcrypt PIN hash: %s", e.getMessage());
      return false;
    } catch (NoClassDefFoundError e) {
      log.warn("bcrypt PIN hashes need BouncyCastle (bcprov), which this server does not ship");
      return false;
    }
  }
}
