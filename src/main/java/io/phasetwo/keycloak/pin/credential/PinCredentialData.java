package io.phasetwo.keycloak.pin.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Non-secret credential data of a {@code phasetwo-pin} credential, stored as JSON in the
 * credential's {@code credentialData}. The hash fields mirror Keycloak's {@code
 * PasswordCredentialData} so Keycloak's {@code PasswordHashProvider} can verify the PIN.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PinCredentialData {
  /** {@code PasswordHashProvider} id that produced the hash. */
  private String algorithm;

  /** Hash iterations. */
  private int hashIterations;

  /** Hash provider parameters (for argon2: type, version, hashLength, memory, parallelism). */
  private Map<String, List<String>> additionalParameters = new LinkedHashMap<>();

  /** Number of digits of the PIN when it was set. */
  private int length;

  /** Consecutive failed attempts. */
  private int failures;

  /** Whether the PIN is locked. */
  private boolean locked;
}
