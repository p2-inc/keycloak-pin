package io.phasetwo.keycloak.pin.credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.phasetwo.keycloak.pin.PinConstants;
import java.io.IOException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.util.JsonSerialization;

/**
 * Read-only view of a please-open.it PIN Code Authenticator credential (type {@code pin-code}),
 * used for best-effort migration (spec D6). Their layout mirrors Keycloak's password credential:
 *
 * <ul>
 *   <li>secretData: {@code {"value": "<base64 hash>", "salt": "<base64 salt>"}}
 *   <li>credentialData: {@code {"algorithm": "argon2", "hashIterations": 5, "pinFormat":
 *       "4-digits", "additionalParameters": {"type": "id", "version": "1.3", "hashLength": "32",
 *       "memory": "7168", "parallelism": "1"}}}
 * </ul>
 *
 * <p>Only {@code argon2} credentials are supported; they are verified with Keycloak's own {@code
 * argon2} provider. While a user still has such a credential, the D4 failure counter and lock are
 * kept as extra {@code failures} / {@code locked} fields in its credential data (their extension
 * ignores unknown fields).
 */
public final class LegacyPinCredential {

  private static final Map<String, String> ARGON2_DEFAULTS =
      Map.of(
          "type", "id", "version", "1.3", "hashLength", "32", "memory", "7168", "parallelism", "1");

  private final CredentialModel stored;
  private final ObjectNode credentialData;
  private final JsonNode secretData;

  private LegacyPinCredential(CredentialModel stored, ObjectNode credentialData, JsonNode secret) {
    this.stored = stored;
    this.credentialData = credentialData;
    this.secretData = secret;
  }

  /**
   * Parses a stored {@code pin-code} credential.
   *
   * @param stored the stored credential
   * @return the view, or null when the type differs or the JSON is unreadable
   */
  public static LegacyPinCredential parse(CredentialModel stored) {
    if (stored == null || !PinConstants.LEGACY_CREDENTIAL_TYPE.equals(stored.getType())) {
      return null;
    }
    try {
      JsonNode data = JsonSerialization.mapper.readTree(nullToEmpty(stored.getCredentialData()));
      JsonNode secret = JsonSerialization.mapper.readTree(nullToEmpty(stored.getSecretData()));
      if (!(data instanceof ObjectNode obj) || secret == null || !secret.isObject()) return null;
      return new LegacyPinCredential(stored, obj, secret);
    } catch (IOException e) {
      return null;
    }
  }

  private static String nullToEmpty(String s) {
    return s == null || s.isBlank() ? "{}" : s;
  }

  /**
   * The stored credential.
   *
   * @return stored credential
   */
  public CredentialModel getStored() {
    return stored;
  }

  /**
   * Hash algorithm id.
   *
   * @return algorithm, may be null
   */
  public String getAlgorithm() {
    return text(credentialData, "algorithm");
  }

  /**
   * Whether this credential can be verified with Keycloak's {@code argon2} provider.
   *
   * @return true for argon2 with a hash and salt
   */
  public boolean isSupported() {
    return PinConstants.HASH_ALGORITHM.equals(getAlgorithm())
        && text(secretData, "value") != null
        && text(secretData, "salt") != null;
  }

  /**
   * PIN length derived from their {@code pinFormat} ({@code 4-digits}, {@code 6-digits}, {@code
   * 8-digits}); empty for custom formats.
   *
   * @return the length if known
   */
  public OptionalInt getLength() {
    String format = text(credentialData, "pinFormat");
    if (format == null) return OptionalInt.empty();
    return switch (format) {
      case "4-digits" -> OptionalInt.of(4);
      case "6-digits" -> OptionalInt.of(6);
      case "8-digits" -> OptionalInt.of(8);
      default -> OptionalInt.empty();
    };
  }

  /**
   * Consecutive failures recorded by this extension.
   *
   * @return failures, 0 when never recorded
   */
  public int getFailures() {
    JsonNode n = credentialData.get("failures");
    return n != null && n.canConvertToInt() ? n.asInt() : 0;
  }

  /**
   * Whether this extension locked the credential.
   *
   * @return true when locked
   */
  public boolean isLocked() {
    JsonNode n = credentialData.get("locked");
    return n != null && n.asBoolean(false);
  }

  /**
   * Records failure state into the credential data JSON and returns it, for {@code
   * updateStoredCredential}.
   *
   * @param failures consecutive failures
   * @param locked lock flag
   * @return the stored credential with updated credential data
   */
  public CredentialModel withFailureState(int failures, boolean locked) {
    credentialData.put("failures", failures);
    credentialData.put("locked", locked);
    try {
      stored.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return stored;
  }

  /**
   * The hash in Keycloak's password credential shape. Missing Argon2 parameters take Keycloak's
   * defaults (the same defaults their extension used).
   *
   * @return password credential view
   */
  public PasswordCredentialModel toPasswordCredentialModel() {
    Map<String, List<String>> params = new LinkedHashMap<>();
    JsonNode extra = credentialData.get("additionalParameters");
    ARGON2_DEFAULTS.forEach(
        (key, def) -> {
          String v = extra == null ? null : text(extra, key);
          params.put(key, List.of(v == null ? def : v));
        });
    JsonNode iterations = credentialData.get("hashIterations");
    int iters = iterations != null && iterations.canConvertToInt() ? iterations.asInt() : 5;
    return PasswordCredentialModel.createFromValues(
        getAlgorithm(),
        Base64.getDecoder().decode(text(secretData, "salt")),
        iters,
        params,
        text(secretData, "value"));
  }

  private static String text(JsonNode node, String field) {
    JsonNode n = node == null ? null : node.get(field);
    if (n == null || n.isNull()) return null;
    return n.isValueNode() ? n.asText() : null;
  }
}
