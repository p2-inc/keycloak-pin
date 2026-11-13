package io.phasetwo.keycloak.pin.credential;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.phasetwo.keycloak.pin.PinConstants;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.util.JsonSerialization;

/**
 * A {@code phasetwo-pin} credential (spec D2). The hash is produced by Keycloak's {@code argon2}
 * {@code PasswordHashProvider} and stored like a password; the credential data also carries the
 * PIN length, the consecutive failure count and the lock flag.
 *
 * <p>Instances built from a please-open.it {@code pin-code} credential ({@link #isLegacy()}) carry
 * only the base {@link CredentialModel} fields; they exist so the account and admin consoles can
 * list such credentials, and are verified through {@link LegacyPinCredential}.
 */
public class PinCredentialModel extends CredentialModel {

  private transient PinCredentialData pinCredentialData;
  private transient PinSecretData pinSecretData;

  private PinCredentialModel() {}

  /**
   * Builds a new, not yet persisted credential from a freshly encoded PIN.
   *
   * @param hashed result of {@code PasswordHashProvider#encodedCredential}
   * @param length number of digits of the PIN
   * @return the credential, type {@link PinConstants#CREDENTIAL_TYPE}
   */
  public static PinCredentialModel create(PasswordCredentialModel hashed, int length) {
    PinCredentialModel model = new PinCredentialModel();
    model.setType(PinConstants.CREDENTIAL_TYPE);
    model.setCreatedDate(Time.currentTimeMillis());
    model.pinCredentialData = new PinCredentialData();
    model.pinSecretData = new PinSecretData();
    model.applyHash(hashed, length);
    return model;
  }

  /**
   * Wraps a stored credential. Parses the PIN data when the type is {@link
   * PinConstants#CREDENTIAL_TYPE}; other types (the legacy {@code pin-code}) are wrapped without
   * parsing.
   *
   * @param stored the stored credential
   * @return the wrapper
   */
  public static PinCredentialModel createFromCredentialModel(CredentialModel stored) {
    if (stored instanceof PinCredentialModel pin) return pin;
    PinCredentialModel model = new PinCredentialModel();
    model.setId(stored.getId());
    model.setType(stored.getType());
    model.setUserLabel(stored.getUserLabel());
    model.setCreatedDate(stored.getCreatedDate());
    model.setFederationLink(stored.getFederationLink());
    model.setCredentialData(stored.getCredentialData());
    model.setSecretData(stored.getSecretData());
    if (PinConstants.CREDENTIAL_TYPE.equals(stored.getType())) {
      try {
        model.pinCredentialData =
            stored.getCredentialData() == null
                ? new PinCredentialData()
                : JsonSerialization.readValue(stored.getCredentialData(), PinCredentialData.class);
        model.pinSecretData =
            stored.getSecretData() == null
                ? new PinSecretData()
                : JsonSerialization.readValue(stored.getSecretData(), PinSecretData.class);
      } catch (IOException e) {
        throw new UncheckedIOException("Unreadable PIN credential " + stored.getId(), e);
      }
    }
    return model;
  }

  /**
   * Whether this wraps a please-open.it {@code pin-code} credential.
   *
   * @return true for the legacy type
   */
  @JsonIgnore
  public boolean isLegacy() {
    return PinConstants.LEGACY_CREDENTIAL_TYPE.equals(getType());
  }

  /**
   * Parsed credential data, null for legacy credentials.
   *
   * @return credential data
   */
  @JsonIgnore
  public PinCredentialData getPinCredentialData() {
    return pinCredentialData;
  }

  /**
   * Parsed secret data, null for legacy credentials.
   *
   * @return secret data
   */
  @JsonIgnore
  public PinSecretData getPinSecretData() {
    return pinSecretData;
  }

  /**
   * Replaces hash, salt, parameters and length, resets the failure counter and the lock, and
   * rewrites the JSON fields.
   *
   * @param hashed result of {@code PasswordHashProvider#encodedCredential}
   * @param length number of digits of the PIN
   */
  public void applyHash(PasswordCredentialModel hashed, int length) {
    var data = hashed.getPasswordCredentialData();
    var secret = hashed.getPasswordSecretData();
    Map<String, List<String>> params = new LinkedHashMap<>();
    if (data.getAdditionalParameters() != null) {
      data.getAdditionalParameters().forEach((k, v) -> params.put(k, List.copyOf(v)));
    }
    pinCredentialData.setAlgorithm(data.getAlgorithm());
    pinCredentialData.setHashIterations(data.getHashIterations());
    pinCredentialData.setAdditionalParameters(params);
    pinCredentialData.setLength(length);
    pinCredentialData.setFailures(0);
    pinCredentialData.setLocked(false);
    pinSecretData.setValue(secret.getValue());
    pinSecretData.setSalt(
        secret.getSalt() == null ? null : Base64.getEncoder().encodeToString(secret.getSalt()));
    writeData();
  }

  /** Serializes the parsed data back into {@code credentialData} and {@code secretData}. */
  public void writeData() {
    try {
      setCredentialData(JsonSerialization.writeValueAsString(pinCredentialData));
      setSecretData(JsonSerialization.writeValueAsString(pinSecretData));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * The hash in Keycloak's password credential shape, for {@code PasswordHashProvider#verify} and
   * {@code policyCheck}.
   *
   * @return password credential view of the hash
   */
  public PasswordCredentialModel toPasswordCredentialModel() {
    byte[] salt =
        pinSecretData.getSalt() == null
            ? null
            : Base64.getDecoder().decode(pinSecretData.getSalt());
    return PasswordCredentialModel.createFromValues(
        pinCredentialData.getAlgorithm(),
        salt,
        pinCredentialData.getHashIterations(),
        pinCredentialData.getAdditionalParameters(),
        pinSecretData.getValue());
  }
}
