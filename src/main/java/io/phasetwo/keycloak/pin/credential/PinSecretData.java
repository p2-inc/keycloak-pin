package io.phasetwo.keycloak.pin.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Secret data of a {@code phasetwo-pin} credential, stored as JSON in the credential's {@code
 * secretData}. Same shape as Keycloak's password secret data.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PinSecretData {
  /** Base64 hash. */
  private String value;

  /** Base64 salt. */
  private String salt;
}
