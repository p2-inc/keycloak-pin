package io.phasetwo.keycloak.pin.credential;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.pin.PinConstants;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/** Registers {@link PinCredentialProvider} under {@link PinConstants#CREDENTIAL_TYPE}. */
@AutoService(CredentialProviderFactory.class)
public class PinCredentialProviderFactory
    implements CredentialProviderFactory<PinCredentialProvider> {

  /** Provider id, equal to the credential type. */
  public static final String PROVIDER_ID = PinConstants.CREDENTIAL_TYPE;

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public PinCredentialProvider create(KeycloakSession session) {
    return new PinCredentialProvider(session);
  }
}
