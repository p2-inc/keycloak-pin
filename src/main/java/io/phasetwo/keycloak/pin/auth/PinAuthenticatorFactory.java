package io.phasetwo.keycloak.pin.auth;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.pin.PinConfig;
import io.phasetwo.keycloak.pin.PinConstants;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** Registers the {@code phasetwo-pin} browser authenticator ("PIN"). */
@AutoService(AuthenticatorFactory.class)
public class PinAuthenticatorFactory implements AuthenticatorFactory {

  /** Provider id. */
  public static final String PROVIDER_ID = PinConstants.AUTHENTICATOR_ID;

  private static final PinAuthenticator SINGLETON = new PinAuthenticator();

  private static final Requirement[] REQUIREMENT_CHOICES = {
    Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED
  };

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "PIN";
  }

  @Override
  public String getHelpText() {
    return "Asks for the user's PIN. Place after a step that identifies the user, usually inside a"
        + " conditional sub-flow with 'Condition - user configured'.";
  }

  @Override
  public String getReferenceCategory() {
    return PinConstants.CREDENTIAL_TYPE;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return PinConfig.AUTHENTICATOR_PROPERTIES;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
