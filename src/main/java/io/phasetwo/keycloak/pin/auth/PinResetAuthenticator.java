package io.phasetwo.keycloak.pin.auth;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.pin.PinConstants;
import io.phasetwo.keycloak.pin.credential.PinCredentialProvider;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Reset-credentials flow authenticator {@code phasetwo-pin-reset} ("Reset PIN"), modeled on
 * Keycloak's {@code reset-otp}: when the user has a PIN, removes it (which also clears a lock) and
 * adds the {@code phasetwo-configure-pin} required action so the user sets a new one before the
 * flow completes. Users without a PIN pass through untouched.
 */
@AutoService(AuthenticatorFactory.class)
public class PinResetAuthenticator implements Authenticator, AuthenticatorFactory {

  /** Provider id. */
  public static final String PROVIDER_ID = PinConstants.RESET_AUTHENTICATOR_ID;

  private static final Requirement[] REQUIREMENT_CHOICES = {
    Requirement.REQUIRED, Requirement.DISABLED
  };

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    PinCredentialProvider pins = PinCredentialProvider.get(context.getSession());
    if (pins.removePin(context.getRealm(), user)) {
      user.addRequiredAction(PinConstants.REQUIRED_ACTION_ID);
      context
          .getEvent()
          .clone()
          .event(EventType.REMOVE_CREDENTIAL)
          .user(user)
          .detail(Details.CREDENTIAL_TYPE, PinConstants.CREDENTIAL_TYPE)
          .success();
    }
    context.success();
  }

  @Override
  public void action(AuthenticationFlowContext context) {}

  @Override
  public boolean requiresUser() {
    return true;
  }

  /**
   * Always true, so the execution can be REQUIRED directly in the reset credentials flow without
   * failing for users that have no PIN. It also works inside a conditional sub-flow.
   */
  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Reset PIN";
  }

  @Override
  public String getHelpText() {
    return "For the reset credentials flow: removes the user's PIN, if any, and sets the 'Configure"
        + " PIN' required action. Place after 'Send Reset Email'.";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
