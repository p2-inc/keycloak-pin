package io.phasetwo.keycloak.pin.action;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.pin.PinConfig;
import io.phasetwo.keycloak.pin.PinConstants;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.validate.ValidationError;

/**
 * Registers the {@code phasetwo-configure-pin} required action. Realm config (Authentication,
 * Required actions, gear icon): {@code length} (4-12, default 4), {@code reject-weak} (default
 * true) and Keycloak's {@code max_auth_age}.
 */
@AutoService(RequiredActionFactory.class)
public class ConfigurePinRequiredActionFactory implements RequiredActionFactory {

  /** Provider id. */
  public static final String PROVIDER_ID = PinConstants.REQUIRED_ACTION_ID;

  private static final ConfigurePinRequiredAction SINGLETON = new ConfigurePinRequiredAction();

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayText() {
    return "Configure PIN";
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return PinConfig.REQUIRED_ACTION_PROPERTIES;
  }

  @Override
  public void validateConfig(
      KeycloakSession session, RealmModel realm, RequiredActionConfigModel model) {
    RequiredActionFactory.super.validateConfig(session, realm, model);
    String length = model.getConfigValue(PinConstants.CONFIG_LENGTH);
    if (length == null || length.isBlank()) return;
    int parsed;
    try {
      parsed = Integer.parseInt(length.trim());
    } catch (NumberFormatException e) {
      throw new ValidationException(
          new ValidationError(PROVIDER_ID, PinConstants.CONFIG_LENGTH, "error-invalid-value"));
    }
    if (parsed < PinConstants.MIN_LENGTH || parsed > PinConstants.MAX_LENGTH) {
      throw new ValidationException(
          new ValidationError(
              PROVIDER_ID,
              PinConstants.CONFIG_LENGTH,
              "error-number-out-of-range",
              PinConstants.MIN_LENGTH,
              PinConstants.MAX_LENGTH));
    }
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
