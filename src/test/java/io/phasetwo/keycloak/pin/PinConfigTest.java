package io.phasetwo.keycloak.pin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.provider.ProviderConfigProperty;

class PinConfigTest {

  @Test
  void maxAttemptsDefaultsAndParsing() {
    assertEquals(5, PinConfig.maxAttempts(null));
    assertEquals(5, PinConfig.maxAttempts(new AuthenticatorConfigModel()));
    assertEquals(3, PinConfig.maxAttempts(config("3")));
    assertEquals(0, PinConfig.maxAttempts(config("0")));
    assertEquals(0, PinConfig.maxAttempts(config("-2")));
    assertEquals(5, PinConfig.maxAttempts(config("abc")));
    assertEquals(5, PinConfig.maxAttempts(config(" ")));
    assertEquals(7, PinConfig.maxAttempts(config(" 7 ")));
  }

  @Test
  void lengthParsingClamps() {
    assertEquals(4, PinConfig.parseLength(null));
    assertEquals(4, PinConfig.parseLength("x"));
    assertEquals(6, PinConfig.parseLength("6"));
    assertEquals(4, PinConfig.parseLength("2"));
    assertEquals(12, PinConfig.parseLength("20"));
  }

  @Test
  void propertyLists() {
    assertEquals(
        PinConstants.CONFIG_MAX_ATTEMPTS, PinConfig.AUTHENTICATOR_PROPERTIES.get(0).getName());
    var names =
        PinConfig.REQUIRED_ACTION_PROPERTIES.stream().map(ProviderConfigProperty::getName).toList();
    assertTrue(names.contains(PinConstants.CONFIG_LENGTH));
    assertTrue(names.contains(PinConstants.CONFIG_REJECT_WEAK));
    assertTrue(names.contains(Constants.MAX_AUTH_AGE_KEY));
  }

  private static AuthenticatorConfigModel config(String maxAttempts) {
    AuthenticatorConfigModel model = new AuthenticatorConfigModel();
    model.setConfig(Map.of(PinConstants.CONFIG_MAX_ATTEMPTS, maxAttempts));
    return model;
  }
}
