package io.phasetwo.keycloak.pin;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Reads PIN configuration from Keycloak's built-in config surfaces (spec D3): the set-PIN
 * required action's realm config ({@code length}, {@code reject-weak}) and an authenticator
 * execution's config ({@code max-attempts}). Absent, blank or unparsable values fall back to the
 * defaults in {@link PinConstants}.
 */
@JBossLog
public final class PinConfig {

  private PinConfig() {}

  /**
   * Config properties of a PIN-verifying authenticator execution ({@code max-attempts}). Native
   * authenticators that verify a PIN should expose the same list.
   */
  public static final List<ProviderConfigProperty> AUTHENTICATOR_PROPERTIES =
      ProviderConfigurationBuilder.create()
          .property()
          .name(PinConstants.CONFIG_MAX_ATTEMPTS)
          .label("Maximum attempts")
          .helpText(
              "Consecutive wrong PINs before the PIN is locked. A locked PIN must be reset (reset"
                  + " credentials flow, or an administrator). 0 means no PIN-specific limit;"
                  + " realm brute-force detection still applies.")
          .type(ProviderConfigProperty.STRING_TYPE)
          .defaultValue(Integer.toString(PinConstants.DEFAULT_MAX_ATTEMPTS))
          .add()
          .build();

  /** Config properties of the set-PIN required action, including Keycloak's max auth age. */
  public static final List<ProviderConfigProperty> REQUIRED_ACTION_PROPERTIES =
      buildRequiredActionProperties();

  private static List<ProviderConfigProperty> buildRequiredActionProperties() {
    List<ProviderConfigProperty> props = new ArrayList<>();
    props.addAll(
        ProviderConfigurationBuilder.create()
            .property()
            .name(PinConstants.CONFIG_LENGTH)
            .label("PIN length")
            .helpText(
                "Number of digits for new PINs ("
                    + PinConstants.MIN_LENGTH
                    + "-"
                    + PinConstants.MAX_LENGTH
                    + "). Existing PINs keep the length they were set with.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(Integer.toString(PinConstants.DEFAULT_LENGTH))
            .add()
            .property()
            .name(PinConstants.CONFIG_REJECT_WEAK)
            .label("Reject weak PINs")
            .helpText(
                "Reject PINs made of one repeated digit or a simple run such as 1234 or 9876.")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .defaultValue(Boolean.toString(PinConstants.DEFAULT_REJECT_WEAK))
            .add()
            .build());
    props.addAll(RequiredActionFactory.MAX_AUTH_AGE_CONFIG_PROPERTIES);
    return List.copyOf(props);
  }

  /**
   * The {@code max-attempts} value of an authenticator execution.
   *
   * @param config the execution config, may be null
   * @return configured value, {@link PinConstants#DEFAULT_MAX_ATTEMPTS} when unset or invalid
   */
  public static int maxAttempts(AuthenticatorConfigModel config) {
    Map<String, String> map = config == null ? null : config.getConfig();
    return parseMaxAttempts(map == null ? null : map.get(PinConstants.CONFIG_MAX_ATTEMPTS));
  }

  /**
   * Parses a {@code max-attempts} value.
   *
   * @param value raw value, may be null
   * @return parsed value (negative values become 0), default when unset or invalid
   */
  public static int parseMaxAttempts(String value) {
    Integer parsed = parseInt(value);
    if (parsed == null) return PinConstants.DEFAULT_MAX_ATTEMPTS;
    return Math.max(PinConstants.UNLIMITED_ATTEMPTS, parsed);
  }

  /**
   * The number of digits a new PIN must have in this realm.
   *
   * @param realm the realm
   * @return the set-PIN required action's {@code length}, clamped to 4-12, default 4
   */
  public static int requiredLength(RealmModel realm) {
    return parseLength(requiredActionValue(realm, PinConstants.CONFIG_LENGTH));
  }

  /**
   * Parses a {@code length} value.
   *
   * @param value raw value, may be null
   * @return clamped length, default when unset or invalid
   */
  public static int parseLength(String value) {
    Integer parsed = parseInt(value);
    if (parsed == null) return PinConstants.DEFAULT_LENGTH;
    return PinPolicy.clampLength(parsed);
  }

  /**
   * Whether weak PINs are rejected in this realm.
   *
   * @param realm the realm
   * @return the set-PIN required action's {@code reject-weak}, default true
   */
  public static boolean rejectWeak(RealmModel realm) {
    String value = requiredActionValue(realm, PinConstants.CONFIG_REJECT_WEAK);
    if (value == null || value.isBlank()) return PinConstants.DEFAULT_REJECT_WEAK;
    return Boolean.parseBoolean(value.trim());
  }

  private static String requiredActionValue(RealmModel realm, String key) {
    RequiredActionConfigModel config =
        realm.getRequiredActionConfigByAlias(PinConstants.REQUIRED_ACTION_ID);
    if (config == null || config.getConfig() == null) return null;
    return config.getConfig().get(key);
  }

  private static Integer parseInt(String value) {
    if (value == null || value.isBlank()) return null;
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      log.warnf("Ignoring invalid PIN config value '%s'", value);
      return null;
    }
  }
}
