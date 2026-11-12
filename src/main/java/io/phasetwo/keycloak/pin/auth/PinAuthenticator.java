package io.phasetwo.keycloak.pin.auth;

import io.phasetwo.keycloak.pin.PinConfig;
import io.phasetwo.keycloak.pin.PinConstants;
import io.phasetwo.keycloak.pin.PinVerification;
import io.phasetwo.keycloak.pin.credential.PinCredentialProvider;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.OptionalInt;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

/**
 * Browser authenticator {@code phasetwo-pin}: asks for the user's PIN and verifies it through
 * {@link PinCredentialProvider#verify} with the execution's {@code max-attempts}. Wrong and locked
 * attempts emit {@code INVALID_USER_CREDENTIALS} with {@code credential_type=phasetwo-pin} (plus
 * {@code reason=pin_locked} when locked) and go through {@code failureChallenge}, so realm
 * brute-force protection counts them.
 */
@JBossLog
public class PinAuthenticator implements Authenticator, CredentialValidator<PinCredentialProvider> {

  /** Login template. */
  public static final String TEMPLATE = "phasetwo-pin-login.ftl";

  private static final String ATTR_LENGTH = "pinLength";
  private static final String ATTR_LOCKED = "pinLocked";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    PinCredentialProvider pins = getCredentialProvider(context.getSession());
    boolean locked = pins.isLocked(context.getRealm(), context.getUser());
    LoginFormsProvider form = form(context, locked);
    if (locked) form.setError("phasetwoPinLocked");
    context.challenge(form.createForm(TEMPLATE));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
    String pin = params.getFirst(PinConstants.FORM_PIN);
    PinCredentialProvider pins = getCredentialProvider(context.getSession());
    RealmModel realm = context.getRealm();
    UserModel user = context.getUser();

    if ((pin == null || pin.isBlank()) && !pins.isLocked(realm, user)) {
      context.challenge(
          form(context, false)
              .addError(new FormMessage(PinConstants.FORM_PIN, "phasetwoPinMissing"))
              .createForm(TEMPLATE));
      return;
    }

    int maxAttempts = PinConfig.maxAttempts(context.getAuthenticatorConfig());
    PinVerification result = pins.verify(realm, user, pin, maxAttempts);
    switch (result.outcome()) {
      case VALID -> context.success();
      case INVALID -> {
        context
            .getEvent()
            .clone()
            .user(user)
            .detail(Details.CREDENTIAL_TYPE, PinConstants.CREDENTIAL_TYPE)
            .error(Errors.INVALID_USER_CREDENTIALS);
        FormMessage error =
            result.isUnlimited()
                ? new FormMessage(PinConstants.FORM_PIN, "phasetwoPinInvalid")
                : result.remainingAttempts() == 1
                    ? new FormMessage(PinConstants.FORM_PIN, "phasetwoPinInvalidLastAttempt")
                    : new FormMessage(
                        PinConstants.FORM_PIN,
                        "phasetwoPinInvalidRemaining",
                        result.remainingAttempts());
        Response page = form(context, false).addError(error).createForm(TEMPLATE);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, page);
      }
      case LOCKED -> {
        context
            .getEvent()
            .clone()
            .user(user)
            .detail(Details.CREDENTIAL_TYPE, PinConstants.CREDENTIAL_TYPE)
            .detail(Details.REASON, PinConstants.EVENT_REASON_LOCKED)
            .error(Errors.INVALID_USER_CREDENTIALS);
        Response page = form(context, true).setError("phasetwoPinLocked").createForm(TEMPLATE);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, page);
      }
      case NOT_CONFIGURED -> context.attempted();
    }
  }

  private LoginFormsProvider form(AuthenticationFlowContext context, boolean locked) {
    OptionalInt length =
        getCredentialProvider(context.getSession())
            .getStoredLength(context.getRealm(), context.getUser());
    LoginFormsProvider form =
        context
            .form()
            .setExecution(context.getExecution().getId())
            .setAttribute(ATTR_LOCKED, locked);
    if (length.isPresent()) form.setAttribute(ATTR_LENGTH, length.getAsInt());
    return form;
  }

  @Override
  public PinCredentialProvider getCredentialProvider(KeycloakSession session) {
    return PinCredentialProvider.get(session);
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return getCredentialProvider(session).hasPin(realm, user);
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    user.addRequiredAction(PinConstants.REQUIRED_ACTION_ID);
  }

  @Override
  public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
    RequiredActionFactory factory =
        (RequiredActionFactory)
            session
                .getKeycloakSessionFactory()
                .getProviderFactory(RequiredActionProvider.class, PinConstants.REQUIRED_ACTION_ID);
    return factory == null ? List.of() : List.of(factory);
  }

  @Override
  public void close() {}
}
