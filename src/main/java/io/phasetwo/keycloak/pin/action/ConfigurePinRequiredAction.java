package io.phasetwo.keycloak.pin.action;

import io.phasetwo.keycloak.pin.PinConstants;
import io.phasetwo.keycloak.pin.PinSetResult;
import io.phasetwo.keycloak.pin.credential.PinCredentialProvider;
import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Required action {@code phasetwo-configure-pin} ("Configure PIN"): asks for a new PIN and its
 * confirmation and stores it through {@link PinCredentialProvider#setPin}. Usable as a required
 * action, an application-initiated action ({@code kc_action=phasetwo-configure-pin}, the account
 * console's set-up / update) and from the execute-actions email.
 */
public class ConfigurePinRequiredAction implements RequiredActionProvider, CredentialRegistrator {

  /** Template. */
  public static final String TEMPLATE = "phasetwo-pin-setup.ftl";

  @Override
  public InitiatedActionSupport initiatedActionSupport() {
    return InitiatedActionSupport.SUPPORTED;
  }

  @Override
  public void evaluateTriggers(RequiredActionContext context) {}

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
    context.challenge(form(context).createForm(TEMPLATE));
  }

  @Override
  public void processAction(RequiredActionContext context) {
    MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
    PinCredentialProvider pins = PinCredentialProvider.get(context.getSession());
    PinSetResult result =
        pins.setPin(
            context.getRealm(),
            context.getUser(),
            params.getFirst(PinConstants.FORM_PIN),
            params.getFirst(PinConstants.FORM_PIN_CONFIRM));
    if (result == PinSetResult.OK) {
      context
          .getEvent()
          .clone()
          .event(EventType.UPDATE_CREDENTIAL)
          .detail(Details.CREDENTIAL_TYPE, PinConstants.CREDENTIAL_TYPE)
          .success();
      context.success();
      return;
    }
    int length = pins.getRequiredLength(context.getRealm());
    FormMessage error =
        switch (result) {
          case INVALID_FORMAT ->
              new FormMessage(PinConstants.FORM_PIN, "phasetwoPinInvalidFormat", length);
          case WEAK -> new FormMessage(PinConstants.FORM_PIN, "phasetwoPinWeak");
          default -> new FormMessage(PinConstants.FORM_PIN_CONFIRM, "phasetwoPinMismatch");
        };
    context.challenge(form(context).addError(error).createForm(TEMPLATE));
  }

  private LoginFormsProvider form(RequiredActionContext context) {
    PinCredentialProvider pins = PinCredentialProvider.get(context.getSession());
    return context
        .form()
        .setAttribute("pinLength", pins.getRequiredLength(context.getRealm()))
        .setAttribute("pinExists", pins.hasPin(context.getRealm(), context.getUser()));
  }

  @Override
  public String getCredentialType(
      KeycloakSession session, AuthenticationSessionModel authenticationSession) {
    return PinConstants.CREDENTIAL_TYPE;
  }

  @Override
  public void close() {}
}
