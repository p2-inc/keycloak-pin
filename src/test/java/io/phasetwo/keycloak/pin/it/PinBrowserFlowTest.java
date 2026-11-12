package io.phasetwo.keycloak.pin.it;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.phasetwo.keycloak.pin.Argon2Fixtures;
import io.phasetwo.keycloak.pin.PinConstants;
import java.util.List;
import java.util.Map;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.representations.idm.EventRepresentation;

/** Set PIN, log in with PIN, attempt counting, lockout, re-hash, account console, AIA. */
class PinBrowserFlowTest extends AbstractPinIntegrationTest {

  private static final String PASSWORD = "Password-123";

  @Test
  void setPin_validatesLengthMismatchAndWeak_thenStores() throws Exception {
    assertEquals(204, setRequiredActionConfig(Map.of("length", "6")).statusCode());
    String userId = createUser("setter", PASSWORD, List.of(PinConstants.REQUIRED_ACTION_ID));

    Browser browser = new Browser();
    Page setup = loginWithPassword(browser, "setter", PASSWORD);
    assertEquals(200, setup.status());
    Document doc = setup.doc();
    Element pin = doc.getElementById("pin");
    assertNotNull(pin, "setup page has a PIN input: " + setup.body());
    assertEquals("numeric", pin.attr("inputmode"));
    assertEquals("off", pin.attr("autocomplete"));
    assertEquals("password", pin.attr("type"));
    assertEquals("6", pin.attr("maxlength"));
    assertNotNull(doc.selectFirst("label[for=pin]"));
    assertNotNull(doc.selectFirst("label[for=pin_confirm]"));
    assertTrue(setup.text().contains("exactly 6 digits"));

    // wrong length
    Page page = submitNewPin(browser, setup, "1357", "1357");
    assertFieldError(page, "pin", "must be exactly 6 digits");
    // non-digits
    page = submitNewPin(browser, page, "13579a", "13579a");
    assertFieldError(page, "pin", "must be exactly 6 digits");
    // weak
    page = submitNewPin(browser, page, "123456", "123456");
    assertFieldError(page, "pin", "too easy to guess");
    page = submitNewPin(browser, page, "777777", "777777");
    assertFieldError(page, "pin", "too easy to guess");
    // mismatch
    page = submitNewPin(browser, page, "135791", "135792");
    assertFieldError(page, "pin_confirm", "do not match");
    assertTrue(credentials(userId, PinConstants.CREDENTIAL_TYPE).isEmpty());

    page = submitNewPin(browser, page, "135791", "135791");
    assertTrue(page.isClientRedirect(), "login completes: " + page.body());

    JsonNode data = pinData(userId);
    assertEquals(6, data.get("length").asInt());
    assertEquals("argon2", data.get("algorithm").asText());
    assertEquals(0, data.get("failures").asInt());
    assertFalse(data.get("locked").asBoolean());

    List<EventRepresentation> updates = events(userId, "UPDATE_CREDENTIAL");
    assertTrue(
        updates.stream()
            .anyMatch(
                e ->
                    PinConstants.CREDENTIAL_TYPE.equals(
                        e.getDetails().get(Details.CREDENTIAL_TYPE))),
        "UPDATE_CREDENTIAL event with credential_type");

    // next login asks for the new PIN
    Browser second = new Browser();
    Page pinPage = loginWithPassword(second, "setter", PASSWORD);
    assertTrue(pinPage.text().contains("6-digit PIN"), pinPage.body());
    assertTrue(submitPin(second, pinPage, "135791").isClientRedirect());
  }

  @Test
  void requiredActionConfigIsValidated() {
    assertEquals(400, setRequiredActionConfig(Map.of("length", "20")).statusCode());
    assertEquals(400, setRequiredActionConfig(Map.of("length", "x")).statusCode());
    assertEquals(
        204, setRequiredActionConfig(Map.of("length", "8", "reject-weak", "false")).statusCode());
  }

  @Test
  void weakPinAllowedWhenRejectWeakIsOff() throws Exception {
    setRequiredActionConfig(Map.of("reject-weak", "false"));
    String userId = createUser("weakling", PASSWORD, List.of(PinConstants.REQUIRED_ACTION_ID));
    Browser browser = new Browser();
    Page setup = loginWithPassword(browser, "weakling", PASSWORD);
    assertTrue(submitNewPin(browser, setup, "1111", "1111").isClientRedirect());
    assertEquals(4, pinData(userId).get("length").asInt());
  }

  @Test
  void loginWithPin_wrongAttemptsCountDown_thenLock() throws Exception {
    String userId =
        createUser(
            "locker",
            PASSWORD,
            List.of(),
            storedCredential(
                PinConstants.CREDENTIAL_TYPE, Argon2Fixtures.phasetwoPin("2580", 7168)));

    // correct PIN
    Browser browser = new Browser();
    Page pinPage = loginWithPassword(browser, "locker", PASSWORD);
    Element pin = pinPage.doc().getElementById("pin");
    assertNotNull(pin, pinPage.body());
    assertEquals("numeric", pin.attr("inputmode"));
    assertEquals("off", pin.attr("autocomplete"));
    assertEquals("4", pin.attr("maxlength"));
    assertNotNull(pinPage.doc().selectFirst("label[for=pin]"));
    assertTrue(pinPage.text().contains("4-digit PIN"));
    assertTrue(submitPin(browser, pinPage, "2580").isClientRedirect());

    // a second tab that reaches the PIN page before the lock
    Browser tab = new Browser();
    Page tabPage = loginWithPassword(tab, "locker", PASSWORD);
    assertNotNull(tabPage.doc().getElementById("pin"));

    // wrong PINs (max-attempts 3 in the fixture)
    Browser other = new Browser();
    Page page = loginWithPassword(other, "locker", PASSWORD);
    page = submitPin(other, page, "0000");
    assertFieldError(page, "pin", "2 attempts remaining");
    page = submitPin(other, page, "1111");
    assertFieldError(page, "pin", "1 attempt remaining");
    page = submitPin(other, page, "2222");
    assertTrue(page.text().contains("PIN is locked"), page.body());
    assertTrue(page.doc().getElementById("pin") == null, "no PIN input once locked");

    JsonNode data = pinData(userId);
    assertTrue(data.get("locked").asBoolean());
    assertEquals(3, data.get("failures").asInt());

    // even the right PIN fails now, without checking the hash
    Page direct = submitPin(tab, tabPage, "2580");
    assertTrue(direct.text().contains("PIN is locked"), direct.body());
    assertFalse(direct.isClientRedirect());
    assertEquals(3, pinData(userId).get("failures").asInt());

    // a fresh login shows the locked state straight away
    Page lockedPage = loginWithPassword(new Browser(), "locker", PASSWORD);
    assertTrue(lockedPage.text().contains("PIN is locked"));
    assertTrue(lockedPage.doc().getElementById("pin") == null);

    List<EventRepresentation> errors = events(userId, "LOGIN_ERROR");
    assertTrue(errors.size() >= 4, "4 failed attempts logged, got " + errors.size());
    assertTrue(
        errors.stream()
            .allMatch(
                e ->
                    Errors.INVALID_USER_CREDENTIALS.equals(e.getError())
                        && PinConstants.CREDENTIAL_TYPE.equals(
                            e.getDetails().get(Details.CREDENTIAL_TYPE))));
    assertTrue(
        errors.stream()
            .anyMatch(
                e -> PinConstants.EVENT_REASON_LOCKED.equals(e.getDetails().get(Details.REASON))));

    // admin unlock = delete the credential; the conditional sub-flow then skips the PIN
    String credId = credentials(userId, PinConstants.CREDENTIAL_TYPE).get(0).getId();
    realm().users().get(userId).removeCredential(credId);
    assertTrue(loginWithPassword(new Browser(), "locker", PASSWORD).isClientRedirect());
  }

  @Test
  void correctPinResetsFailures_andUnlimitedNeverLocks() throws Exception {
    String userId =
        createUser(
            "counter",
            PASSWORD,
            List.of(),
            storedCredential(
                PinConstants.CREDENTIAL_TYPE, Argon2Fixtures.phasetwoPin("2580", 7168)));
    Browser browser = new Browser();
    Page page = loginWithPassword(browser, "counter", PASSWORD);
    page = submitPin(browser, page, "0000");
    assertEquals(1, pinData(userId).get("failures").asInt());
    assertTrue(submitPin(browser, page, "2580").isClientRedirect());
    assertEquals(0, pinData(userId).get("failures").asInt());

    // max-attempts 0 = unlimited
    var config = realm().flows().getAuthenticatorConfig(pinExecutionConfigId());
    config.getConfig().put(PinConstants.CONFIG_MAX_ATTEMPTS, "0");
    realm().flows().updateAuthenticatorConfig(config.getId(), config);

    Browser other = new Browser();
    page = loginWithPassword(other, "counter", PASSWORD);
    for (int i = 0; i < 4; i++) {
      page = submitPin(other, page, "0000");
      assertFieldError(page, "pin", "Invalid PIN.");
      assertFalse(page.text().contains("remaining"));
    }
    assertFalse(pinData(userId).get("locked").asBoolean());
    assertTrue(submitPin(other, page, "2580").isClientRedirect());
  }

  @Test
  void rehashesWhenArgon2ParametersChanged() throws Exception {
    String userId =
        createUser(
            "rehash",
            PASSWORD,
            List.of(),
            storedCredential(
                PinConstants.CREDENTIAL_TYPE, Argon2Fixtures.phasetwoPin("2580", 4096)));
    assertEquals("4096", pinData(userId).at("/additionalParameters/memory/0").asText());
    Browser browser = new Browser();
    Page page = loginWithPassword(browser, "rehash", PASSWORD);
    assertTrue(submitPin(browser, page, "2580").isClientRedirect());
    JsonNode data = pinData(userId);
    assertEquals("7168", data.at("/additionalParameters/memory/0").asText());
    assertEquals(4, data.get("length").asInt());
    // and the new hash still verifies
    Browser again = new Browser();
    assertTrue(
        submitPin(again, loginWithPassword(again, "rehash", PASSWORD), "2580").isClientRedirect());
  }

  @Test
  void accountConsoleOffersSetUpAndUpdate() throws Exception {
    createUser("console", PASSWORD, List.of());
    JsonNode pin = accountPinType("console");
    assertEquals("two-factor", pin.get("category").asText());
    assertEquals(PinConstants.REQUIRED_ACTION_ID, pin.get("createAction").asText());
    assertTrue(pin.path("updateAction").isMissingNode() || pin.get("updateAction").isNull());
    assertTrue(pin.get("removeable").asBoolean());
    assertEquals(0, pin.get("userCredentialMetadatas").size());

    createUser(
        "console2",
        PASSWORD,
        List.of(),
        storedCredential(PinConstants.CREDENTIAL_TYPE, Argon2Fixtures.phasetwoPin("2580", 7168)));
    JsonNode withPin = accountPinType("console2");
    assertEquals(1, withPin.get("userCredentialMetadatas").size());
    assertEquals(PinConstants.REQUIRED_ACTION_ID, withPin.get("updateAction").asText());
    assertTrue(
        withPin.path("createAction").isMissingNode() || withPin.get("createAction").isNull());
    // secrets are never returned
    assertTrue(
        withPin.at("/userCredentialMetadatas/0/credential/secretData").isMissingNode()
            || withPin.at("/userCredentialMetadatas/0/credential/secretData").isNull());
  }

  @Test
  void applicationInitiatedActionShowsCancel() throws Exception {
    createUser("aia", PASSWORD, List.of());
    Browser browser = new Browser();
    Page setup =
        loginWithPassword(browser, "aia", PASSWORD, "kc_action=" + PinConstants.REQUIRED_ACTION_ID);
    assertNotNull(setup.doc().getElementById("pin"), setup.body());
    assertNotNull(setup.doc().selectFirst("button[name=cancel-aia]"));
    Page done = submitNewPin(browser, setup, "2468", "2468");
    assertTrue(done.isClientRedirect(), done.body());
    assertTrue(done.location().contains("kc_action_status=success"), done.location());
  }

  @Test
  void requiredExecutionEnrollsUsersWithoutPin() throws Exception {
    // make the PIN sub-flow REQUIRED, so the condition no longer skips users without a PIN
    var sub =
        realm().flows().getExecutions("pin browser forms").stream()
            .filter(e -> "pin browser conditional".equals(e.getDisplayName()))
            .findFirst()
            .orElseThrow();
    sub.setRequirement("REQUIRED");
    realm().flows().updateExecutions("pin browser forms", sub);

    String userId = createUser("enroll", PASSWORD, List.of());
    Browser browser = new Browser();
    Page setup = loginWithPassword(browser, "enroll", PASSWORD);
    assertNotNull(setup.doc().getElementById("pin_confirm"), "set-PIN page: " + setup.text());
    assertTrue(submitNewPin(browser, setup, "1357", "1357").isClientRedirect());
    assertEquals(4, pinData(userId).get("length").asInt());
  }

  // ------------------------------------------------------------------------------------------

  private static void assertFieldError(Page page, String field, String text) {
    Element error = page.doc().getElementById("input-error-" + field);
    assertNotNull(error, "error for " + field + " in " + page.body());
    assertTrue(error.text().contains(text), error.text());
    Element input = page.doc().getElementById(field);
    assertEquals("true", input.attr("aria-invalid"));
    assertTrue(input.attr("aria-describedby").contains("input-error-" + field));
  }

  private static String pinExecutionConfigId() {
    return realm().flows().getExecutions("pin browser conditional").stream()
        .filter(e -> PinConstants.AUTHENTICATOR_ID.equals(e.getProviderId()))
        .findFirst()
        .orElseThrow()
        .getAuthenticationConfig();
  }

  private static JsonNode accountPinType(String username) throws Exception {
    String token =
        io.restassured.RestAssured.given()
            .baseUri(container.getAuthServerUrl())
            .formParam("grant_type", "password")
            .formParam("client_id", CLIENT)
            .formParam("username", username)
            .formParam("password", PASSWORD)
            .post("realms/" + REALM + "/protocol/openid-connect/token")
            .then()
            .statusCode(200)
            .extract()
            .path("access_token");
    String body =
        io.restassured.RestAssured.given()
            .baseUri(container.getAuthServerUrl())
            .auth()
            .oauth2(token)
            .accept("application/json")
            .get("realms/" + REALM + "/account/credentials")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    for (JsonNode type : MAPPER.readTree(body)) {
      if (PinConstants.CREDENTIAL_TYPE.equals(type.get("type").asText())) return type;
    }
    throw new AssertionError("phasetwo-pin not offered by the account console: " + body);
  }
}
