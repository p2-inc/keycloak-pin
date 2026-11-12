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
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Details;

/**
 * Reset credentials flow ({@code phasetwo-pin-reset}), execute-actions email, and migration from
 * please-open.it's {@code pin-code} credential (spec D6).
 */
class PinResetAndMigrationTest extends AbstractPinIntegrationTest {

  private static final String PASSWORD = "Password-123";

  @Test
  void resetCredentialsFlow_removesLockedPin_andRequiresNewPin() throws Exception {
    String[] locked = Argon2Fixtures.phasetwoPin("2580", 7168);
    locked[1] =
        locked[1].replace("\"failures\":0,\"locked\":false", "\"failures\":3,\"locked\":true");
    String userId =
        createUser(
            "resetter",
            PASSWORD,
            List.of(),
            storedCredential(PinConstants.CREDENTIAL_TYPE, locked));
    assertTrue(pinData(userId).get("locked").asBoolean());

    Browser browser = new Browser();
    Page login = browser.get(authUrl());
    Element forgot = login.doc().selectFirst("a[href*=reset-credentials]");
    assertNotNull(forgot, "forgot password link: " + login.body());
    Page choose = browser.get(forgot.absUrl("href"));
    Page sent = browser.submit(choose, Map.of("username", "resetter"));
    assertEquals(200, sent.status(), sent.body());

    String link = actionTokenLink(awaitMail("resetter@phasetwo.io"));
    Page setup = browser.get(link);
    assertNotNull(setup.doc().getElementById("pin"), "set-PIN page after reset: " + setup.body());
    assertTrue(credentials(userId, PinConstants.CREDENTIAL_TYPE).isEmpty(), "old PIN removed");
    assertTrue(
        realm()
            .users()
            .get(userId)
            .toRepresentation()
            .getRequiredActions()
            .contains(PinConstants.REQUIRED_ACTION_ID));

    Page done = submitNewPin(browser, setup, "1357", "1357");
    assertTrue(done.isClientRedirect() || done.status() == 200, done.body());

    JsonNode data = pinData(userId);
    assertFalse(data.get("locked").asBoolean());
    assertEquals(0, data.get("failures").asInt());
    assertFalse(
        realm()
            .users()
            .get(userId)
            .toRepresentation()
            .getRequiredActions()
            .contains(PinConstants.REQUIRED_ACTION_ID));
    assertTrue(
        events(userId, "REMOVE_CREDENTIAL").stream()
            .anyMatch(
                e ->
                    PinConstants.CREDENTIAL_TYPE.equals(
                        e.getDetails().get(Details.CREDENTIAL_TYPE))));

    Browser fresh = new Browser();
    Page pinPage = loginWithPassword(fresh, "resetter", PASSWORD);
    assertTrue(submitPin(fresh, pinPage, "1357").isClientRedirect());
  }

  @Test
  void resetCredentialsFlow_leavesUsersWithoutPinAlone() throws Exception {
    String userId = createUser("nopin", PASSWORD, List.of());
    Browser browser = new Browser();
    Page login = browser.get(authUrl());
    Page choose = browser.get(login.doc().selectFirst("a[href*=reset-credentials]").absUrl("href"));
    browser.submit(choose, Map.of("username", "nopin"));
    Page after = browser.get(actionTokenLink(awaitMail("nopin@phasetwo.io")));
    assertTrue(after.doc().getElementById("pin") == null, after.body());
    assertFalse(
        realm()
            .users()
            .get(userId)
            .toRepresentation()
            .getRequiredActions()
            .contains(PinConstants.REQUIRED_ACTION_ID));
  }

  @Test
  void executeActionsEmail_setsPin() throws Exception {
    String userId = createUser("emailed", PASSWORD, List.of());
    realm()
        .users()
        .get(userId)
        .executeActionsEmail(CLIENT, REDIRECT_URI, List.of(PinConstants.REQUIRED_ACTION_ID));
    String mail = awaitMail("emailed@phasetwo.io");
    assertTrue(mail.contains("Configure PIN"), "required action name in the email: " + mail);

    Browser browser = new Browser();
    Page page = browser.get(actionTokenLink(mail));
    if (page.doc().getElementById("pin") == null) {
      // Keycloak shows "perform the following actions" with a proceed link first
      Element proceed = page.doc().selectFirst("a[href*=action-token], a[href*=login-actions]");
      assertNotNull(proceed, page.body());
      page = browser.get(proceed.absUrl("href"));
    }
    assertNotNull(page.doc().getElementById("pin"), page.body());
    Page done = submitNewPin(browser, page, "8642", "8642");
    assertTrue(done.isClientRedirect() || done.status() == 200, done.body());
    assertEquals(4, pinData(userId).get("length").asInt());
  }

  @Test
  void migratesPleaseOpenItPinCode() throws Exception {
    String userId =
        createUser(
            "legacy",
            PASSWORD,
            List.of(),
            storedCredential(
                PinConstants.LEGACY_CREDENTIAL_TYPE,
                Argon2Fixtures.legacyPinCode("246813", "6-digits")));
    assertEquals(
        1,
        credentials(userId, PinConstants.LEGACY_CREDENTIAL_TYPE).size(),
        "pin-code credential is kept on user import");

    Browser browser = new Browser();
    Page pinPage = loginWithPassword(browser, "legacy", PASSWORD);
    assertTrue(pinPage.text().contains("6-digit PIN"), pinPage.body());

    Page wrong = submitPin(browser, pinPage, "000000");
    assertTrue(wrong.text().contains("2 attempts remaining"), wrong.body());
    assertEquals(
        1,
        MAPPER
            .readTree(
                credentials(userId, PinConstants.LEGACY_CREDENTIAL_TYPE).get(0).getCredentialData())
            .get("failures")
            .asInt());

    assertTrue(submitPin(browser, wrong, "246813").isClientRedirect());
    assertTrue(
        credentials(userId, PinConstants.LEGACY_CREDENTIAL_TYPE).isEmpty(), "pin-code removed");
    JsonNode data = pinData(userId);
    assertEquals(6, data.get("length").asInt());
    assertEquals(0, data.get("failures").asInt());

    Browser fresh = new Browser();
    assertTrue(
        submitPin(fresh, loginWithPassword(fresh, "legacy", PASSWORD), "246813")
            .isClientRedirect());
  }

  @Test
  void legacyPinCodeLocksToo() throws Exception {
    String userId =
        createUser(
            "legacylock",
            PASSWORD,
            List.of(),
            storedCredential(
                PinConstants.LEGACY_CREDENTIAL_TYPE,
                Argon2Fixtures.legacyPinCode("1357", "4-digits")));
    Browser browser = new Browser();
    Page page = loginWithPassword(browser, "legacylock", PASSWORD);
    for (String wrong : List.of("0000", "1111", "2222")) page = submitPin(browser, page, wrong);
    assertTrue(page.text().contains("PIN is locked"), page.body());
    Page again = loginWithPassword(new Browser(), "legacylock", PASSWORD);
    assertTrue(again.text().contains("PIN is locked"));
    assertEquals(1, credentials(userId, PinConstants.LEGACY_CREDENTIAL_TYPE).size());
  }
}
