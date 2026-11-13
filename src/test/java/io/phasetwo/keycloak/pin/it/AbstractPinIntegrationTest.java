package io.phasetwo.keycloak.pin.it;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.phasetwo.keycloak.pin.PinConstants;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.CookieHandler;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.utility.MountableFile;

/**
 * Testcontainers harness: one Keycloak (with {@code target/classes} as a provider) and one MailHog
 * on a shared network, a fresh {@code pin-test} realm per test, and a small cookie-aware browser.
 *
 * <p>The server version comes from {@code -Dkeycloak-version} (default from the pom), so {@code mvn
 * verify -Dkeycloak-version=26.4.7} runs the same suite against 26.4.
 */
public abstract class AbstractPinIntegrationTest {

  public static final String KEYCLOAK_IMAGE =
      String.format(
          "quay.io/phasetwo/keycloak-crdb:%s", System.getProperty("keycloak-version", "26.8.0"));
  public static final String REALM = "pin-test";
  public static final String CLIENT = "pin-client";
  public static final String REDIRECT_URI = "http://localhost/callback";

  static final ObjectMapper MAPPER = JsonSerialization.mapper;
  static final Network network = Network.newNetwork();

  static final GenericContainer<?> mailhog =
      new GenericContainer<>("mailhog/mailhog:v1.0.1")
          .withNetwork(network)
          .withNetworkAliases("mailhog")
          .withExposedPorts(1025, 8025);

  static final KeycloakContainer container = buildContainer();
  static Keycloak keycloak;

  private static KeycloakContainer buildContainer() {
    KeycloakContainer c =
        new KeycloakContainer(KEYCLOAK_IMAGE)
            .withContextPath("/auth")
            .withProviderClassesFrom("target/classes")
            .withNetwork(network)
            .withExposedPorts(8080, 9000)
            .withLogConsumer(
                frame -> {
                  String line = frame.getUtf8String();
                  if (line.contains("ERROR") || line.contains("WARN"))
                    System.out.print("[KC] " + line);
                });
    if (isJacocoPresent()) {
      c =
          c.withCopyFileToContainer(
                  MountableFile.forHostPath("target/jacoco-agent/"), "/jacoco-agent")
              .withEnv(
                  "JAVA_OPTS_APPEND",
                  "-javaagent:/jacoco-agent/org.jacoco.agent-runtime.jar=destfile=/tmp/jacoco.exec");
    }
    return c;
  }

  private static boolean isJacocoPresent() {
    return Files.exists(Path.of("target/jacoco-agent/org.jacoco.agent-runtime.jar"));
  }

  @BeforeAll
  static void startContainers() {
    if (!mailhog.isRunning()) mailhog.start();
    if (!container.isRunning()) container.start();
    keycloak = container.getKeycloakAdminClient();
  }

  @AfterAll
  static void stopContainers() throws IOException {
    if (isJacocoPresent() && container.isRunning()) {
      String id = container.getContainerId();
      container.getDockerClient().stopContainerCmd(id).exec();
      Files.createDirectories(Path.of("target", "jacoco-report"));
      container.copyFileFromContainer(
          "/tmp/jacoco.exec",
          "./target/jacoco-report/jacoco-%s.exec".formatted(id.substring(0, 12)));
      // the agent only writes on JVM exit, so the next test class needs a fresh container
      container.stop();
    }
  }

  @BeforeEach
  void importRealmAndRegisterAction() throws Exception {
    try (InputStream in = getClass().getResourceAsStream("/realms/pin-realm.json")) {
      keycloak.realms().create(JsonSerialization.readValue(in, RealmRepresentation.class));
    }
    adminRequest()
        .body(Map.of("providerId", PinConstants.REQUIRED_ACTION_ID, "name", "Configure PIN"))
        .post("authentication/register-required-action")
        .then()
        .statusCode(204);
    clearMail();
  }

  @AfterEach
  void removeRealm() {
    try {
      keycloak.realm(REALM).remove();
    } catch (Exception ignored) {
      // best effort
    }
  }

  // ------------------------------------------------------------------------------------------
  // admin helpers
  // ------------------------------------------------------------------------------------------

  static RealmResource realm() {
    return keycloak.realm(REALM);
  }

  static io.restassured.specification.RequestSpecification adminRequest() {
    return given()
        .baseUri(container.getAuthServerUrl())
        .basePath("admin/realms/" + REALM + "/")
        .contentType("application/json")
        .auth()
        .oauth2(keycloak.tokenManager().getAccessTokenString());
  }

  static io.restassured.response.Response setRequiredActionConfig(Map<String, String> config) {
    return adminRequest()
        .body(Map.of("config", config))
        .put("authentication/required-actions/" + PinConstants.REQUIRED_ACTION_ID + "/config");
  }

  /** Creates a user with a password and optional extra stored credentials. */
  static String createUser(
      String username,
      String password,
      List<String> requiredActions,
      CredentialRepresentation... extra) {
    UserRepresentation user = new UserRepresentation();
    user.setUsername(username);
    user.setEmail(username + "@phasetwo.io");
    user.setEmailVerified(true);
    user.setFirstName("Pin");
    user.setLastName("Tester");
    user.setEnabled(true);
    user.setRequiredActions(requiredActions);
    List<CredentialRepresentation> creds = new ArrayList<>();
    CredentialRepresentation pw = new CredentialRepresentation();
    pw.setType(CredentialRepresentation.PASSWORD);
    pw.setValue(password);
    pw.setTemporary(false);
    creds.add(pw);
    creds.addAll(List.of(extra));
    user.setCredentials(creds);
    try (Response response = realm().users().create(user)) {
      assertEquals(201, response.getStatus(), "user create");
      String path = response.getLocation().getPath();
      return path.substring(path.lastIndexOf('/') + 1);
    }
  }

  static CredentialRepresentation storedCredential(String type, String[] secretAndData) {
    CredentialRepresentation c = new CredentialRepresentation();
    c.setType(type);
    c.setSecretData(secretAndData[0]);
    c.setCredentialData(secretAndData[1]);
    return c;
  }

  static List<CredentialRepresentation> credentials(String userId, String type) {
    return realm().users().get(userId).credentials().stream()
        .filter(c -> type.equals(c.getType()))
        .toList();
  }

  static JsonNode pinData(String userId) throws IOException {
    List<CredentialRepresentation> pins = credentials(userId, PinConstants.CREDENTIAL_TYPE);
    assertEquals(1, pins.size(), "exactly one phasetwo-pin credential");
    return MAPPER.readTree(pins.get(0).getCredentialData());
  }

  static List<EventRepresentation> events(String userId, String type) {
    return realm().getEvents(List.of(type), null, userId, null, null, null, 0, 100);
  }

  // ------------------------------------------------------------------------------------------
  // browser
  // ------------------------------------------------------------------------------------------

  /** A page or redirect returned to the browser. */
  record Page(int status, String body, String location, URI uri) {
    Document doc() {
      return Jsoup.parse(body, uri.toString());
    }

    String formAction() {
      Element form = doc().selectFirst("form[action]");
      return form == null ? null : form.absUrl("action");
    }

    boolean isClientRedirect() {
      return location != null && location.startsWith(REDIRECT_URI);
    }

    String text() {
      return doc().text();
    }
  }

  /** Cookie-aware HTTP client that follows redirects inside Keycloak only. */
  static final class Browser {
    private final HttpClient http =
        HttpClient.newBuilder()
            .cookieHandler(new CookieJar())
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    Page get(String url) throws Exception {
      return follow(send(HttpRequest.newBuilder(URI.create(url)).GET().build()));
    }

    Page post(String url, Map<String, String> form) throws Exception {
      String body =
          form.entrySet().stream()
              .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
              .collect(Collectors.joining("&"));
      return follow(
          send(
              HttpRequest.newBuilder(URI.create(url))
                  .header("Content-Type", "application/x-www-form-urlencoded")
                  .POST(HttpRequest.BodyPublishers.ofString(body))
                  .build()));
    }

    /** Submits the first form on the page with the given fields. */
    Page submit(Page page, Map<String, String> form) throws Exception {
      return post(page.formAction(), form);
    }

    private Page send(HttpRequest request) throws Exception {
      HttpResponse<String> r = http.send(request, HttpResponse.BodyHandlers.ofString());
      return new Page(
          r.statusCode(), r.body(), r.headers().firstValue("Location").orElse(null), r.uri());
    }

    private Page follow(Page page) throws Exception {
      int hops = 0;
      while (page.status() / 100 == 3 && page.location() != null && !page.isClientRedirect()) {
        if (++hops > 10) throw new AssertionError("too many redirects");
        URI next = page.uri().resolve(page.location());
        page = send(HttpRequest.newBuilder(next).GET().build());
      }
      return page;
    }
  }

  /**
   * Single-host cookie jar. Keycloak marks its auth cookies {@code SameSite=None; Secure}, and the
   * JDK's {@code CookieManager} never replays Secure cookies over plain http (browsers exempt
   * localhost), so it would drop the auth session between requests.
   */
  static final class CookieJar extends CookieHandler {
    private final Map<String, String> cookies = new LinkedHashMap<>();

    @Override
    public synchronized Map<String, List<String>> get(
        URI uri, Map<String, List<String>> requestHeaders) {
      if (cookies.isEmpty()) return Map.of();
      return Map.of(
          "Cookie",
          List.of(
              cookies.entrySet().stream()
                  .map(e -> e.getKey() + "=" + e.getValue())
                  .collect(Collectors.joining("; "))));
    }

    @Override
    public synchronized void put(URI uri, Map<String, List<String>> responseHeaders) {
      responseHeaders.forEach(
          (name, values) -> {
            if (name == null || !name.equalsIgnoreCase("Set-Cookie")) return;
            for (String header : values) {
              String[] parts = header.split(";");
              String[] kv = parts[0].split("=", 2);
              if (kv.length != 2) continue;
              String key = kv[0].trim();
              String value = kv[1].trim();
              boolean expired = value.isEmpty();
              for (String attr : parts) {
                String a = attr.trim().toLowerCase();
                if (a.equals("max-age=0") || a.startsWith("expires=thu, 01 jan 1970")) {
                  expired = true;
                }
              }
              if (expired) cookies.remove(key);
              else cookies.put(key, value);
            }
          });
    }
  }

  static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }

  static String authUrl(String... extraParams) {
    StringBuilder sb =
        new StringBuilder(container.getAuthServerUrl())
            .append("/realms/")
            .append(REALM)
            .append("/protocol/openid-connect/auth?client_id=")
            .append(CLIENT)
            .append("&response_type=code&scope=openid&redirect_uri=")
            .append(enc(REDIRECT_URI));
    for (String p : extraParams) sb.append('&').append(p);
    return sb.toString();
  }

  /** Opens the login page and submits username and password. */
  static Page loginWithPassword(Browser browser, String username, String password, String... extra)
      throws Exception {
    Page login = browser.get(authUrl(extra));
    assertEquals(200, login.status(), "login page");
    Map<String, String> form = new LinkedHashMap<>();
    form.put("username", username);
    form.put("password", password);
    return browser.submit(login, form);
  }

  static Page submitPin(Browser browser, Page page, String pin) throws Exception {
    return browser.submit(page, Map.of(PinConstants.FORM_PIN, pin));
  }

  static Page submitNewPin(Browser browser, Page page, String pin, String confirm)
      throws Exception {
    return browser.submit(
        page, Map.of(PinConstants.FORM_PIN, pin, PinConstants.FORM_PIN_CONFIRM, confirm));
  }

  // ------------------------------------------------------------------------------------------
  // mail
  // ------------------------------------------------------------------------------------------

  private static final Pattern LINK =
      Pattern.compile("https?://[^\\s\"'<>]+action-token[^\\s\"'<>]*");

  static String mailhogUrl() {
    return "http://" + mailhog.getHost() + ":" + mailhog.getMappedPort(8025);
  }

  static void clearMail() {
    given().baseUri(mailhogUrl()).delete("/api/v1/messages").then().statusCode(200);
  }

  /** Waits for a mail to {@code to} and returns its decoded body. */
  static String awaitMail(String to) throws Exception {
    long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
    while (System.nanoTime() < deadline) {
      JsonNode items =
          MAPPER
              .readTree(given().baseUri(mailhogUrl()).get("/api/v2/messages").asString())
              .get("items");
      for (JsonNode item : items) {
        for (JsonNode recipient : item.path("To")) {
          String address =
              recipient.path("Mailbox").asText() + "@" + recipient.path("Domain").asText();
          if (address.equalsIgnoreCase(to)) {
            return decodeQuotedPrintable(item.path("Content").path("Body").asText());
          }
        }
      }
      Thread.sleep(250);
    }
    throw new AssertionError("Timed out waiting for mail to " + to);
  }

  static String actionTokenLink(String mailBody) {
    Matcher m = LINK.matcher(mailBody);
    if (!m.find()) throw new AssertionError("no action-token link in mail: " + mailBody);
    return m.group().replace("&amp;", "&");
  }

  private static String decodeQuotedPrintable(String s) {
    return s.replace("=\r\n", "").replace("=\n", "").replace("=3D", "=");
  }
}
