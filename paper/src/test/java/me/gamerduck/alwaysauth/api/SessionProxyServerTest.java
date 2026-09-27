package me.gamerduck.alwaysauth.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import me.gamerduck.alwaysauth.Platform;
import me.gamerduck.alwaysauth.api.config.SessionConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class SessionProxyServerTest {
    private static final String PROFILE = "{\"id\":\"123456781234123412341234567890ab\",\"name\":\"PlayerOne\",\"properties\":[]}";
    private static final String SECRET = "secret+/session/minecraft/hasJoined?&=%26";
    private static final String IP = "203.0.113.7";
    private static final String HAS_JOINED = "/session/minecraft/hasJoined";
    private static final String JOIN = "/session/minecraft/join";

    @TempDir Path temporaryDirectory;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private UpstreamFixture upstream;
    private TestPlatform platform;
    private String secret;
    private Path dataDirectory;

    @BeforeEach
    void startServers() throws Exception {
        upstream = new UpstreamFixture();
        createPlatform(SECRET, true);
    }

    @AfterEach
    void stopServers() {
        if (platform != null) platform.onDisable();
        if (upstream != null) upstream.close();
    }

    private void createPlatform(String newSecret, boolean authenticationEnabled) throws IOException {
        if (platform != null) platform.onDisable();
        secret = newSecret;
        dataDirectory = Files.createTempDirectory(temporaryDirectory, "plugin-");
        Files.writeString(dataDirectory.resolve("config.properties"),
                "port=0\nip-address=127.0.0.1\ncheck-updates=false\nsecret-key=" + secret
                        + "\nauthentication-enabled=" + authenticationEnabled
                        + "\nupstream-server=" + upstream.url() + "\n");
        platform = new TestPlatform(dataDirectory);
    }

    @Test
    void successfulOnlineLoginPreservesClientIpAndDecodesQueryOnce() throws Exception {
        String serverId = "hash+&?=%26";
        HttpResponse<String> response = get(authenticatedUri(HAS_JOINED,
                "username=PlayerOne&serverId=" + encode(serverId) + "&ip=" + encode(IP)));

        assertEquals(200, response.statusCode());
        assertEquals(PROFILE, response.body());
        assertEquals("application/json; charset=UTF-8", response.headers().firstValue("Content-Type").orElseThrow());
        assertEquals(Map.of("username", "PlayerOne", "serverId", serverId, "ip", IP),
                decodeQuery(upstream.lastUri.get().getRawQuery()));
        assertEquals(PROFILE, platform.proxyServer().getDatabase().getFallbackAuth("playerone", IP, "basic", 72));
    }

    @Test
    void legacyNestedQueryRouteSupportsEncodedTokenAndGeneratedBase64Token() throws Exception {
        String query = "username=PlayerOne&serverId=" + encode("hash+%26") + "&ip=" + encode(IP);
        assertEquals(200, get(URI.create(proxyUrl() + "/auth?token=" + encode(secret) + HAS_JOINED + "?" + query)).statusCode());
        assertEquals("hash+%26", decodeQuery(upstream.lastUri.get().getRawQuery()).get("serverId"));

        createPlatform("generated/base64/key==", true);
        assertEquals(200, get(URI.create(proxyUrl() + "/auth?token=" + secret + HAS_JOINED + "?" + query)).statusCode());
        assertEquals(IP, decodeQuery(upstream.lastUri.get().getRawQuery()).get("ip"));
    }

    @Test
    void legacyRouteAlsoAcceptsOrdinaryAmpersandParameters() throws Exception {
        URI request = URI.create(proxyUrl() + "/auth?token=" + encode(secret) + HAS_JOINED
                + "&username=PlayerOne&serverId=hash&ip=" + encode(IP));
        assertEquals(200, get(request).statusCode());
    }

    @ParameterizedTest
    @ValueSource(ints = {204, 400, 401, 403, 404})
    void explicitUpstreamRejectionCannotAuthenticateCachedPlayer(int rejection) throws Exception {
        cacheOnlineLogin();
        upstream.status.set(rejection);
        upstream.body.set("Denied");

        HttpResponse<String> response = hasJoined(IP);
        assertEquals(rejection, response.statusCode());
        assertEquals(rejection == 204 ? "" : "Denied", response.body());
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 500, 502, 503, 504})
    void upstreamOutageAllowsPreviouslyAuthenticatedMatchingIp(int outage) throws Exception {
        cacheOnlineLogin();
        upstream.status.set(outage);
        upstream.body.set("Unavailable");
        HttpResponse<String> response = hasJoined(IP);
        assertEquals(200, response.statusCode());
        assertEquals(PROFILE, response.body());
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "unknown", "UNKNOWN", "203.0.113.8"})
    void fallbackRequiresKnownMatchingClientIp(String ip) throws Exception {
        cacheOnlineLogin();
        upstream.status.set(503);
        assertEquals(503, hasJoined(ip).statusCode());
    }

    @Test
    void onlineLoginWithoutClientIpDoesNotCreateAnUnboundCacheEntry() throws Exception {
        assertEquals(200, hasJoined(null).statusCode());
        assertEquals(0, platform.proxyServer().getDatabase().getStats().totalPlayers());
        upstream.status.set(503);
        assertEquals(503, hasJoined(IP).statusCode());
    }

    @Test
    void disabledFallbackRetainsUnavailableResult() throws Exception {
        cacheOnlineLogin();
        platform.config().setFallbackEnabled(false);
        upstream.status.set(503);
        assertEquals(503, hasJoined(IP).statusCode());
    }

    @Test
    void reloadAndSubsequentToggleUpdateRunningFallback() throws Exception {
        cacheOnlineLogin();
        platform.config().setFallbackEnabled(false);
        platform.config().saveConfig();
        platform.cmdReload(new Object());
        upstream.status.set(503);
        assertEquals(503, hasJoined(IP).statusCode());

        platform.cmdToggle(new Object());
        assertEquals(200, hasJoined(IP).statusCode());
    }

    @Test
    void mediumExpiryUsesExactDurationAndBasicAndZeroLimitRetainExistingContract() throws Exception {
        cacheOnlineLogin();
        String databaseUrl = "jdbc:h2:file:" + dataDirectory.resolve("authcache.db").toAbsolutePath()
                + ";AUTO_SERVER=TRUE;MODE=MySQL";
        try (var connection = DriverManager.getConnection(databaseUrl, "sa", "");
             var statement = connection.prepareStatement("UPDATE player_auth SET last_seen = ?")) {
            statement.setLong(1, System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(90));
            assertEquals(1, statement.executeUpdate());
        }
        platform.config().setSecurityLevel("medium");
        platform.config().setMaxOfflineHours(1);
        upstream.status.set(503);
        assertEquals(503, hasJoined(IP).statusCode());

        platform.config().setSecurityLevel("basic");
        assertEquals(200, hasJoined(IP).statusCode());
        platform.config().setSecurityLevel("medium");
        platform.config().setMaxOfflineHours(0);
        assertEquals(200, hasJoined(IP).statusCode());
    }

    @Test
    void cacheFailureCannotChangeSuccessfulOnlineAuthenticationOrAuthorizeFallback() throws Exception {
        cacheOnlineLogin();
        platform.proxyServer().getDatabase().close();
        assertEquals(200, hasJoined(IP).statusCode());
        upstream.status.set(503);
        assertEquals(503, hasJoined(IP).statusCode());
    }

    @Test
    void connectionFailureAllowsMatchingCachedSession() throws Exception {
        cacheOnlineLogin();
        upstream.close();
        assertEquals(200, hasJoined(IP).statusCode());
        assertEquals(503, hasJoined("203.0.113.8").statusCode());
    }

    @Test
    void readTimeoutAllowsMatchingCachedSession() throws Exception {
        cacheOnlineLogin();
        upstream.delayMillis.set(4000);
        assertEquals(200, hasJoined(IP).statusCode());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "null", "[]", "{}", "not-json",
            "{\"id\":\"not-a-uuid\",\"name\":\"PlayerOne\"}",
            "{\"id\":\"123456781234123412341234567890ab\",\"name\":\"AnotherPlayer\"}"})
    void malformedSuccessfulResponseCannotUseCachedFallback(String invalidResponse) throws Exception {
        cacheOnlineLogin();
        upstream.body.set(invalidResponse);
        assertEquals(502, hasJoined(IP).statusCode());
    }

    @Test
    void missingWrongAndDuplicateTokensAreRejectedWithoutForwarding() throws Exception {
        String query = "username=PlayerOne&serverId=hash&ip=" + encode(IP);
        assertEquals(403, get(URI.create(proxyUrl() + "/auth" + HAS_JOINED + "?" + query)).statusCode());
        assertEquals(403, get(URI.create(proxyUrl() + "/auth" + HAS_JOINED + "?token=wrong&" + query)).statusCode());
        assertEquals(400, get(URI.create(proxyUrl() + "/auth" + HAS_JOINED
                + "?token=" + encode(secret) + "&token=" + encode(secret) + "&" + query)).statusCode());
        assertNull(upstream.lastUri.get());
    }

    @Test
    void incompleteTokenRouteAndDuplicateSessionParametersReturnClientErrors() throws Exception {
        assertEquals(404, get(URI.create(proxyUrl() + "/auth?token=" + encode(secret))).statusCode());
        assertEquals(400, get(authenticatedUri(HAS_JOINED, "username=PlayerOne&username=PlayerOne&serverId=hash")).statusCode());
        assertEquals(400, get(authenticatedUri(HAS_JOINED, "username=PlayerOne")).statusCode());
        assertEquals(404, get(authenticatedUri(HAS_JOINED + "Extra", "username=PlayerOne&serverId=hash")).statusCode());
        assertEquals(405, get(authenticatedUri(JOIN, "")).statusCode());
        assertNull(upstream.lastUri.get());
    }

    @ParameterizedTest
    @ValueSource(ints = {204, 403})
    void joinForwardsRequestAndPreservesUpstreamResult(int status) throws Exception {
        upstream.status.set(status);
        upstream.body.set("Rejected join");
        String body = "{\"accessToken\":\"example\",\"selectedProfile\":\"1234\",\"serverId\":\"hash\"}";
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(authenticatedUri(JOIN, ""))
                .timeout(Duration.ofSeconds(10)).POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(status, response.statusCode());
        assertEquals(body, upstream.lastBody.get());
        assertEquals(JOIN, upstream.lastUri.get().getPath());
        assertEquals(status == 204 ? "" : "Rejected join", response.body());
    }

    @Test
    void authenticationDisabledAcceptsDirectSessionPath() throws Exception {
        createPlatform(SECRET, false);
        assertEquals(200, get(URI.create(proxyUrl() + HAS_JOINED + "?username=PlayerOne&serverId=hash&ip=" + encode(IP))).statusCode());
    }

    @Test
    void stopIsIdempotentAndReleasesListenerAndDatabase() throws Exception {
        cacheOnlineLogin();
        int port = platform.proxyServer().boundPort();
        platform.proxyServer().stop();
        platform.proxyServer().stop();
        HttpServer rebound = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        rebound.start();
        try {
            assertEquals(port, rebound.getAddress().getPort());
            assertNull(platform.proxyServer().getDatabase().getFallbackAuth("PlayerOne", IP, "basic", 72));
        } finally {
            rebound.stop(0);
        }
    }

    @Test
    void bindFailureDoesNotCreateDatabase() throws Exception {
        Path failedDirectory = Files.createDirectory(temporaryDirectory.resolve("bind-failure"));
        SessionConfig config = new SessionConfig(failedDirectory.toFile(), platform);
        assertThrows(IOException.class, () -> new SessionProxyServer(
                platform.proxyServer().boundPort(), failedDirectory.toFile(), platform, config));
        assertFalse(Files.exists(failedDirectory.resolve("authcache.db.mv.db")));
    }

    @Test
    void databaseInitializationFailureReleasesAlreadyBoundPort() throws Exception {
        Path invalidDirectory = Files.writeString(temporaryDirectory.resolve("regular-file"), "not a directory");
        int port;
        try (ServerSocket reserved = new ServerSocket(0, 0, java.net.InetAddress.getByName("127.0.0.1"))) {
            port = reserved.getLocalPort();
        }
        assertThrows(IllegalStateException.class, () -> new SessionProxyServer(
                port, invalidDirectory.toFile(), platform, platform.config()));
        HttpServer rebound = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        rebound.start();
        rebound.stop(0);
    }

    @Test
    void stoppingBeforeStartReleasesListener() throws Exception {
        Path directory = Files.createDirectory(temporaryDirectory.resolve("never-started"));
        SessionConfig config = new SessionConfig(directory.toFile(), platform);
        SessionProxyServer neverStarted = new SessionProxyServer(0, directory.toFile(), platform, config);
        int port = neverStarted.boundPort();
        neverStarted.stop();
        HttpServer rebound = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        rebound.start();
        rebound.stop(0);
    }

    private void cacheOnlineLogin() throws Exception {
        assertEquals(200, hasJoined(IP).statusCode());
        assertEquals(1, platform.proxyServer().getDatabase().getStats().totalPlayers());
    }

    private HttpResponse<String> hasJoined(String ip) throws Exception {
        String query = "username=PlayerOne&serverId=hash" + (ip == null ? "" : "&ip=" + encode(ip));
        return get(authenticatedUri(HAS_JOINED, query));
    }

    private HttpResponse<String> get(URI uri) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private URI authenticatedUri(String endpoint, String query) {
        return URI.create(proxyUrl() + "/auth" + endpoint + "?token=" + encode(secret) + (query.isEmpty() ? "" : "&" + query));
    }

    private String proxyUrl() {
        return "http://127.0.0.1:" + platform.proxyServer().boundPort();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static Map<String, String> decodeQuery(String query) {
        Map<String, String> params = new HashMap<>();
        for (String parameter : query.split("&")) {
            String[] pair = parameter.split("=", 2);
            params.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8), URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        return params;
    }

    private static final class TestPlatform extends Platform<Object> {
        private TestPlatform(Path directory) { super(directory); }
        @Override public void sendMessage(Object recipient, String message) { }
        @Override public boolean hasPermission(Object recipient, String permission) { return false; }
        @Override public void sendLogMessage(String message) { }
        @Override public void sendSevereLogMessage(String message) { }
        @Override public void sendWarningLogMessage(String message) { }
        @Override public Optional<String> getUpdateMessage() { return Optional.empty(); }
    }

    private static final class UpstreamFixture implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        private final AtomicInteger status = new AtomicInteger(200);
        private final AtomicReference<String> body = new AtomicReference<>(PROFILE);
        private final AtomicReference<URI> lastUri = new AtomicReference<>();
        private final AtomicReference<String> lastBody = new AtomicReference<>();
        private final AtomicLong delayMillis = new AtomicLong();
        private boolean closed;

        private UpstreamFixture() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/session/minecraft/", this::respond);
            server.setExecutor(executor);
            server.start();
        }

        private String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }

        private void respond(HttpExchange exchange) throws IOException {
            lastUri.set(exchange.getRequestURI());
            lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            try {
                if (delayMillis.get() > 0) Thread.sleep(delayMillis.get());
                int code = status.get();
                byte[] response = body.get().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(code, code == 204 || response.length == 0 ? -1 : response.length);
                if (code != 204 && response.length > 0) exchange.getResponseBody().write(response);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        }

        @Override public void close() {
            if (closed) return;
            closed = true;
            server.stop(0);
            executor.shutdownNow();
        }
    }
}
