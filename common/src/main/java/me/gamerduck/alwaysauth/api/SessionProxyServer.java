package me.gamerduck.alwaysauth.api;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import me.gamerduck.alwaysauth.Platform;
import me.gamerduck.alwaysauth.api.config.SessionConfig;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class SessionProxyServer {
    private static final int UPSTREAM_TIMEOUT_MS = 3000;
    private static final String HAS_JOINED_PATH = "/session/minecraft/hasJoined";
    private static final String JOIN_PATH = "/session/minecraft/join";

    private final HttpServer server;
    private final ExecutorService executor;
    private final AuthDatabase database;
    private final Gson gson = new Gson();
    private volatile SessionConfig config;
    private final Platform<?> platform;
    private final String upstreamSessionServer;
    private final boolean debug;
    private final String secretKey;
    private final AtomicBoolean stopped = new AtomicBoolean();
    private boolean started;

    public AuthDatabase getDatabase() {
        return database;
    }

    public SessionProxyServer(int port, File dataFolder, Platform<?> platform, SessionConfig config) throws IOException {
        this.platform = platform;
        this.config = config;
        this.debug = platform.isDebug();
        this.secretKey = config.getSecretKey();
        this.upstreamSessionServer = config.getUpstreamSessionServer();

        HttpServer createdServer = null;
        ExecutorService createdExecutor = null;
        AuthDatabase createdDatabase = null;
        try {
            // Bind first so a port conflict cannot leave an unused database connection open.
            createdServer = HttpServer.create(new InetSocketAddress(config.getIpAddress(), port), 0);
            createdExecutor = Executors.newVirtualThreadPerTaskExecutor();
            if (config.isRemoteDatabase()) {
                createdDatabase = new AuthDatabase(
                        config.getDatabaseHost(), config.getDatabasePort(), config.getDatabaseName(),
                        config.getDatabaseUsername(), config.getDatabasePassword(), config.getDatabaseType(), platform
                );
            } else {
                createdDatabase = new AuthDatabase(new File(dataFolder, "authcache.db"), platform);
            }

            if (config.isAuthenticationEnabled()) {
                createdServer.createContext("/auth", this::handleAuthPath);
            } else {
                createdServer.createContext(HAS_JOINED_PATH, exchange -> handleSessionPath(exchange, HAS_JOINED_PATH,
                        exchange.getRequestURI().getRawQuery()));
                createdServer.createContext(JOIN_PATH, exchange -> handleSessionPath(exchange, JOIN_PATH,
                        exchange.getRequestURI().getRawQuery()));
            }
            createdServer.setExecutor(createdExecutor);
        } catch (IOException | RuntimeException | Error failure) {
            try {
                if (createdServer != null) closeServer(createdServer, false);
            } catch (RuntimeException | Error cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            } finally {
                if (createdExecutor != null) createdExecutor.shutdownNow();
                if (createdDatabase != null) createdDatabase.close();
            }
            throw failure;
        }
        this.server = createdServer;
        this.executor = createdExecutor;
        this.database = createdDatabase;

        platform.sendLogMessage("Session proxy server created on port " + server.getAddress().getPort());
        platform.sendLogMessage("Authentication mode: " + (config.isAuthenticationEnabled() ? "ENABLED" : "DISABLED"));
    }

    int boundPort() {
        return server.getAddress().getPort();
    }

    public void reconfigureRuntimeSettings(SessionConfig candidate) {
        // Only fallback/security/cache age are read from this runtime reference. Listener,
        // upstream, database and authentication credentials keep their startup generation.
        config = Objects.requireNonNull(candidate);
    }

    public synchronized void start() {
        if (stopped.get()) throw new IllegalStateException("Session proxy server already stopped");
        try {
            server.start();
            started = true;
        } catch (RuntimeException | Error failure) {
            stop();
            throw failure;
        }
        platform.sendLogMessage("Session proxy server started");
    }

    public synchronized void stop() {
        if (!stopped.compareAndSet(false, true)) return;
        try {
            closeServer(server, started);
        } finally {
            executor.shutdownNow();
            database.close();
        }
        platform.sendLogMessage("Session proxy server stopped");
    }

    private static void closeServer(HttpServer server, boolean started) {
        // The JDK listener stays bound when stop() is called before start(). Starting the
        // bound server first lets stop() close it even during failed construction.
        try {
            if (!started) server.start();
        } finally {
            server.stop(0);
        }
    }

    private boolean verifyAuthToken(String providedToken) {
        return providedToken != null && MessageDigest.isEqual(
                providedToken.getBytes(StandardCharsets.UTF_8), secretKey.getBytes(StandardCharsets.UTF_8));
    }

    private void handleAuthPath(HttpExchange exchange) throws IOException {
        try {
            String rawQuery = exchange.getRequestURI().getRawQuery();
            String path = exchange.getRequestURI().getPath();
            String token = null;
            String sessionQuery = rawQuery;
            Map<String, String> rawParams = parseRawQuery(rawQuery);
            String rawToken = rawParams.get("token");

            if ("/auth".equals(path) && rawToken != null) {
                // Older authlib appends the endpoint and a second '?' to the configured
                // /auth?token=... base URL. Keep accepting those already configured clients.
                int endpointStart = rawToken.lastIndexOf("/session/minecraft/");
                if (endpointStart >= 0) {
                    String endpointAndQuery = rawToken.substring(endpointStart);
                    int queryStart = endpointAndQuery.indexOf('?');
                    path = queryStart < 0 ? endpointAndQuery : endpointAndQuery.substring(0, queryStart);
                    String nestedQuery = queryStart < 0 ? null : endpointAndQuery.substring(queryStart + 1);
                    token = decode(rawToken.substring(0, endpointStart));
                    // The first nested parameter sits inside the legacy token value; the
                    // remaining parameters are ordinary '&' separated query parameters.
                    rawParams.remove("token");
                    Map<String, String> nestedParams = parseRawQuery(nestedQuery);
                    for (Map.Entry<String, String> entry : nestedParams.entrySet()) {
                        if (rawParams.putIfAbsent(entry.getKey(), entry.getValue()) != null) {
                            throw new IllegalArgumentException("Duplicate query parameter");
                        }
                    }
                    sessionQuery = encodeRawQuery(rawParams);
                } else {
                    token = decode(rawToken);
                }
            } else if (path.startsWith("/auth/")) {
                path = path.substring("/auth".length());
                token = rawToken == null ? null : decode(rawToken);
            }

            if (!verifyAuthToken(token)) {
                platform.sendWarningLogMessage("Invalid or missing auth token");
                sendResponse(exchange, 403, "Forbidden: Invalid authentication token");
                return;
            }
            dispatchSessionPath(exchange, path, sessionQuery);
        } catch (IllegalArgumentException e) {
            sendResponse(exchange, 400, "Invalid query parameters");
        }
    }

    private void handleSessionPath(HttpExchange exchange, String expectedPath, String rawQuery) throws IOException {
        if (!expectedPath.equals(exchange.getRequestURI().getPath())) {
            sendResponse(exchange, 404, "Not Found");
            return;
        }
        dispatchSessionPath(exchange, expectedPath, rawQuery);
    }

    private void dispatchSessionPath(HttpExchange exchange, String path, String rawQuery) throws IOException {
        if (HAS_JOINED_PATH.equals(path)) {
            if (!"GET".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "Method Not Allowed");
                return;
            }
            handleHasJoined(exchange, rawQuery);
        } else if (JOIN_PATH.equals(path)) {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "Method Not Allowed");
                return;
            }
            handleJoin(exchange);
        } else {
            sendResponse(exchange, 404, "Not Found");
        }
    }

    private void handleHasJoined(HttpExchange exchange, String rawQuery) throws IOException {
        Map<String, String> params;
        try {
            params = parseQuery(rawQuery);
        } catch (IllegalArgumentException e) {
            sendResponse(exchange, 400, "Invalid query parameters");
            return;
        }
        String username = params.get("username");
        String serverId = params.get("serverId");
        String ip = params.get("ip");
        if (username == null || username.isBlank() || serverId == null || serverId.isBlank()) {
            sendResponse(exchange, 400, "Missing parameters");
            return;
        }
        if (debug) platform.sendLogMessage("Authentication request for user: " + username);

        String cleanQuery = "username=" + encode(username) + "&serverId=" + encode(serverId);
        if (ip != null) cleanQuery += "&ip=" + encode(ip);

        UpstreamResponse upstream;
        try {
            upstream = forwardToUpstream(HAS_JOINED_PATH, cleanQuery, null);
        } catch (MalformedURLException e) {
            platform.sendSevereLogMessage("Invalid upstream session server URL");
            sendResponse(exchange, 502, "Invalid upstream session server URL");
            return;
        } catch (IOException e) {
            useFallbackOrUnavailable(exchange, username, ip);
            return;
        }

        if (upstream.statusCode() == 200) {
            JsonObject profile;
            try {
                profile = gson.fromJson(upstream.body(), JsonObject.class);
                if (profile == null || !profile.has("id") || !profile.has("name")
                        || !profile.get("id").isJsonPrimitive() || !profile.get("id").getAsJsonPrimitive().isString()
                        || !profile.get("name").isJsonPrimitive() || !profile.get("name").getAsJsonPrimitive().isString()
                        || !profile.get("id").getAsString().matches("(?i)[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                        || !username.equalsIgnoreCase(profile.get("name").getAsString())) {
                    throw new IllegalArgumentException("Invalid session profile");
                }
            } catch (RuntimeException e) {
                platform.sendWarningLogMessage("Upstream returned invalid session data for " + username);
                sendResponse(exchange, 502, "Invalid upstream session response");
                return;
            }
            // A failed cache write must never turn a valid online login into fallback.
            database.cacheAuthentication(username, ip, profile);
            sendResponse(exchange, 200, upstream.body());
        } else if (isUnavailable(upstream.statusCode())) {
            useFallbackOrUnavailable(exchange, username, ip);
        } else {
            // An explicit rejection (including 204) is authoritative even for cached players.
            sendResponse(exchange, upstream.statusCode(), upstream.body());
        }
    }

    private void useFallbackOrUnavailable(HttpExchange exchange, String username, String ip) throws IOException {
        platform.sendWarningLogMessage("Upstream session server unavailable for " + username);
        SessionConfig runtimeConfig = config;
        if (runtimeConfig.isFallbackEnabled()) {
            String fallbackResponse = database.getFallbackAuth(username, ip, runtimeConfig.getSecurityLevel(), runtimeConfig.getMaxOfflineHours());
            if (fallbackResponse != null) {
                platform.sendWarningLogMessage("Using FALLBACK authentication for " + username);
                sendResponse(exchange, 200, fallbackResponse);
                return;
            }
        }
        sendResponse(exchange, 503, "Session server unavailable");
    }

    private static boolean isUnavailable(int statusCode) {
        return statusCode == 429 || statusCode >= 500 && statusCode <= 599;
    }

    private void handleJoin(HttpExchange exchange) throws IOException {
        try {
            UpstreamResponse response = forwardToUpstream(JOIN_PATH, null, readInputStream(exchange.getRequestBody()));
            sendResponse(exchange, response.statusCode(), response.body());
        } catch (IOException e) {
            platform.sendWarningLogMessage("Error forwarding join request");
            sendResponse(exchange, 503, "Session server unavailable");
        }
    }

    private UpstreamResponse forwardToUpstream(String endpoint, String query, String body) throws IOException {
        URL url = new URL(upstreamSessionServer + endpoint + (query == null ? "" : "?" + query));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod(body == null ? "GET" : "POST");
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(UPSTREAM_TIMEOUT_MS);
            conn.setReadTimeout(UPSTREAM_TIMEOUT_MS);
            if (body != null) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body.getBytes(StandardCharsets.UTF_8));
                }
            }
            int statusCode = conn.getResponseCode();
            InputStream input = statusCode >= 400 ? conn.getErrorStream() : conn.getInputStream();
            return new UpstreamResponse(statusCode, input == null ? "" : readInputStream(input));
        } finally {
            conn.disconnect();
        }
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        if (statusCode == 200) exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, statusCode == 204 || bytes.length == 0 ? -1 : bytes.length);
        try {
            if (statusCode != 204 && bytes.length > 0) {
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        } finally {
            exchange.close();
        }
    }

    private String readInputStream(InputStream input) throws IOException {
        try (InputStream stream = input) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseRawQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) return params;
        for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            if (pair.length == 2 && params.putIfAbsent(decode(pair[0]), pair[1]) != null) {
                throw new IllegalArgumentException("Duplicate query parameter");
            }
        }
        return params;
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> params = parseRawQuery(query);
        params.replaceAll((key, value) -> decode(value));
        return params;
    }

    private static String encodeRawQuery(Map<String, String> rawParams) {
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : rawParams.entrySet()) {
            if (!query.isEmpty()) query.append('&');
            query.append(encode(entry.getKey())).append('=').append(entry.getValue());
        }
        return query.toString();
    }

    private record UpstreamResponse(int statusCode, String body) { }
}
