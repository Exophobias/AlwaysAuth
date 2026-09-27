package me.gamerduck.alwaysauth.paper;

import com.mojang.authlib.services.MinecraftServicesDiscoveryService;
import com.mojang.authlib.services.MinecraftServicesSessionService;
import com.mojang.authlib.services.ServicesKeySet;
import com.mojang.authlib.services.response.discovery.*;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

class PaperAuthenticationHookTest {
    private static final String PROFILE = "{\"id\":\"123456781234123412341234567890ab\",\"name\":\"Example\",\"properties\":[]}";

    @Test
    void realAuthlibRoutesVerificationWhileOriginalDiscoveryIsOfflineAndRestoresOnClose() throws Exception {
        AtomicReference<String> query = new AtomicReference<>();
        HttpServer proxy = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        proxy.createContext("/auth/session/minecraft/hasJoined", exchange -> {
            query.set(exchange.getRequestURI().getRawQuery());
            byte[] bytes = PROFILE.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        proxy.start();
        MinecraftServicesDiscoveryService original = discovery(DiscoveryResponse::offline);
        TestSession session = new TestSession(original);
        Object client = sessionField(session, "client");
        Object keys = sessionField(session, "servicesKeySet");
        Object cache = sessionField(session, "insecureProfiles");
        String endpoint = PaperAuthenticationHook.verificationEndpoint("127.0.0.1", proxy.getAddress().getPort(),
                true, "a+b&c/session=d");
        try {
            try (PaperAuthenticationHook ignored = PaperAuthenticationHook.install(session, endpoint)) {
                var profile = session.hasJoinedServer("Example", "server hash", InetAddress.getByName("192.0.2.12"));
                assertNotNull(profile);
                assertEquals("Example", profile.profile().name());
                assertTrue(query.get().contains("token=a%2Bb%26c%2Fsession%3Dd"), query.get());
                assertTrue(query.get().contains("username=Example"), query.get());
                assertTrue(query.get().contains("ip=192.0.2.12"), query.get());
                assertSame(client, sessionField(session, "client"));
                assertSame(keys, sessionField(session, "servicesKeySet"));
                assertSame(cache, sessionField(session, "insecureProfiles"));
            }
            assertSame(original, sessionField(session, "discoveryService"));
        } finally {
            proxy.stop(0);
        }
    }

    @Test
    void preservesOtherEndpointsAndFollowsDiscoveryRefresh() throws Exception {
        Endpoint join = new Endpoint("https://session.example/join");
        Endpoint profiles = new Endpoint("https://session.example/profile/{profileId}");
        Endpoints textures = new Endpoints(Map.of("getTexture", new Endpoint("https://textures.example/{textureId}",
                List.of("https://textures.example/{textureId}"))));
        Discovery initial = new Discovery("minecraft", Endpoints.empty(), new Endpoints(Map.of(
                "verify", new Endpoint("https://session.example/verify"), "join", join, "getProfileById", profiles)),
                Endpoints.empty(), textures, Endpoints.empty());
        AtomicReference<DiscoveryResponse> response = new AtomicReference<>(new DiscoveryResponse("prod", "minecraft", initial));
        MinecraftServicesDiscoveryService original = discovery(response::get);
        TestSession session = new TestSession(original);
        try (PaperAuthenticationHook ignored = PaperAuthenticationHook.install(session, "http://127.0.0.1/verify")) {
            MinecraftServicesDiscoveryService installed = (MinecraftServicesDiscoveryService) sessionField(session, "discoveryService");
            assertEquals("http://127.0.0.1/verify", installed.getUrl(Service.SESSION, "verify"));
            assertEquals(join.uri(), installed.getUrl(Service.SESSION, "join"));
            assertEquals(profiles.uri(), installed.getUrl(Service.SESSION, "getProfileById"));
            assertEquals(original.getValidUris(Service.PROFILES, "getTexture"), installed.getValidUris(Service.PROFILES, "getTexture"));
            assertTrue(installed.isAllowedTextureDomain("https://textures.example/abc"));
            assertFalse(installed.isAllowedTextureDomain("https://untrusted.example/abc"));
            Discovery refreshed = new Discovery("minecraft", initial.authentication(), new Endpoints(Map.of(
                    "verify", new Endpoint("https://new.example/verify"), "join", new Endpoint("https://new.example/join"))),
                    initial.player(), initial.profiles(), initial.telemetry());
            response.set(new DiscoveryResponse("prod", "minecraft", refreshed));
            assertEquals("https://new.example/join", installed.getUrl(Service.SESSION, "join"));
            assertEquals("http://127.0.0.1/verify", installed.getUrl(Service.SESSION, "verify"));
        }
    }

    @Test
    void closeDoesNotOverwriteAnotherPluginsReplacement() throws Exception {
        TestSession session = new TestSession(discovery(DiscoveryResponse::offline));
        PaperAuthenticationHook hook = PaperAuthenticationHook.install(session, "http://127.0.0.1/verify");
        MinecraftServicesDiscoveryService later = discovery(DiscoveryResponse::offline);
        Field field = MinecraftServicesSessionService.class.getDeclaredField("discoveryService");
        field.setAccessible(true);
        field.set(session, later);
        hook.close();
        assertSame(later, field.get(session));
    }

    @Test
    void disabledTokenAuthUsesTheUnauthenticatedProxyRoute() {
        assertEquals("http://127.0.0.1:8765/session/minecraft/hasJoined",
                PaperAuthenticationHook.verificationEndpoint("127.0.0.1", 8765, false, "unused"));
        URI remote = URI.create(PaperAuthenticationHook.verificationEndpoint("https://auth.example/base/", 8765, true, "secret"));
        assertEquals("/base/auth/session/minecraft/hasJoined", remote.getPath());
        assertEquals("token=secret", remote.getRawQuery());
    }

    private static MinecraftServicesDiscoveryService discovery(Supplier<DiscoveryResponse> supplier) throws Exception {
        var constructor = MinecraftServicesDiscoveryService.class.getDeclaredConstructor(Proxy.class, boolean.class, Supplier.class);
        constructor.setAccessible(true);
        return constructor.newInstance(Proxy.NO_PROXY, false, supplier);
    }

    private static Object sessionField(Object session, String name) throws Exception {
        Field field = MinecraftServicesSessionService.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(session);
    }

    private static final class TestSession extends MinecraftServicesSessionService {
        private TestSession(MinecraftServicesDiscoveryService discovery) {
            super(ServicesKeySet.EMPTY, Proxy.NO_PROXY, discovery);
        }
    }
}
