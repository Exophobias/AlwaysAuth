package me.gamerduck.alwaysauth.paper;

import com.mojang.authlib.services.MinecraftServicesDiscoveryService;
import com.mojang.authlib.services.MinecraftServicesSessionService;
import com.mojang.authlib.services.response.discovery.Discovery;
import com.mojang.authlib.services.response.discovery.DiscoveryResponse;
import com.mojang.authlib.services.response.discovery.Endpoint;
import com.mojang.authlib.services.response.discovery.Endpoints;
import me.gamerduck.alwaysauth.api.config.SessionConfig;
import org.bukkit.Bukkit;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Proxy;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.function.Supplier;

/** Redirects only the existing server session's login verification on authlib 10. */
final class PaperAuthenticationHook implements AutoCloseable {
    private final Object sessionService;
    private final Field discoveryField;
    private final MinecraftServicesDiscoveryService original;
    private final MinecraftServicesDiscoveryService replacement;
    private Object runtimeServer;
    private Method proxySetter;
    private boolean previousProxyCheck;

    private PaperAuthenticationHook(Object sessionService, Field discoveryField,
                                    MinecraftServicesDiscoveryService original,
                                    MinecraftServicesDiscoveryService replacement) {
        this.sessionService = sessionService;
        this.discoveryField = discoveryField;
        this.original = original;
        this.replacement = replacement;
    }

    static PaperAuthenticationHook install(SessionConfig config) throws ReflectiveOperationException {
        Object craftServer = Bukkit.getServer();
        Object server = craftServer.getClass().getMethod("getServer").invoke(craftServer);
        Field servicesField = Class.forName("net.minecraft.server.MinecraftServer").getDeclaredField("services");
        servicesField.setAccessible(true);
        Object services = servicesField.get(server);
        Object session = services.getClass().getMethod("sessionService").invoke(services);
        PaperAuthenticationHook hook = install(session, verificationEndpoint(config.getIpAddress(), config.getPort(),
                config.isAuthenticationEnabled(), config.getSecretKey()));
        try {
            Method getter = server.getClass().getMethod("getPreventProxyConnections");
            hook.proxySetter = server.getClass().getMethod("setPreventProxyConnections", boolean.class);
            hook.previousProxyCheck = (boolean) getter.invoke(server);
            hook.runtimeServer = server;
            hook.proxySetter.invoke(server, true);
            if (!(boolean) getter.invoke(server)) {
                throw new IllegalStateException("Player IP forwarding could not be enabled");
            }
            return hook;
        } catch (ReflectiveOperationException | RuntimeException failure) {
            try { hook.close(); } catch (ReflectiveOperationException restoreFailure) { failure.addSuppressed(restoreFailure); }
            throw failure;
        }
    }

    static String verificationEndpoint(String host, int port, boolean authenticated, String secret) {
        String base = host.startsWith("http://") || host.startsWith("https://")
                ? host : "http://" + host + ":" + port;
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        String endpoint = base + (authenticated ? "/auth" : "") + "/session/minecraft/hasJoined";
        if (authenticated) endpoint += "?token=" + URLEncoder.encode(secret, StandardCharsets.UTF_8);
        URI uri = URI.create(endpoint);
        if (uri.getHost() == null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Invalid session server address");
        }
        return endpoint;
    }

    @SuppressWarnings("unchecked")
    static PaperAuthenticationHook install(Object sessionService, String endpoint) throws ReflectiveOperationException {
        if (!(sessionService instanceof MinecraftServicesSessionService)) {
            throw new IllegalStateException("Unsupported session service; AlwaysAuth requires Paper 26.3/authlib 10");
        }
        Field discoveryField = MinecraftServicesSessionService.class.getDeclaredField("discoveryService");
        discoveryField.setAccessible(true);
        MinecraftServicesDiscoveryService original = (MinecraftServicesDiscoveryService) discoveryField.get(sessionService);

        Field supplierField = MinecraftServicesDiscoveryService.class.getDeclaredField("discoverySupplier");
        supplierField.setAccessible(true);
        Supplier<DiscoveryResponse> originalSupplier = (Supplier<DiscoveryResponse>) supplierField.get(original);
        Supplier<DiscoveryResponse> supplier = () -> withVerification(originalSupplier.get(), endpoint);

        Field keysField = MinecraftServicesDiscoveryService.class.getDeclaredField("servicesKeySetEnabled");
        keysField.setAccessible(true);
        Constructor<MinecraftServicesDiscoveryService> constructor = MinecraftServicesDiscoveryService.class
                .getDeclaredConstructor(Proxy.class, boolean.class, Supplier.class);
        constructor.setAccessible(true);
        MinecraftServicesDiscoveryService replacement = constructor.newInstance(original.getProxy(),
                keysField.getBoolean(original), supplier);
        discoveryField.set(sessionService, replacement);
        if (discoveryField.get(sessionService) != replacement) {
            throw new IllegalStateException("Authentication hook installation could not be verified");
        }
        return new PaperAuthenticationHook(sessionService, discoveryField, original, replacement);
    }

    static DiscoveryResponse withVerification(DiscoveryResponse response, String endpoint) {
        Discovery discovery = response.discovery();
        var sessions = new HashMap<>(discovery.session().endpoints());
        sessions.put("verify", new Endpoint(endpoint));
        return new DiscoveryResponse(response.isOffline() ? "alwaysauth" : response.environment(), response.product(),
                new Discovery(discovery.product(), discovery.authentication(), new Endpoints(sessions),
                        discovery.player(), discovery.profiles(), discovery.telemetry()));
    }

    @Override
    public void close() throws ReflectiveOperationException {
        // A later plugin may have installed its own hook; never overwrite its discovery object.
        if (discoveryField.get(sessionService) == replacement) {
            discoveryField.set(sessionService, original);
            if (discoveryField.get(sessionService) != original) {
                throw new IllegalStateException("Authentication hook restoration could not be verified");
            }
            if (runtimeServer != null) {
                proxySetter.invoke(runtimeServer, previousProxyCheck);
                runtimeServer = null;
            }
        }
    }
}
