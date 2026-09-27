package me.gamerduck.alwaysauth.paper;

import io.papermc.paper.command.brigadier.CommandSourceStack;
import me.gamerduck.alwaysauth.Platform;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.List;
import java.util.logging.Logger;

public class PaperPlatform extends Platform<CommandSourceStack> implements Listener {

    private static final Logger LOGGER = Logger.getLogger("AlwaysAuth");
    private final PaperAuthenticationHook authenticationHook;

    public PaperPlatform(JavaPlugin bootstrap) {
        super(bootstrap.getDataFolder().toPath());

        PaperAuthenticationHook installedHook = null;
        try {
            installedHook = PaperAuthenticationHook.install(config());
            sendLogMessage("Paper 26.3 login verification hook installed (online mode preserved)");
            bootstrap.registerCommand("alwaysauth", List.of("aa", "alwaysa"), (commandSourceStack, args) -> {
                if (commandSourceStack.getSender().hasPermission("alwaysauth.admin")) {
                    if (args.length == 0) {
                        cmdHelp(commandSourceStack);
                        return;
                    }
                    switch (args[0].toLowerCase()) {
                        case "status" -> cmdStatus(commandSourceStack);
                        case "stats" -> cmdStats(commandSourceStack);
                        case "toggle" -> cmdToggle(commandSourceStack);
                        case "security" -> {
                            if (args.length < 2) {
                                sendMessage(commandSourceStack, "§cUsage: /alwaysauth security <basic|medium>");
                                return;
                            }
                            String level = args[1].toLowerCase();
                            cmdSecurity(commandSourceStack, level);
                        }
                        case "cleanup" -> cmdCleanup(commandSourceStack);
                        case "reload" -> cmdReload(commandSourceStack);
                        default -> cmdDefault(commandSourceStack);
                    }

                    return;
                } else {
                    sendMessage(commandSourceStack, "§cNo permissions");
                }
            });
        } catch (Exception | LinkageError e) {
            if (installedHook != null) {
                try { installedHook.close(); } catch (Exception restoreFailure) { e.addSuppressed(restoreFailure); }
            }
            super.onDisable();
            throw new IllegalStateException("Could not initialize Paper 26.3 authentication", e);
        }
        authenticationHook = installedHook;

    }


    @Override
    public void sendMessage(CommandSourceStack commandSender, String msg) {
        commandSender.getSender().sendMessage(msg);
    }

    @Override
    public boolean hasPermission(CommandSourceStack commandSender, String permission) {
        return commandSender.getSender().hasPermission(permission);
    }

    @Override
    public void onDisable() {
        try {
            authenticationHook.close();
        } catch (Exception e) {
            sendSevereLogMessage("Could not restore the original authentication discovery service");
            throw new IllegalStateException("Authentication hook restoration failed", e);
        } finally {
            super.onDisable();
        }
    }

    @Override
    public void sendLogMessage(String msg) {
        LOGGER.info(msg.replaceAll("§.", ""));
    }

    @Override
    public void sendSevereLogMessage(String msg) {
        LOGGER.severe(msg.replaceAll("§.", ""));
    }

    @Override
    public void sendWarningLogMessage(String msg) {
        LOGGER.warning(msg.replaceAll("§.", ""));
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        if (event.getPlayer().hasPermission("alwaysauth.admin")) {
            getUpdateMessage().ifPresent(updateMessage -> event.getPlayer().sendMessage(updateMessage));
        }
    }

}
