package me.gamerduck.alwaysauth.paper;

import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.BasicCommand;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.function.BiConsumer;

/** All management actions use the same real permission as their help and suggestions. */
public final class AlwaysAuthCommand implements BasicCommand {
    private static final List<String> ACTIONS = List.of("status", "stats", "toggle", "security", "cleanup", "reload");
    private final BiConsumer<CommandSourceStack, String[]> action;
    public AlwaysAuthCommand(BiConsumer<CommandSourceStack, String[]> action) { this.action = action; }

    @Override public void execute(CommandSourceStack source, String[] args) {
        if (!source.getSender().hasPermission("alwaysauth.admin")) {
            source.getSender().sendMessage("§cYou do not have permission to do that.");
            return;
        }
        if (args.length == 0 || args[0].equalsIgnoreCase("help")) { help(source); return; }
        if (!ACTIONS.contains(args[0].toLowerCase(Locale.ROOT))) {
            source.getSender().sendMessage("§cUnknown command."); help(source); return;
        }
        if (args[0].equalsIgnoreCase("security") && args.length < 2) {
            source.getSender().sendMessage("§cUsage: /alwaysauth security <basic|medium>"); return;
        }
        action.accept(source, args);
    }

    private void help(CommandSourceStack source) {
        source.getSender().sendMessage("§8---------- §aAlwaysAuth Staff§8 ----------");
        List<String> descriptions = List.of("show the current status", "show cache statistics", "toggle session fallback",
                "set the security level", "remove old cache entries", "reload configuration");
        for (int i = 0; i < ACTIONS.size(); i++)
            source.getSender().sendMessage("§a/alwaysauth " + ACTIONS.get(i)
                    + (ACTIONS.get(i).equals("security") ? " <basic|medium>" : "") + "§8 - §7" + descriptions.get(i));
        source.getSender().sendMessage("§8----------------------------------------");
    }

    @Override public Collection<String> suggest(CommandSourceStack source, String[] args) {
        if (!source.getSender().hasPermission("alwaysauth.admin")) return List.of();
        List<String> choices = args.length == 1 ? List.of("help", "status", "stats", "toggle", "security", "cleanup", "reload")
                : args.length == 2 && args[0].equalsIgnoreCase("help") ? List.of("staff", "1")
                : args.length == 2 && args[0].equalsIgnoreCase("security") ? List.of("basic", "medium") : List.of();
        String prefix = args.length == 0 ? "" : args[args.length - 1].toLowerCase(Locale.ROOT);
        return choices.stream().filter(choice -> choice.startsWith(prefix)).toList();
    }
}
