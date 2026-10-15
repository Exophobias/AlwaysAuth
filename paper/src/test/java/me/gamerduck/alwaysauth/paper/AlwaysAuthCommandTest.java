package me.gamerduck.alwaysauth.paper;

import io.papermc.paper.command.brigadier.CommandSourceStack;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.bukkit.command.CommandSender;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AlwaysAuthCommandTest {
    private CommandSourceStack source(boolean granted, List<String> messages) {
        CommandSender sender = (CommandSender) Proxy.newProxyInstance(CommandSender.class.getClassLoader(), new Class<?>[]{CommandSender.class}, (p, m, args) -> {
            if (m.getName().equals("hasPermission")) return granted;
            if (m.getName().equals("sendMessage") && args[0] instanceof String text) { messages.add(text); return null; }
            if (m.getReturnType() == boolean.class) return false;
            return null;
        });
        return (CommandSourceStack) Proxy.newProxyInstance(CommandSourceStack.class.getClassLoader(),new Class<?>[]{CommandSourceStack.class},
                (p,m,args) -> m.getName().equals("getSender") ? sender : null);
    }
    @Test void noGrantCannotSeeHelpSuggestionsOrDispatchActions() {
        AtomicInteger actions = new AtomicInteger(); List<String> messages = new ArrayList<>();
        AlwaysAuthCommand command = new AlwaysAuthCommand((s,a) -> actions.incrementAndGet());
        CommandSourceStack source = source(false,messages);
        assertFalse(command.canUse(source.getSender()));
        for (String[] args : List.of(new String[0],new String[]{"help","staff"},new String[]{"toggle"},new String[]{"security","basic"},new String[]{"cleanup"})) command.execute(source,args);
        assertEquals(0,actions.get());assertEquals(5,messages.size());
        assertTrue(messages.stream().allMatch(m -> m.equals("§cYou do not have permission to do that.")));
        assertTrue(command.suggest(source,new String[]{""}).isEmpty());
        assertTrue(command.suggest(source,new String[]{"help",""}).isEmpty());
    }
    @Test void staffAndConsoleHelpClampWithoutActions() {
        AtomicInteger actions = new AtomicInteger(); List<String> messages = new ArrayList<>();
        AlwaysAuthCommand command = new AlwaysAuthCommand((s,a) -> actions.incrementAndGet());
        CommandSourceStack source=source(true,messages);
        assertTrue(command.canUse(source.getSender()));
        for (String[] args : List.of(new String[0],new String[]{"help"},new String[]{"help","0"},new String[]{"help","99"},new String[]{"help","banana"},new String[]{"help","staff","99"})) {
            messages.clear();command.execute(source,args);assertEquals(8,messages.size());
            assertTrue(messages.get(0).contains("AlwaysAuth Staff"));
            assertTrue(messages.get(7).startsWith("§8---"));
        }
        assertEquals(0,actions.get());
        assertEquals(List.of("basic","medium"),new ArrayList<>(command.suggest(source,new String[]{"security",""})));
        command.execute(source,new String[]{"status"});assertEquals(1,actions.get());
    }
    @Test void unknownCommandShowsErrorAndHelpWhileMissingSecurityNeverDispatches() {
        AtomicInteger actions=new AtomicInteger();List<String> messages=new ArrayList<>();
        AlwaysAuthCommand command=new AlwaysAuthCommand((s,a)->actions.incrementAndGet());
        command.execute(source(true,messages),new String[]{"unknown"});assertEquals(9,messages.size());
        assertEquals("§cUnknown command.",messages.get(0));
        command.execute(source(true,messages),new String[]{"security"});assertEquals(0,actions.get());
    }
}
