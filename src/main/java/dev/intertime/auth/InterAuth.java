package dev.intertime.auth;

import io.papermc.paper.event.player.AsyncChatEvent;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.*;
import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class InterAuth extends JavaPlugin implements Listener, CommandExecutor {

    private static final int ITERATIONS = 120_000;
    private static final int MIN_LEN = 6;
    private static final int MAX_ATTEMPTS = 5;
    private static final int TIMEOUT_SECONDS = 60;

    private final Set<UUID> logged = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private File dataFile;
    private YamlConfiguration data;

    @Override
    public void onEnable() {
        if (!getDataFolder().exists()) getDataFolder().mkdirs();
        dataFile = new File(getDataFolder(), "data.yml");
        data = YamlConfiguration.loadConfiguration(dataFile);
        Bukkit.getPluginManager().registerEvents(this, this);
        for (String c : List.of("reg", "l", "cp", "authset")) {
            Objects.requireNonNull(getCommand(c)).setExecutor(this);
        }
    }

    // ---------- storage / hashing ----------

    private String key(Player p) {
        return p.getName().toLowerCase(Locale.ROOT);
    }

    private boolean isRegistered(Player p) {
        return data.contains("users." + key(p));
    }

    private String hash(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);
        byte[] h = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(h);
    }

    private void store(Player p, String password) throws Exception {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        data.set("users." + key(p) + ".salt", Base64.getEncoder().encodeToString(salt));
        data.set("users." + key(p) + ".hash", hash(password, salt));
        save();
    }

    private boolean check(Player p, String password) {
        try {
            String s = data.getString("users." + key(p) + ".salt");
            String h = data.getString("users." + key(p) + ".hash");
            if (s == null || h == null) return false;
            String test = hash(password, Base64.getDecoder().decode(s));
            return MessageDigest.isEqual(test.getBytes(), h.getBytes());
        } catch (Exception e) {
            return false;
        }
    }

    private synchronized void save() {
        try {
            data.save(dataFile);
        } catch (IOException e) {
            getLogger().severe("Cannot save data.yml: " + e.getMessage());
        }
    }

    // ---------- helpers ----------

    private boolean authed(Player p) {
        return logged.contains(p.getUniqueId());
    }

    private void msg(Player p, String text, NamedTextColor color) {
        p.sendMessage(Component.text(text, color));
    }

    private void prompt(Player p) {
        if (isRegistered(p)) msg(p, "Увійдіть: /l <пароль>", NamedTextColor.YELLOW);
        else msg(p, "Зареєструйтесь: /reg <пароль> <пароль>", NamedTextColor.YELLOW);
    }

    private void toSpawn(Player p) {
        Location spawn = getConfig().getLocation("spawn");
        if (spawn == null) spawn = Bukkit.getWorlds().get(0).getSpawnLocation();
        p.teleport(spawn);
    }

    // ---------- commands ----------

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("Only for players.");
            return true;
        }
        String name = cmd.getName().toLowerCase(Locale.ROOT);

        switch (name) {
            case "reg" -> {
                if (authed(p) || isRegistered(p)) {
                    msg(p, "Ви вже зареєстровані. Використайте /l <пароль>.", NamedTextColor.RED);
                    return true;
                }
                if (args.length != 2) {
                    msg(p, "Використання: /reg <пароль> <пароль>", NamedTextColor.RED);
                    return true;
                }
                if (!args[0].equals(args[1])) {
                    msg(p, "Паролі не збігаються.", NamedTextColor.RED);
                    return true;
                }
                if (args[0].length() < MIN_LEN) {
                    msg(p, "Пароль мінімум " + MIN_LEN + " символів.", NamedTextColor.RED);
                    return true;
                }
                try {
                    store(p, args[0]);
                } catch (Exception e) {
                    msg(p, "Помилка реєстрації.", NamedTextColor.RED);
                    return true;
                }
                logged.add(p.getUniqueId());
                msg(p, "Реєстрація успішна!", NamedTextColor.GREEN);
                toSpawn(p);
            }
            case "l" -> {
                if (authed(p)) {
                    msg(p, "Ви вже увійшли.", NamedTextColor.RED);
                    return true;
                }
                if (!isRegistered(p)) {
                    msg(p, "Спочатку /reg <пароль> <пароль>", NamedTextColor.RED);
                    return true;
                }
                if (args.length != 1) {
                    msg(p, "Використання: /l <пароль>", NamedTextColor.RED);
                    return true;
                }
                if (check(p, args[0])) {
                    attempts.remove(p.getUniqueId());
                    logged.add(p.getUniqueId());
                    msg(p, "Ви успішно увійшли!", NamedTextColor.GREEN);
                    toSpawn(p);
                } else {
                    int n = attempts.merge(p.getUniqueId(), 1, Integer::sum);
                    if (n >= MAX_ATTEMPTS) {
                        p.kick(Component.text("Забагато невдалих спроб.", NamedTextColor.RED));
                    } else {
                        msg(p, "Невірний пароль (" + n + "/" + MAX_ATTEMPTS + ")", NamedTextColor.RED);
                    }
                }
            }
            case "cp" -> {
                if (!authed(p)) {
                    msg(p, "Спочатку увійдіть.", NamedTextColor.RED);
                    return true;
                }
                if (args.length != 2) {
                    msg(p, "Використання: /cp <старий> <новий>", NamedTextColor.RED);
                    return true;
                }
                if (!check(p, args[0])) {
                    msg(p, "Старий пароль невірний.", NamedTextColor.RED);
                    return true;
                }
                if (args[1].length() < MIN_LEN) {
                    msg(p, "Пароль мінімум " + MIN_LEN + " символів.", NamedTextColor.RED);
                    return true;
                }
                try {
                    store(p, args[1]);
                    msg(p, "Пароль змінено.", NamedTextColor.GREEN);
                } catch (Exception e) {
                    msg(p, "Помилка.", NamedTextColor.RED);
                }
            }
            case "authset" -> {
                if (!p.hasPermission("interauth.admin")) {
                    msg(p, "Немає прав.", NamedTextColor.RED);
                    return true;
                }
                if (args.length != 1 || !(args[0].equalsIgnoreCase("auth") || args[0].equalsIgnoreCase("spawn"))) {
                    msg(p, "Використання: /authset <auth|spawn>", NamedTextColor.RED);
                    return true;
                }
                String where = args[0].toLowerCase(Locale.ROOT);
                getConfig().set(where, p.getLocation());
                saveConfig();
                msg(p, where.equals("auth")
                        ? "Точку реєстрації/входу збережено."
                        : "Спавн після входу збережено.", NamedTextColor.GREEN);
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    // ---------- join / quit ----------

    @EventHandler
    public void onJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();
        logged.remove(p.getUniqueId());
        attempts.remove(p.getUniqueId());
        Location authLoc = getConfig().getLocation("auth");
        if (authLoc != null) p.teleport(authLoc);
        prompt(p);
        Bukkit.getScheduler().runTaskLater(this, () -> {
            if (p.isOnline() && !authed(p)) {
                p.kick(Component.text("Час на авторизацію вичерпано.", NamedTextColor.RED));
            }
        }, TIMEOUT_SECONDS * 20L);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        logged.remove(e.getPlayer().getUniqueId());
        attempts.remove(e.getPlayer().getUniqueId());
    }

    // ---------- restrictions for unauthenticated players ----------

    @EventHandler(priority = EventPriority.LOWEST)
    public void onMove(PlayerMoveEvent e) {
        if (authed(e.getPlayer())) return;
        if (e.getFrom().getX() != e.getTo().getX()
                || e.getFrom().getY() != e.getTo().getY()
                || e.getFrom().getZ() != e.getTo().getZ()) {
            e.setTo(e.getFrom());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommandPre(PlayerCommandPreprocessEvent e) {
        if (authed(e.getPlayer())) return;
        String c = e.getMessage().toLowerCase(Locale.ROOT).split(" ")[0].replace("/interauth:", "/");
        if (!(c.equals("/l") || c.equals("/reg"))) {
            e.setCancelled(true);
            prompt(e.getPlayer());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChat(AsyncChatEvent e) {
        if (!authed(e.getPlayer())) {
            e.setCancelled(true);
            prompt(e.getPlayer());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onBreak(BlockBreakEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlace(BlockPlaceEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteract(PlayerInteractEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteractEntity(PlayerInteractEntityEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onDrop(PlayerDropItemEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPickup(org.bukkit.event.entity.EntityPickupItemEvent e) {
        if (e.getEntity() instanceof Player p && !authed(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInvClick(InventoryClickEvent e) {
        if (e.getWhoClicked() instanceof Player p && !authed(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInvOpen(InventoryOpenEvent e) {
        if (e.getPlayer() instanceof Player p && !authed(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onDamage(EntityDamageEvent e) {
        if (e.getEntity() instanceof Player p && !authed(p)) e.setCancelled(true);
    }
}
