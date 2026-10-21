pub mod models;
pub mod parser;

use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use crate::logs::models::{classify_ip_origin, lookup_mac_vendor, LogEntry};
use crate::logs::parser::parse_journalctl_output;
use crate::ufw::cli::run_in_background_thread;

/// Cache mémoire des noms d'hôtes résolus (`IP -> Option<Hostname>`) pour éviter
/// de relancer des requêtes DNS/mDNS à chaque rafraîchissement.
fn hostname_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Détecte l'adresse IP de la passerelle par défaut (Box / Routeur) via `ip route show default`.
fn detect_default_gateway_ip() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "via" {
                if let Some(gw) = tokens.next() {
                    return Some(gw.trim().to_string());
                }
            }
        }
    }
    None
}

/// Lit la table ARP / voisinage du noyau (`ip neigh`) pour associer `IP -> MAC` quand le log n'a pas de champ MAC.
fn read_neighbor_mac_table() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(out) = Command::new("ip")
        .args(["neigh", "show"])
        .env("LC_ALL", "C")
        .output()
    else {
        return map;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(ip) = parts.first() {
            if let Some(pos) = parts.iter().position(|&p| p == "lladdr") {
                if let Some(mac) = parts.get(pos + 1) {
                    map.insert((*ip).to_string(), mac.to_uppercase());
                }
            }
        }
    }
    map
}

/// Résout le nom d'hôte associé à une IP (via `/etc/hosts`, mDNS `.local`, `systemd-resolved` ou DNS inverse)
/// avec un délai maximal court (1 seconde) pour ne jamais ralentir l'interface.
fn resolve_single_ip_hostname(ip: &str) -> Option<String> {
    if let Ok(cache) = hostname_cache().lock() {
        if let Some(cached) = cache.get(ip) {
            return cached.clone();
        }
    }

    // Ignore les adresses link-local IPv6 sans scope ou multicast
    if ip.starts_with("224.")
        || ip.starts_with("239.")
        || ip.starts_with("ff0")
        || ip == "255.255.255.255"
        || ip == "0.0.0.0"
    {
        return None;
    }

    let resolved = Command::new("timeout")
        .args(["0.8s", "getent", "hosts", ip])
        .env("LC_ALL", "C")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let line = String::from_utf8_lossy(&o.stdout);
            let mut parts = line.split_whitespace();
            let _ip_col = parts.next()?;
            let host = parts.next()?.trim();
            if !host.is_empty() && host != ip {
                Some(host.to_string())
            } else {
                None
            }
        });

    if let Ok(mut cache) = hostname_cache().lock() {
        cache.insert(ip.to_string(), resolved.clone());
    }

    resolved
}

/// Enrichit une liste d'entrées de journal avec le nom de la machine source, la passerelle et les infos ARP.
fn enrich_log_entries(entries: &mut [LogEntry]) {
    let gateway_ip = detect_default_gateway_ip();
    let neigh_macs = read_neighbor_mac_table();

    let unique_ips: HashSet<String> = entries.iter().map(|e| e.src.clone()).collect();
    let mut host_map: HashMap<String, Option<String>> = HashMap::with_capacity(unique_ips.len());
    for ip in unique_ips {
        let host = resolve_single_ip_hostname(&ip);
        host_map.insert(ip, host);
    }

    for entry in entries.iter_mut() {
        entry.origin = classify_ip_origin(&entry.src, gateway_ip.as_deref());
        if let Some(Some(hostname)) = host_map.get(&entry.src) {
            entry.src_hostname = Some(hostname.clone());
        }
        if entry.src_mac.is_none() {
            if let Some(mac) = neigh_macs.get(&entry.src) {
                entry.src_mac = Some(mac.clone());
            }
        }
        if entry.src_vendor.is_none() {
            if let Some(mac) = &entry.src_mac {
                entry.src_vendor = lookup_mac_vendor(mac).map(String::from);
            }
        }
    }
}

/// Exécute `journalctl -k -g "UFW BLOCK" -n 150 --output=short-iso` de façon synchrone
/// et enrichit chaque entrée avec le nom d'hôte, le service ciblé et le type d'appareil.
pub fn read_ufw_block_logs_sync() -> Result<Vec<LogEntry>, String> {
    let output = Command::new("journalctl")
        .args(["-k", "-g", "UFW BLOCK", "-n", "150", "--output=short-iso"])
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("Impossible d'exécuter journalctl : {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        let mut entries = parse_journalctl_output(&stdout);
        enrich_log_entries(&mut entries);
        return Ok(entries);
    }

    // Lorsque `-g "UFW BLOCK"` ne trouve aucune entrée dans le journal noyau,
    // `journalctl` renvoie le code de sortie 1 avec "-- No entries --".
    let combined = format!("{stdout}\n{stderr}").to_lowercase();
    if output.status.code() == Some(1)
        && (stdout.trim().is_empty()
            || combined.contains("no entries")
            || stderr.trim().is_empty())
    {
        return Ok(Vec::new());
    }

    Err(format!(
        "Erreur lors de la lecture de journalctl : {}",
        stderr.trim()
    ))
}

/// Charge les journaux de blocage UFW dans un thread d'arrière-plan et renvoie le résultat sur le thread GTK.
pub fn fetch_logs_async<C>(callback: C)
where
    C: FnOnce(Result<Vec<LogEntry>, String>) + 'static,
{
    run_in_background_thread(read_ufw_block_logs_sync, callback);
}
