use std::sync::OnceLock;

use regex::Regex;

use crate::logs::models::{classify_ip_origin, lookup_mac_vendor, LogEntry};

fn iso_ts_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+")
            .expect("Regex timestamp ISO valide")
    })
}

fn src_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bSRC=([^\s]+)").expect("Regex SRC valide"))
}

fn dst_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bDST=([^\s]+)").expect("Regex DST valide"))
}

fn proto_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bPROTO=([^\s]+)").expect("Regex PROTO valide"))
}

fn spt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bSPT=(\d+)").expect("Regex SPT valide"))
}

fn dpt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bDPT=(\d+)").expect("Regex DPT valide"))
}

fn in_iface_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bIN=([^\s]*)").expect("Regex IN valide"))
}

fn mac_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bMAC=([0-9a-fA-F:]+)").expect("Regex MAC valide"))
}

/// Extrait l'adresse MAC source (6 octets du milieu) depuis le champ `MAC=` de Netfilter
/// qui contient : `DST_MAC (6 octets) : SRC_MAC (6 octets) : ETHERTYPE (2 octets)`.
pub fn extract_source_mac(raw_mac_field: &str) -> Option<String> {
    let parts: Vec<&str> = raw_mac_field.split(':').collect();
    if parts.len() >= 12 {
        Some(parts[6..12].join(":").to_uppercase())
    } else if parts.len() == 6 {
        Some(parts.join(":").to_uppercase())
    } else {
        None
    }
}

/// Normalise le nom du protocole (ex. `PROTO=2` dans le noyau Linux correspond à `IGMP`).
pub fn normalize_protocol(raw_proto: &str) -> String {
    match raw_proto.trim().to_uppercase().as_str() {
        "2" => String::from("IGMP"),
        "58" | "ICMPV6" => String::from("ICMPv6"),
        "47" => String::from("GRE"),
        "50" => String::from("ESP"),
        other => other.to_string(),
    }
}

/// Analyse une ligne issue de `journalctl -k -g "UFW BLOCK" -n 150 --output=short-iso`.
pub fn parse_ufw_log_line(line: &str) -> Option<LogEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() || !trimmed.contains("UFW BLOCK") {
        return None;
    }

    let (raw_timestamp, timestamp) = if let Some(caps) = iso_ts_regex().captures(trimmed) {
        let raw = caps[0].trim().to_string();
        let formatted = format!("{} {}", &caps[1], &caps[2]);
        (raw, formatted)
    } else {
        let first_tok = trimmed.split_whitespace().next().unwrap_or("Inconnu");
        (first_tok.to_string(), first_tok.to_string())
    };

    let src = src_regex()
        .captures(trimmed)
        .map(|c| c[1].to_string())?;
    let dst = dst_regex()
        .captures(trimmed)
        .map(|c| c[1].to_string())?;
    let proto = proto_regex()
        .captures(trimmed)
        .map(|c| normalize_protocol(&c[1]))
        .unwrap_or_else(|| String::from("AUTRE"));

    let spt = spt_regex().captures(trimmed).map(|c| c[1].to_string());
    let dpt = dpt_regex().captures(trimmed).map(|c| c[1].to_string());
    let interface_in = in_iface_regex()
        .captures(trimmed)
        .map(|c| c[1].to_string())
        .filter(|s| !s.is_empty());

    let src_mac = mac_regex()
        .captures(trimmed)
        .and_then(|c| extract_source_mac(&c[1]));
    let src_vendor = src_mac
        .as_deref()
        .and_then(lookup_mac_vendor)
        .map(String::from);

    let origin = classify_ip_origin(&src, None);

    Some(LogEntry {
        timestamp,
        raw_timestamp,
        src,
        src_hostname: None,
        src_mac,
        src_vendor,
        origin,
        dst,
        proto,
        spt,
        dpt,
        interface_in,
    })
}

/// Analyse la sortie complète de `journalctl` et retourne les événements du plus récent au plus ancien.
pub fn parse_journalctl_output(output: &str) -> Vec<LogEntry> {
    let mut entries: Vec<LogEntry> = output.lines().filter_map(parse_ufw_log_line).collect();
    entries.reverse();
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_ipv4_log_line() {
        let line = "2026-10-21T13:45:12+0200 noos-pc kernel: [UFW BLOCK] IN=wlan0 OUT= MAC=00:11:22:33:44:55:b8:27:eb:aa:bb:cc:08:00 SRC=192.168.1.42 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0";
        let entry = parse_ufw_log_line(line).expect("Doit parser une ligne TCP IPv4");
        assert_eq!(entry.timestamp, "2026-10-21 13:45:12");
        assert_eq!(entry.src, "192.168.1.42");
        assert_eq!(entry.dst, "192.168.1.100");
        assert_eq!(entry.proto, "TCP");
        assert_eq!(entry.spt.as_deref(), Some("51234"));
        assert_eq!(entry.dpt.as_deref(), Some("22"));
        assert_eq!(entry.interface_in.as_deref(), Some("wlan0"));
        assert_eq!(entry.src_mac.as_deref(), Some("B8:27:EB:AA:BB:CC"));
        assert_eq!(entry.src_vendor.as_deref(), Some("Raspberry Pi"));
        assert_eq!(
            entry.display_main_line(),
            "Appareil Raspberry Pi (192.168.1.42) → Port 22 (SSH)"
        );
    }

    #[test]
    fn test_parse_udp_ipv6_log_line() {
        let line = "2026-10-21T13:46:05+02:00 archlinux kernel: [UFW BLOCK] IN=enp3s0 OUT= SRC=fe80::211:22ff:fe33:4455 DST=ff02::fb LEN=72 PROTO=UDP SPT=5353 DPT=5353 LEN=32";
        let entry = parse_ufw_log_line(line).expect("Doit parser une ligne UDP IPv6");
        assert_eq!(entry.timestamp, "2026-10-21 13:46:05");
        assert_eq!(entry.src, "fe80::211:22ff:fe33:4455");
        assert_eq!(entry.proto, "UDP");
        assert_eq!(entry.spt.as_deref(), Some("5353"));
        assert_eq!(entry.dpt.as_deref(), Some("5353"));
        assert!(entry.display_main_line().contains("Découverte mDNS / Avahi"));
    }

    #[test]
    fn test_parse_igmp_and_icmp() {
        let igmp_line = "2026-10-21T13:47:00+0200 host kernel: [UFW BLOCK] IN=wlan0 OUT= SRC=192.168.1.254 DST=224.0.0.1 LEN=32 PROTO=2";
        let igmp = parse_ufw_log_line(igmp_line).expect("Doit parser PROTO=2 en IGMP");
        assert_eq!(igmp.proto, "IGMP");
        assert!(igmp.display_main_line().contains("Groupe Multicast (IGMP)"));

        let icmp_line = "2026-10-21T13:47:00+0200 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.15 LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=1234 SEQ=1";
        let entry = parse_ufw_log_line(icmp_line).expect("Doit parser une ligne ICMP sans port");
        assert_eq!(entry.proto, "ICMP");
        assert!(entry.spt.is_none());
        assert!(entry.dpt.is_none());
        assert_eq!(
            entry.display_main_line(),
            "Appareil local (10.0.0.5) → Ping / Diagnostic (ICMP)"
        );
    }

    #[test]
    fn test_filter_matching() {
        let line = "2026-10-21T13:45:12+0200 noos-pc kernel: [UFW BLOCK] IN=wlan0 OUT= SRC=192.168.1.42 DST=192.168.1.100 PROTO=TCP SPT=51234 DPT=22";
        let mut entry = parse_ufw_log_line(line).unwrap();
        entry.src_hostname = Some(String::from("macbook-axel.local"));
        assert!(entry.matches_filter("192.168.1.42"));
        assert!(entry.matches_filter("macbook"));
        assert!(entry.matches_filter("ssh"));
        assert!(entry.matches_filter("22"));
        assert!(entry.matches_filter("51234"));
        assert!(entry.matches_filter("tcp"));
        assert!(!entry.matches_filter("8080"));
    }
}
