use std::net::IpAddr;

/// Portée réseau d'une adresse IP pour aider l'utilisateur à comprendre l'origine du trafic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficOrigin {
    /// Votre box / routeur domestique (passerelle par défaut).
    GatewayRouter,
    /// Appareil du réseau local (Wi-Fi / Ethernet domestique, LAN privé ou lien local IPv6).
    LocalNetwork,
    /// Pont virtuel local (machines virtuelles libvirt / QEMU / conteneurs Docker).
    VirtualBridge,
    /// Boucle locale (cette machine).
    Loopback,
    /// Adresse publique extérieure (Internet).
    Internet,
}

impl TrafficOrigin {
    pub fn badge_label(self) -> &'static str {
        match self {
            Self::GatewayRouter => "Box / Routeur",
            Self::LocalNetwork => "Réseau local",
            Self::VirtualBridge => "VM / Conteneur",
            Self::Loopback => "Localhost",
            Self::Internet => "Internet",
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::GatewayRouter | Self::LocalNetwork | Self::VirtualBridge | Self::Loopback => {
                "fw-badge-local"
            }
            Self::Internet => "fw-badge-internet",
        }
    }
}

/// Entrée d'événement de blocage UFW extraite du journal noyau (`journalctl -k -g "UFW BLOCK"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Horodatage formaté de façon lisible (ex. `2026-10-21 13:45:12`).
    pub timestamp: String,
    /// Horodatage ISO brut issu de `journalctl --output=short-iso`.
    pub raw_timestamp: String,
    /// Adresse IP source (`SRC=...`).
    pub src: String,
    /// Nom d'hôte résolu pour l'adresse IP source (via mDNS, DNS inverse ou `/etc/hosts`).
    pub src_hostname: Option<String>,
    /// Adresse MAC source extraite de l'en-tête Ethernet (`MAC=...`).
    pub src_mac: Option<String>,
    /// Fabricant ou type d'interface identifié à partir de l'adresse MAC (OUI).
    pub src_vendor: Option<String>,
    /// Origine qualifiée du trafic (Box/Routeur, Réseau local, VM, Internet).
    pub origin: TrafficOrigin,
    /// Adresse IP de destination locale (`DST=...`).
    pub dst: String,
    /// Protocole réseau (`TCP`, `UDP`, `ICMP`, `ICMPv6`, `IGMP`, etc.).
    pub proto: String,
    /// Port source (`SPT=...`, absent pour ICMP/IGMP).
    pub spt: Option<String>,
    /// Port destination ciblé (`DPT=...`, absent pour ICMP/IGMP).
    pub dpt: Option<String>,
    /// Interface réseau d'entrée (`IN=...`).
    pub interface_in: Option<String>,
}

impl LogEntry {
    /// Nom lisible de l'appareil source : combine le nom d'hôte (ou le fabricant/rôle) et l'IP.
    pub fn display_source_host(&self) -> String {
        if let Some(host) = &self.src_hostname {
            return format!("{host} ({})", self.src);
        }
        if self.origin == TrafficOrigin::GatewayRouter {
            return format!("Box / Routeur ({})", self.src);
        }
        if let Some(vendor) = &self.src_vendor {
            return format!("Appareil {vendor} ({})", self.src);
        }
        match self.origin {
            TrafficOrigin::LocalNetwork => format!("Appareil local ({})", self.src),
            TrafficOrigin::VirtualBridge => format!("Machine virtuelle ({})", self.src),
            TrafficOrigin::Loopback => format!("Cette machine ({})", self.src),
            TrafficOrigin::Internet => self.src.clone(),
            TrafficOrigin::GatewayRouter => format!("Box / Routeur ({})", self.src),
        }
    }

    /// Nom du service ou de l'application associé au port destination (ou au protocole).
    pub fn service_description(&self) -> String {
        if let Some(dpt_str) = &self.dpt {
            if let Ok(port) = dpt_str.parse::<u16>() {
                if let Some(service_name) = describe_port_service(port, &self.proto) {
                    return format!("Port {port} ({service_name})");
                }
            }
            return format!("Port {dpt_str}");
        }

        match self.proto.as_str() {
            "IGMP" => String::from("Groupe Multicast (IGMP)"),
            "ICMP" => String::from("Ping / Diagnostic (ICMP)"),
            "ICMPV6" | "ICMPv6" => String::from("Découverte réseau IPv6 (ICMPv6)"),
            other => format!("Protocole {other}"),
        }
    }

    /// Ligne principale affichée dans la liste :
    /// met en évidence le nom de la machine source, l'IP et le service ciblé.
    pub fn display_main_line(&self) -> String {
        let src_label = self.display_source_host();
        let target_label = self.service_description();
        format!("{src_label} → {target_label}")
    }

    /// Ligne technique au format `IP_SOURCE:SPT → Port DPT`.
    pub fn display_technical_flow(&self) -> String {
        match (&self.spt, &self.dpt) {
            (Some(spt), Some(dpt)) => format!("{}:{} → {}:{}", self.src, spt, self.dst, dpt),
            (None, Some(dpt)) => format!("{} → {}:{}", self.src, self.dst, dpt),
            (Some(spt), None) => format!("{}:{} → {}", self.src, spt, self.dst),
            (None, None) => format!("{} → {}", self.src, self.dst),
        }
    }

    /// Résumé clair en une ligne (sous-titre de la liste principale).
    pub fn display_subtitle(&self) -> String {
        let summary = self.short_activity_label();
        match &self.interface_in {
            Some(iface) if !iface.is_empty() => {
                format!("{} · {summary} · via {iface}", self.timestamp)
            }
            _ => format!("{} · {summary}", self.timestamp),
        }
    }

    /// Libellé court expliquant la nature du trafic bloqué.
    pub fn short_activity_label(&self) -> String {
        if let Some(multicast_desc) = describe_special_destination(&self.dst) {
            return multicast_desc.to_string();
        }

        if let Some(dpt_str) = &self.dpt {
            if let Ok(port) = dpt_str.parse::<u16>() {
                if let Some(desc) = describe_port_purpose(port) {
                    return desc.to_string();
                }
            }
            return format!(
                "Connexion entrante {} vers le port {}",
                self.proto, dpt_str
            );
        }

        match self.proto.as_str() {
            "IGMP" => String::from("Annonce de groupe multicast local (box / routeur / TV)"),
            "ICMP" | "ICMPV6" | "ICMPv6" => {
                String::from("Requête de diagnostic ou de présence réseau (Ping)")
            }
            _ => format!("Paquet réseau {} bloqué", self.proto),
        }
    }

    /// Explication pédagogique complète affichée lorsque l'utilisateur déplie la ligne.
    pub fn detailed_explanation(&self) -> String {
        if let Some(multicast_desc) = describe_special_destination(&self.dst) {
            return format!(
                "{multicast_desc}. Ce paquet n'était pas dirigé spécifiquement contre votre ordinateur, \
                 mais diffusé à tous les appareils du réseau local (découverte automatique de services, TV, imprimantes ou box). \
                 Son blocage est normal et sans aucun risque."
            );
        }

        if self.proto == "IGMP" {
            return String::from(
                "Paquet de gestion de groupes Multicast (IGMP), généralement envoyé par votre box Internet ou un équipement multimédia. \
                 Son blocage par défaut par UFW est normal."
            );
        }

        if let Some(dpt_str) = &self.dpt {
            if let Ok(port) = dpt_str.parse::<u16>() {
                match port {
                    1714..=1764 => {
                        return String::from(
                            "Tentative de communication KDE Connect / GSConnect (synchronisation téléphone ↔ PC). \
                             Si vous souhaitez utiliser KDE Connect avec cet appareil, autorisez la plage de ports 1714:1764 (TCP + UDP)."
                        );
                    }
                    53317 => {
                        return String::from(
                            "Tentative de partage de fichiers via LocalSend sur le réseau local. \
                             Autorisez le port 53317 si vous souhaitez recevoir des fichiers depuis cet appareil."
                        );
                    }
                    137..=139 | 445 => {
                        return String::from(
                            "Trafic de partage de fichiers Windows / Samba (SMB/NetBIOS). \
                             Souvent émis automatiquement par d'autres PC ou par votre box sur le réseau local."
                        );
                    }
                    5353 => {
                        return String::from(
                            "Découverte automatique d'appareils et d'imprimantes sur le réseau local (mDNS / Avahi / Bonjour)."
                        );
                    }
                    1900 => {
                        return String::from(
                            "Découverte automatique d'équipements multimédias sur le réseau local (UPnP / SSDP / DLNA)."
                        );
                    }
                    22 => {
                        return String::from(
                            "Tentative de connexion à distance via SSH (port 22). \
                             Si vous n'avez pas initié cette connexion vous-même, le pare-feu vous a protégé."
                        );
                    }
                    _ => {}
                }
            }
        }

        match self.origin {
            TrafficOrigin::Internet => String::from(
                "Connexion entrante non sollicitée provenant d'Internet et bloquée automatiquement par UFW."
            ),
            _ => String::from(
                "Paquet émis par un appareil de votre réseau local vers un port non ouvert sur votre ordinateur."
            ),
        }
    }

    /// Vérifie si l'entrée correspond au filtre de recherche (IP, nom d'hôte, fabricant, port, service ou protocole).
    pub fn matches_filter(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }

        if self.src.to_lowercase().contains(&q)
            || self.dst.to_lowercase().contains(&q)
            || self.proto.to_lowercase().contains(&q)
            || self.timestamp.to_lowercase().contains(&q)
            || self.display_main_line().to_lowercase().contains(&q)
            || self.short_activity_label().to_lowercase().contains(&q)
        {
            return true;
        }

        if let Some(host) = &self.src_hostname {
            if host.to_lowercase().contains(&q) {
                return true;
            }
        }
        if let Some(vendor) = &self.src_vendor {
            if vendor.to_lowercase().contains(&q) {
                return true;
            }
        }
        if let Some(mac) = &self.src_mac {
            if mac.to_lowercase().contains(&q) {
                return true;
            }
        }
        if let Some(spt) = &self.spt {
            if spt.contains(&q) {
                return true;
            }
        }
        if let Some(dpt) = &self.dpt {
            if dpt.contains(&q) {
                return true;
            }
        }

        false
    }
}

/// Qualifie l'origine d'une adresse IP source.
pub fn classify_ip_origin(src: &str, gateway_ip: Option<&str>) -> TrafficOrigin {
    if let Some(gw) = gateway_ip {
        if !gw.is_empty() && src == gw {
            return TrafficOrigin::GatewayRouter;
        }
    }

    if src.starts_with("192.168.122.") || src.starts_with("172.17.") {
        return TrafficOrigin::VirtualBridge;
    }

    if let Ok(ip) = src.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    TrafficOrigin::Loopback
                } else if v4.is_private() || v4.is_link_local() || v4.is_broadcast() {
                    TrafficOrigin::LocalNetwork
                } else {
                    TrafficOrigin::Internet
                }
            }
            IpAddr::V6(v6) => {
                let segs = v6.segments();
                if v6.is_loopback() {
                    TrafficOrigin::Loopback
                } else if (segs[0] & 0xffc0) == 0xfe80 || (segs[0] & 0xfe00) == 0xfc00 {
                    // fe80::/10 (lien local) ou fc00::/7 (ULA privé)
                    TrafficOrigin::LocalNetwork
                } else {
                    TrafficOrigin::Internet
                }
            }
        }
    } else {
        TrafficOrigin::LocalNetwork
    }
}

/// Identifie les adresses de destination spéciales (Multicast / Broadcast) très fréquentes dans les logs UFW.
pub fn describe_special_destination(dst: &str) -> Option<&'static str> {
    let lower = dst.to_lowercase();
    match lower.as_str() {
        "224.0.0.1" => Some("Diffusion Multicast locale (tous les appareils du réseau)"),
        "224.0.0.2" => Some("Diffusion Multicast vers les routeurs du réseau"),
        "224.0.0.22" => Some("Protocole de groupe Multicast IGMPv3"),
        "224.0.0.251" | "ff02::fb" | "ff02:0000:0000:0000:0000:0000:0000:00fb" => {
            Some("Découverte locale d'appareils et imprimantes (Multicast mDNS)")
        }
        "224.0.0.252" | "ff02::1:3" | "ff02:0000:0000:0000:0000:0000:0001:0003" => {
            Some("Résolution de noms locale Windows (Multicast LLMNR)")
        }
        "239.255.255.250" | "ff02::c" | "ff02:0000:0000:0000:0000:0000:0000:000c" => {
            Some("Découverte d'équipements multimédias UPnP / SSDP / DLNA")
        }
        "255.255.255.255" => Some("Diffusion générale sur le réseau local (Broadcast)"),
        "ff02::1" | "ff02:0000:0000:0000:0000:0000:0000:0001" => {
            Some("Diffusion IPv6 à tous les appareils du réseau local")
        }
        "ff02::2" | "ff02:0000:0000:0000:0000:0000:0000:0002" => {
            Some("Diffusion IPv6 vers les routeurs locaux")
        }
        "ff02::16" | "ff02:0000:0000:0000:0000:0000:0000:0016" => {
            Some("Annonce de groupe Multicast IPv6 (MLDv2)")
        }
        _ => {
            if lower.ends_with(".255") {
                Some("Diffusion sur le sous-réseau local (Broadcast)")
            } else if lower.starts_with("224.")
                || lower.starts_with("239.")
                || lower.starts_with("ff0")
            {
                Some("Diffusion de groupe Multicast local")
            } else {
                None
            }
        }
    }
}

/// Dictionnaire des services réseau courants par numéro de port.
pub fn describe_port_service(port: u16, _proto: &str) -> Option<&'static str> {
    match port {
        20 | 21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 | 465 | 587 => Some("Messagerie SMTP"),
        53 => Some("DNS"),
        67 | 68 => Some("DHCP"),
        80 | 8000 | 8080 => Some("Web HTTP"),
        110 | 995 => Some("Messagerie POP3"),
        123 => Some("Horloge NTP"),
        137 => Some("NetBIOS Noms / Samba"),
        138 => Some("NetBIOS Datagram / Samba"),
        139 => Some("Partage Samba / NetBIOS"),
        143 | 993 => Some("Messagerie IMAP"),
        443 | 8443 => Some("Web HTTPS"),
        445 => Some("Partage de fichiers SMB / Samba"),
        546 | 547 => Some("DHCPv6"),
        631 => Some("Imprimante CUPS / IPP"),
        1194 => Some("VPN OpenVPN"),
        1714..=1764 => Some("KDE Connect / GSConnect"),
        1900 => Some("Découverte UPnP / SSDP"),
        2049 => Some("Partage NFS"),
        3000 | 5173 => Some("Serveur de dév. Web"),
        3306 => Some("Base MySQL / MariaDB"),
        3389 => Some("Bureau à distance RDP"),
        5000 => Some("UPnP / Synology / Flask"),
        5353 => Some("Découverte mDNS / Avahi"),
        5355 => Some("Résolution LLMNR"),
        5432 => Some("Base PostgreSQL"),
        5900..=5909 => Some("Bureau à distance VNC"),
        6379 => Some("Base Redis"),
        7359 | 8096 | 8920 => Some("Média Jellyfin"),
        8384 | 21027 | 22000 => Some("Syncthing"),
        9090 => Some("Cockpit / Prometheus"),
        25565 => Some("Serveur Minecraft"),
        27015..=27036 => Some("Steam / Jeu réseau"),
        32400 | 32410..=32414 => Some("Média Plex"),
        51820 => Some("VPN WireGuard"),
        53317 => Some("LocalSend"),
        _ => None,
    }
}

/// Explication courte de l'usage d'un port ciblé.
pub fn describe_port_purpose(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("Tentative d'accès distant sécurisé (SSH)"),
        53 => Some("Requête de résolution de nom de domaine (DNS)"),
        67 | 68 | 546 | 547 => Some("Configuration automatique d'adresse IP (DHCP)"),
        80 | 443 | 8080 | 8443 => Some("Requête vers un serveur Web (HTTP/HTTPS)"),
        123 => Some("Synchronisation de l'horloge système (NTP)"),
        137..=139 | 445 => Some("Découverte ou partage de fichiers Windows / Samba"),
        631 => Some("Service d'impression réseau (CUPS / IPP)"),
        1714..=1764 => Some("Synchronisation smartphone ↔ PC (KDE Connect)"),
        1900 => Some("Recherche d'appareils multimédias sur le réseau (UPnP / DLNA)"),
        3389 => Some("Tentative de connexion Bureau à distance (RDP)"),
        5353 => Some("Découverte automatique d'appareils et imprimantes (mDNS)"),
        5355 => Some("Résolution de noms d'appareils locaux (LLMNR)"),
        5900..=5909 => Some("Tentative de partage d'écran à distance (VNC)"),
        8384 | 21027 | 22000 => Some("Synchronisation de fichiers Syncthing"),
        27015..=27036 => Some("Découverte ou flux Steam sur le réseau local"),
        32400 | 32410..=32414 => Some("Découverte de serveur multimédia Plex"),
        51820 => Some("Trafic de tunnel VPN WireGuard"),
        53317 => Some("Transfert de fichiers sur le réseau local (LocalSend)"),
        _ => None,
    }
}

/// Identifie les préfixes MAC (OUI) les plus courants sur un réseau domestique ou virtuel.
pub fn lookup_mac_vendor(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(0..8)?.to_uppercase();
    match prefix.as_str() {
        "52:54:00" => Some("QEMU / KVM (Virtuel)"),
        "02:42:AC" => Some("Conteneur Docker"),
        "00:50:56" | "00:0C:29" | "00:05:69" => Some("VMware"),
        "08:00:27" | "0A:00:27" => Some("VirtualBox"),
        "B8:27:EB" | "DC:A6:32" | "E4:5F:01" | "28:CD:C1" | "D8:3A:DD" => Some("Raspberry Pi"),
        "14:0C:76" | "F4:CA:E5" | "68:A3:78" | "34:27:92" | "70:FC:8F" | "8C:97:EA" => {
            Some("Freebox")
        }
        "00:11:32" | "90:09:D0" => Some("Synology NAS"),
        "3C:22:FB" | "F0:18:98" | "A4:83:E7" | "BC:D0:74" | "D0:81:7A" => Some("Apple"),
        "DC:EF:CA" | "B4:B0:24" | "38:F9:D3" => Some("Apple"),
        _ => None,
    }
}
