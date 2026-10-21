use std::fmt;

/// Protocole réseau d'une règle UFW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Both => "Tous",
        }
    }

    pub fn cli_suffix(self) -> Option<&'static str> {
        match self {
            Self::Tcp => Some("tcp"),
            Self::Udp => Some("udp"),
            Self::Both => None,
        }
    }

    pub fn from_dropdown_index(index: u32) -> Self {
        match index {
            0 => Self::Tcp,
            1 => Self::Udp,
            _ => Self::Both,
        }
    }
}

/// Action appliquée par une règle UFW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    Reject,
    Limit,
}

impl RuleAction {
    pub fn badge_label(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::Reject => "REJECT",
            Self::Limit => "LIMIT",
        }
    }

    pub fn french_label(self) -> &'static str {
        match self {
            Self::Allow => "Autoriser",
            Self::Deny => "Bloquer",
            Self::Reject => "Rejeter",
            Self::Limit => "Limiter",
        }
    }

    pub fn cli_arg(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
            Self::Limit => "limit",
        }
    }

    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow | Self::Limit)
    }

    pub fn from_dropdown_index(index: u32) -> Self {
        match index {
            0 => Self::Allow,
            _ => Self::Deny,
        }
    }
}

/// Direction du flux réseau concerné par la règle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDirection {
    In,
    Out,
}

impl RuleDirection {
    pub fn badge_label(self) -> &'static str {
        match self {
            Self::In => "IN",
            Self::Out => "OUT",
        }
    }

    pub fn french_label(self) -> &'static str {
        match self {
            Self::In => "Entrée",
            Self::Out => "Sortie",
        }
    }
}

/// Représentation structurée d'une règle issue de `ufw status numbered`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub number: u32,
    pub port: String,
    pub protocol: Protocol,
    pub action: RuleAction,
    pub direction: RuleDirection,
    pub from: String,
    pub ipv6: bool,
}

impl Rule {
    /// Titre lisible de la cible (port/service + nom de service connu + indication IPv6 éventuelle).
    pub fn display_target(&self) -> String {
        let service_hint = self
            .port
            .split(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .and_then(|port_num| {
                crate::logs::models::describe_port_service(port_num, self.protocol.label())
            });

        match (service_hint, self.ipv6) {
            (Some(svc), true) => format!("Port {} — {svc} (IPv6)", self.port),
            (Some(svc), false) => format!("Port {} — {svc}", self.port),
            (None, true) => format!("Port {} (IPv6)", self.port),
            (None, false) => format!("Port {}", self.port),
        }
    }

    /// Sous-titre descriptif de la règle.
    pub fn display_subtitle(&self) -> String {
        let src = if self.from.eq_ignore_ascii_case("Anywhere")
            || self.from.eq_ignore_ascii_case("Anywhere (v6)")
            || self.from.eq_ignore_ascii_case("Partout")
        {
            "Toutes les adresses (Anywhere)"
        } else {
            self.from.as_str()
        };
        format!(
            "{} · Direction : {} ({}) · Source : {}",
            self.action.french_label(),
            self.direction.french_label(),
            self.direction.badge_label(),
            src
        )
    }
}

/// État global du pare-feu UFW et liste de ses règles numérotées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallStatus {
    pub active: bool,
    pub ufw_installed: bool,
    pub default_incoming: String,
    pub default_outgoing: String,
    pub rules: Vec<Rule>,
}

impl Default for FirewallStatus {
    fn default() -> Self {
        Self {
            active: false,
            ufw_installed: true,
            default_incoming: String::from("Bloquée (Entrée)"),
            default_outgoing: String::from("Autorisée (Sortie)"),
            rules: Vec::new(),
        }
    }
}

/// Erreurs possibles lors des opérations sur le pare-feu UFW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UfwError {
    /// L'utilisateur a annulé ou fermé la boîte de dialogue d'authentification Polkit (`pkexec`).
    Cancelled,
    /// Le binaire `ufw` n'est pas installé sur le système.
    NotInstalled,
    /// Le port ou la plage de ports saisie est invalide.
    InvalidPort(String),
    /// Échec d'exécution de la commande système.
    CommandFailed(String),
}

impl fmt::Display for UfwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "Authentification Polkit annulée par l'utilisateur."),
            Self::NotInstalled => write!(
                f,
                "Le paquet « ufw » n'est pas installé sur ce système (sudo pacman -S ufw)."
            ),
            Self::InvalidPort(msg) => write!(f, "{msg}"),
            Self::CommandFailed(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for UfwError {}
