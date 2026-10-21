use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;

use crate::ufw::models::{
    FirewallStatus, Protocol, Rule, RuleAction, RuleDirection, UfwError,
};

/// Vérifie si le binaire `ufw` est présent sur le système.
pub fn is_ufw_installed() -> bool {
    for path in ["/usr/bin/ufw", "/usr/sbin/ufw", "/sbin/ufw", "/bin/ufw"] {
        if Path::new(path).is_file() {
            return true;
        }
    }
    Command::new("which")
        .arg("ufw")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Détecte de manière fiable et sans élévation de privilèges si le pare-feu UFW est actif.
/// Lit `/etc/ufw/ufw.conf` (`ENABLED=yes` / `ENABLED=no`), qui est mis à jour par `ufw enable` et `ufw disable`.
/// En repli, interroge `systemctl is-active ufw`.
pub fn check_ufw_active() -> bool {
    if let Ok(content) = fs::read_to_string("/etc/ufw/ufw.conf") {
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                if key.trim().eq_ignore_ascii_case("ENABLED") {
                    let clean_val = val.trim().trim_matches('"').trim_matches('\'');
                    return clean_val.eq_ignore_ascii_case("yes")
                        || clean_val.eq_ignore_ascii_case("true")
                        || clean_val == "1";
                }
            }
        }
    }

    Command::new("systemctl")
        .args(["is-active", "ufw"])
        .env("LC_ALL", "C")
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .eq_ignore_ascii_case("active")
        })
        .unwrap_or(false)
}

/// Lit la configuration par défaut (`/etc/default/ufw`) sans privilèges root.
/// Retourne `(default_incoming, default_outgoing, ipv6_enabled)`.
pub fn read_ufw_defaults() -> (String, String, bool) {
    let mut incoming = String::from("Bloquée (Entrée)");
    let mut outgoing = String::from("Autorisée (Sortie)");
    let mut ipv6 = true;

    if let Ok(content) = fs::read_to_string("/etc/default/ufw") {
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                let k = key.trim();
                let v = val.trim().trim_matches('"').trim_matches('\'').to_uppercase();
                match k {
                    "DEFAULT_INPUT_POLICY" => {
                        incoming = match v.as_str() {
                            "ACCEPT" => String::from("Autorisée (Entrée)"),
                            "REJECT" => String::from("Rejetée (Entrée)"),
                            _ => String::from("Bloquée (Entrée)"),
                        };
                    }
                    "DEFAULT_OUTPUT_POLICY" => {
                        outgoing = match v.as_str() {
                            "DROP" => String::from("Bloquée (Sortie)"),
                            "REJECT" => String::from("Rejetée (Sortie)"),
                            _ => String::from("Autorisée (Sortie)"),
                        };
                    }
                    "IPV6" => {
                        ipv6 = v == "YES" || v == "TRUE" || v == "1";
                    }
                    _ => {}
                }
            }
        }
    }

    (incoming, outgoing, ipv6)
}

/// Parse une ligne `### tuple ###` issue de `/etc/ufw/user.rules` ou `/etc/ufw/user6.rules`.
pub fn parse_ufw_tuple_line(line: &str, number: u32, ipv6: bool) -> Option<Rule> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("### tuple ###")?.trim();

    // Retirer un éventuel suffixe `comment=...`
    let without_comment = match rest.split_once(" comment=") {
        Some((before, _)) => before.trim(),
        None => rest,
    };

    let tokens: Vec<&str> = without_comment.split_whitespace().collect();
    if tokens.len() < 6 || tokens.len() > 9 {
        return None;
    }

    // Format UFW :
    // 0: action (ex: allow, deny, reject, limit, allow_log, route:allow)
    // 1: proto (tcp, udp, any)
    // 2: dport (22, 80, 1714:1764, any)
    // 3: dst (0.0.0.0/0, ::/0, ...)
    // 4: sport (any, ...)
    // 5: src (0.0.0.0/0, ::/0, 192.168.1.0/24, ...)
    // [6: dapp, 7: sapp] (si len >= 8)
    // last (si len == 7 ou 9): direction/iface (in, out, in_virbr0, out_wlan0, in_virbr0!out_wlan0)
    let raw_action = tokens[0];
    let action_base = raw_action
        .split(':')
        .next_back()
        .unwrap_or(raw_action)
        .split('_')
        .next()
        .unwrap_or(raw_action)
        .to_lowercase();

    let action = match action_base.as_str() {
        "allow" => RuleAction::Allow,
        "deny" => RuleAction::Deny,
        "reject" => RuleAction::Reject,
        "limit" => RuleAction::Limit,
        _ => RuleAction::Allow,
    };

    let protocol = match tokens[1].to_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => Protocol::Both,
    };

    let dport = tokens[2];
    let src = tokens[5];

    let dir_token = if tokens.len() == 7 || tokens.len() == 9 {
        tokens[tokens.len() - 1]
    } else {
        "in"
    };

    let direction = if dir_token.starts_with("out") {
        RuleDirection::Out
    } else {
        RuleDirection::In
    };

    let port = if dport != "any" {
        dport.to_string()
    } else if tokens.len() >= 8 && tokens[6] != "-" {
        tokens[6].replace("%20", " ")
    } else if let Some((_, iface)) = dir_token.split_once('_') {
        format!("Interface {iface}")
    } else {
        String::from("Tous les ports")
    };

    let from = if src == "0.0.0.0/0" || src == "::/0" || src.eq_ignore_ascii_case("any") {
        String::from("Anywhere")
    } else {
        src.to_string()
    };

    Some(Rule {
        number,
        port,
        protocol,
        action,
        direction,
        from,
        ipv6,
    })
}

/// Lit directement les règles numérotées depuis `/etc/ufw/user.rules` et `/etc/ufw/user6.rules`
/// sans demander de mot de passe Polkit (`pkexec`), exactement dans l'ordre utilisé par `ufw status numbered`.
pub fn read_status_and_rules_unprivileged() -> FirewallStatus {
    let installed = is_ufw_installed();
    let active = check_ufw_active();
    let (default_incoming, default_outgoing, ipv6_enabled) = read_ufw_defaults();

    if !installed {
        return FirewallStatus {
            active: false,
            ufw_installed: false,
            default_incoming,
            default_outgoing,
            rules: Vec::new(),
        };
    }

    let mut rules = Vec::new();
    let mut counter: u32 = 1;

    if let Ok(v4_content) = fs::read_to_string("/etc/ufw/user.rules") {
        for line in v4_content.lines() {
            if let Some(rule) = parse_ufw_tuple_line(line, counter, false) {
                rules.push(rule);
                counter += 1;
            }
        }
    }

    if ipv6_enabled {
        if let Ok(v6_content) = fs::read_to_string("/etc/ufw/user6.rules") {
            for line in v6_content.lines() {
                if let Some(rule) = parse_ufw_tuple_line(line, counter, true) {
                    rules.push(rule);
                    counter += 1;
                }
            }
        }
    }

    FirewallStatus {
        active,
        ufw_installed: true,
        default_incoming,
        default_outgoing,
        rules,
    }
}

/// Valide strictement une spécification de port ou plage de ports (`[0-9:]` uniquement, entre 1 et 65535).
/// Empêche toute injection d'arguments ou de commandes.
pub fn validate_port_spec(input: &str) -> Result<String, UfwError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(UfwError::InvalidPort(String::from(
            "Veuillez saisir un numéro de port ou une plage (ex. 80, 22, 1714:1764).",
        )));
    }

    // Validation stricte : uniquement [0-9:]
    if !trimmed.chars().all(|c| c.is_ascii_digit() || c == ':') {
        return Err(UfwError::InvalidPort(String::from(
            "Caractères non autorisés : seuls les chiffres (0-9) et « : » sont permis.",
        )));
    }

    if let Some((start_str, end_str)) = trimmed.split_once(':') {
        if start_str.is_empty() || end_str.is_empty() || end_str.contains(':') {
            return Err(UfwError::InvalidPort(String::from(
                "Format de plage invalide. Utilisez le format debut:fin (ex. 1714:1764).",
            )));
        }

        let start = start_str.parse::<u16>().map_err(|_| {
            UfwError::InvalidPort(String::from(
                "Le port de début doit être compris entre 1 et 65535.",
            ))
        })?;
        let end = end_str.parse::<u16>().map_err(|_| {
            UfwError::InvalidPort(String::from(
                "Le port de fin doit être compris entre 1 et 65535.",
            ))
        })?;

        if start == 0 || end == 0 {
            return Err(UfwError::InvalidPort(String::from(
                "Le numéro de port doit être compris entre 1 et 65535 (0 est invalide).",
            )));
        }

        if start > end {
            return Err(UfwError::InvalidPort(format!(
                "Plage invalide : le port de début ({start}) est supérieur au port de fin ({end})."
            )));
        }

        Ok(format!("{start}:{end}"))
    } else {
        let port = trimmed.parse::<u16>().map_err(|_| {
            UfwError::InvalidPort(String::from(
                "Le numéro de port doit être compris entre 1 et 65535.",
            ))
        })?;

        if port == 0 {
            return Err(UfwError::InvalidPort(String::from(
                "Le numéro de port doit être compris entre 1 et 65535 (0 est invalide).",
            )));
        }

        Ok(port.to_string())
    }
}

/// Détermine si le code de retour ou le message d'erreur de `pkexec` correspond à une annulation Polkit.
pub fn is_pkexec_cancelled(exit_code: Option<i32>, stderr: &str) -> bool {
    if matches!(exit_code, Some(126) | Some(127)) {
        return true;
    }
    let lower = stderr.to_lowercase();
    lower.contains("dismissed")
        || lower.contains("not authorized")
        || lower.contains("authentication failed")
        || lower.contains("cancelled")
        || lower.contains("canceled")
}

/// Exécute `pkexec ufw <args...>` en une seule élévation Polkit.
pub fn run_pkexec_ufw(args: &[&str]) -> Result<String, UfwError> {
    if !is_ufw_installed() {
        return Err(UfwError::NotInstalled);
    }

    let output = Command::new("pkexec")
        .arg("ufw")
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .map_err(|e| {
            UfwError::CommandFailed(format!("Impossible de lancer pkexec ufw : {e}"))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if output.status.success() {
        return Ok(stdout);
    }

    let code = output.status.code();
    if is_pkexec_cancelled(code, &stderr) {
        return Err(UfwError::Cancelled);
    }

    let detail = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else if !stdout.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        format!("Code de sortie {:?}", code)
    };

    Err(UfwError::CommandFailed(format!(
        "Échec de la commande ufw ({}) : {detail}",
        args.join(" ")
    )))
}

fn rule_line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT|AUTORISER|REFUSER|REJETER|LIMITER)(?:\s+(IN|OUT|FWD|ENTRÉE|SORTIE))?\s{2,}(.+)$",
        )
        .expect("Regex UFW status numbered valide")
    })
}

/// Parse la sortie de `ufw status numbered` en `FirewallStatus`.
pub fn parse_ufw_status_output(output: &str, fallback_active: bool) -> FirewallStatus {
    let (default_incoming, default_outgoing, _) = read_ufw_defaults();
    let mut status = FirewallStatus {
        active: fallback_active,
        ufw_installed: true,
        default_incoming,
        default_outgoing,
        rules: Vec::new(),
    };

    let re = rule_line_regex();

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let lower = line.to_lowercase();
        if lower.starts_with("status:") || lower.starts_with("état") || lower.starts_with("etat")
        {
            if lower.contains("inactive") || lower.contains("inactif") {
                status.active = false;
            } else if lower.contains("active") || lower.contains("actif") {
                status.active = true;
            }
            continue;
        }

        if let Some(caps) = re.captures(line) {
            let Ok(number) = caps[1].parse::<u32>() else {
                continue;
            };
            let raw_target = caps[2].trim();
            let raw_action = caps[3].trim().to_uppercase();
            let raw_dir = caps
                .get(4)
                .map(|m| m.as_str().trim().to_uppercase())
                .unwrap_or_else(|| String::from("IN"));
            let raw_from = caps[5].trim();

            let ipv6 = raw_target.contains("(v6)") || raw_from.contains("(v6)");
            let clean_target = raw_target.replace("(v6)", "").trim().to_string();

            let (port, protocol) = if let Some((p, proto_str)) = clean_target.rsplit_once('/') {
                let proto = match proto_str.trim().to_lowercase().as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    _ => Protocol::Both,
                };
                (p.trim().to_string(), proto)
            } else {
                (clean_target, Protocol::Both)
            };

            let action = match raw_action.as_str() {
                "ALLOW" | "AUTORISER" => RuleAction::Allow,
                "DENY" | "REFUSER" => RuleAction::Deny,
                "REJECT" | "REJETER" => RuleAction::Reject,
                "LIMIT" | "LIMITER" => RuleAction::Limit,
                _ => RuleAction::Allow,
            };

            let direction = match raw_dir.as_str() {
                "OUT" | "SORTIE" => RuleDirection::Out,
                _ => RuleDirection::In,
            };

            let clean_from = raw_from.replace("(v6)", "").trim().to_string();

            status.rules.push(Rule {
                number,
                port,
                protocol,
                action,
                direction,
                from: if clean_from.is_empty() {
                    String::from("Anywhere")
                } else {
                    clean_from
                },
                ipv6,
            });
        }
    }

    status
}

/// Construit les arguments CLI pour ajouter une règle UFW après validation stricte.
pub fn build_add_rule_commands(
    port_input: &str,
    protocol: Protocol,
    action: RuleAction,
) -> Result<Vec<Vec<String>>, UfwError> {
    let valid_port = validate_port_spec(port_input)?;
    let action_arg = action.cli_arg().to_string();

    match protocol {
        Protocol::Tcp => Ok(vec![vec![action_arg, format!("{valid_port}/tcp")]]),
        Protocol::Udp => Ok(vec![vec![action_arg, format!("{valid_port}/udp")]]),
        Protocol::Both => {
            if valid_port.contains(':') {
                Ok(vec![
                    vec![action_arg.clone(), format!("{valid_port}/tcp")],
                    vec![action_arg, format!("{valid_port}/udp")],
                ])
            } else {
                Ok(vec![vec![action_arg, valid_port]])
            }
        }
    }
}

/// Exécute une commande dans un thread d'arrière-plan via le pool de threads GIO (`gio::spawn_blocking`)
/// et invoque `on_complete` sur le thread principal GTK sans jamais le bloquer.
pub fn run_in_background_thread<T, F, C>(work: F, on_complete: C)
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    C: FnOnce(T) + 'static,
{
    glib::MainContext::default().spawn_local(async move {
        if let Ok(result) = gio::spawn_blocking(work).await {
            on_complete(result);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_single_ports() {
        assert_eq!(validate_port_spec("22").unwrap(), "22");
        assert_eq!(validate_port_spec(" 8080 ").unwrap(), "8080");
        assert_eq!(validate_port_spec("1").unwrap(), "1");
        assert_eq!(validate_port_spec("65535").unwrap(), "65535");
    }

    #[test]
    fn test_validate_port_ranges() {
        assert_eq!(validate_port_spec("1714:1764").unwrap(), "1714:1764");
        assert_eq!(validate_port_spec("60000:61000").unwrap(), "60000:61000");
    }

    #[test]
    fn test_reject_invalid_or_injected_ports() {
        assert!(validate_port_spec("").is_err());
        assert!(validate_port_spec("0").is_err());
        assert!(validate_port_spec("65536").is_err());
        assert!(validate_port_spec("1000:500").is_err());
        assert!(validate_port_spec("1000:2000:3000").is_err());
        assert!(validate_port_spec(":80").is_err());
        assert!(validate_port_spec("80:").is_err());
        assert!(validate_port_spec("80/tcp").is_err());
        assert!(validate_port_spec("80; rm -rf /").is_err());
        assert!(validate_port_spec("$(whoami)").is_err());
        assert!(validate_port_spec("ssh").is_err());
    }

    #[test]
    fn test_parse_ufw_tuple_lines() {
        let l1 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in";
        let r1 = parse_ufw_tuple_line(l1, 1, false).unwrap();
        assert_eq!(r1.number, 1);
        assert_eq!(r1.port, "22");
        assert_eq!(r1.protocol, Protocol::Tcp);
        assert_eq!(r1.action, RuleAction::Allow);
        assert_eq!(r1.direction, RuleDirection::In);
        assert!(!r1.ipv6);

        let l2 = "### tuple ### deny any 443 ::/0 any ::/0 out comment=74657374";
        let r2 = parse_ufw_tuple_line(l2, 2, true).unwrap();
        assert_eq!(r2.number, 2);
        assert_eq!(r2.port, "443");
        assert_eq!(r2.protocol, Protocol::Both);
        assert_eq!(r2.action, RuleAction::Deny);
        assert_eq!(r2.direction, RuleDirection::Out);
        assert!(r2.ipv6);
    }

    #[test]
    fn test_parse_ufw_status_numbered() {
        let sample = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere
[ 3] 443                        DENY IN     Anywhere
[ 4] 1714:1764/udp              ALLOW IN    Anywhere
[ 5] 53/udp                     ALLOW OUT   Anywhere
[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
";

        let status = parse_ufw_status_output(sample, false);
        assert!(status.active);
        assert_eq!(status.rules.len(), 6);

        assert_eq!(status.rules[0].number, 1);
        assert_eq!(status.rules[0].port, "22");
        assert_eq!(status.rules[0].protocol, Protocol::Tcp);
        assert_eq!(status.rules[0].action, RuleAction::Allow);
        assert_eq!(status.rules[0].direction, RuleDirection::In);
        assert!(!status.rules[0].ipv6);
    }

    #[test]
    fn test_pkexec_cancellation_detection() {
        assert!(is_pkexec_cancelled(Some(126), ""));
        assert!(is_pkexec_cancelled(Some(127), ""));
        assert!(is_pkexec_cancelled(
            Some(1),
            "Error executing command as another user: Request dismissed"
        ));
        assert!(!is_pkexec_cancelled(Some(1), "ERROR: Bad port"));
    }
}
