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

/// Vérifie de manière non-privilégiée si le service `ufw` est actif via `systemctl is-active ufw`.
pub fn check_systemd_ufw_active() -> bool {
    let output = Command::new("systemctl")
        .args(["is-active", "ufw"])
        .env("LC_ALL", "C")
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.trim().eq_ignore_ascii_case("active")
        }
        Err(_) => false,
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

/// Exécute `pkexec ufw <args...>` de façon synchrone (à appeler uniquement depuis un thread d'arrière-plan).
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

/// Parse la sortie de `ufw status numbered` (ou `ufw status verbose`) en `FirewallStatus`.
pub fn parse_ufw_status_output(output: &str, fallback_active: bool) -> FirewallStatus {
    let mut status = FirewallStatus {
        active: fallback_active,
        ufw_installed: true,
        default_incoming: String::from("Bloquée (Entrée)"),
        default_outgoing: String::from("Autorisée (Sortie)"),
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
            // Pour une plage de ports (ex. 1714:1764), UFW impose de préciser /tcp ou /udp.
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

        assert_eq!(status.rules[2].number, 3);
        assert_eq!(status.rules[2].port, "443");
        assert_eq!(status.rules[2].protocol, Protocol::Both);
        assert_eq!(status.rules[2].action, RuleAction::Deny);

        assert_eq!(status.rules[3].number, 4);
        assert_eq!(status.rules[3].port, "1714:1764");
        assert_eq!(status.rules[3].protocol, Protocol::Udp);

        assert_eq!(status.rules[4].direction, RuleDirection::Out);
        assert!(status.rules[5].ipv6);
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
