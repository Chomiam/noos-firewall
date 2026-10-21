pub mod cli;
pub mod models;

use crate::ufw::cli::{
    build_add_rule_commands, read_status_and_rules_unprivileged, run_in_background_thread,
    run_pkexec_ufw,
};
use crate::ufw::models::{FirewallStatus, Protocol, RuleAction, UfwError};

/// Récupère l'état du pare-feu et les règles numérotées sans bloquer l'interface
/// et sans demander de mot de passe Polkit (lecture directe de `/etc/ufw/`).
pub fn fetch_status_async<C>(_load_rules: bool, callback: C)
where
    C: FnOnce(Result<FirewallStatus, UfwError>) + 'static,
{
    run_in_background_thread(|| Ok(read_status_and_rules_unprivileged()), callback);
}

/// Active (`pkexec ufw --force enable`) ou désactive (`pkexec ufw disable`) le pare-feu en arrière-plan
/// avec une seule demande de mot de passe Polkit.
pub fn set_enabled_async<C>(enable: bool, callback: C)
where
    C: FnOnce(Result<FirewallStatus, UfwError>) + 'static,
{
    run_in_background_thread(
        move || {
            if enable {
                run_pkexec_ufw(&["--force", "enable"])?;
            } else {
                run_pkexec_ufw(&["disable"])?;
            }
            let mut status = read_status_and_rules_unprivileged();
            status.active = enable;
            Ok(status)
        },
        callback,
    );
}

/// Ajoute une règle UFW (`pkexec ufw allow|deny <port>/<proto>`) avec une seule demande Polkit,
/// puis recharge immédiatement la liste des règles.
pub fn add_rule_async<C>(
    port_input: String,
    protocol: Protocol,
    action: RuleAction,
    callback: C,
) where
    C: FnOnce(Result<FirewallStatus, UfwError>) + 'static,
{
    run_in_background_thread(
        move || {
            let commands = build_add_rule_commands(&port_input, protocol, action)?;
            if let [single] = commands.as_slice() {
                let refs: Vec<&str> = single.iter().map(String::as_str).collect();
                run_pkexec_ufw(&refs)?;
            } else {
                for cmd_args in &commands {
                    let refs: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
                    run_pkexec_ufw(&refs)?;
                }
            }

            Ok(read_status_and_rules_unprivileged())
        },
        callback,
    );
}

/// Supprime une règle par son numéro (`pkexec ufw --force delete <numero>`) avec une seule demande Polkit,
/// puis recharge immédiatement la liste des règles.
pub fn delete_rule_async<C>(rule_number: u32, callback: C)
where
    C: FnOnce(Result<FirewallStatus, UfwError>) + 'static,
{
    run_in_background_thread(
        move || {
            let num_str = rule_number.to_string();
            run_pkexec_ufw(&["--force", "delete", &num_str])?;
            Ok(read_status_and_rules_unprivileged())
        },
        callback,
    );
}
