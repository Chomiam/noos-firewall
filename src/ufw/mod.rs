pub mod cli;
pub mod models;

use crate::ufw::cli::{
    build_add_rule_commands, check_systemd_ufw_active, is_ufw_installed,
    parse_ufw_status_output, run_in_background_thread, run_pkexec_ufw,
};
use crate::ufw::models::{FirewallStatus, Protocol, RuleAction, UfwError};

/// Récupère l'état initial du pare-feu sans bloquer l'interface.
/// Si `ufw` est actif et `load_rules` vaut `true`, interroge `pkexec ufw status numbered`.
pub fn fetch_status_async<C>(load_rules: bool, callback: C)
where
    C: FnOnce(Result<FirewallStatus, UfwError>) + 'static,
{
    run_in_background_thread(
        move || {
            let installed = is_ufw_installed();
            let active = check_systemd_ufw_active();

            if !installed {
                return Ok(FirewallStatus {
                    active: false,
                    ufw_installed: false,
                    ..FirewallStatus::default()
                });
            }

            if load_rules {
                let out = run_pkexec_ufw(&["status", "numbered"])?;
                Ok(parse_ufw_status_output(&out, active))
            } else {
                Ok(FirewallStatus {
                    active,
                    ufw_installed: true,
                    ..FirewallStatus::default()
                })
            }
        },
        callback,
    );
}

/// Active (`pkexec ufw --force enable`) ou désactive (`pkexec ufw disable`) le pare-feu en arrière-plan.
pub fn set_enabled_async<C>(enable: bool, callback: C)
where
    C: FnOnce(Result<FirewallStatus, UfwError>) + 'static,
{
    run_in_background_thread(
        move || {
            if enable {
                run_pkexec_ufw(&["--force", "enable"])?;
                // Lecture de l'état après activation
                match run_pkexec_ufw(&["status", "numbered"]) {
                    Ok(out) => Ok(parse_ufw_status_output(&out, true)),
                    Err(UfwError::Cancelled) => Ok(FirewallStatus {
                        active: true,
                        ufw_installed: true,
                        ..FirewallStatus::default()
                    }),
                    Err(e) => Err(e),
                }
            } else {
                run_pkexec_ufw(&["disable"])?;
                Ok(FirewallStatus {
                    active: false,
                    ufw_installed: true,
                    ..FirewallStatus::default()
                })
            }
        },
        callback,
    );
}

/// Ajoute une règle UFW (`pkexec ufw allow|deny <port>/<proto>`) puis recharge la liste des règles.
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
            for cmd_args in &commands {
                let refs: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
                run_pkexec_ufw(&refs)?;
            }

            let active = check_systemd_ufw_active();
            match run_pkexec_ufw(&["status", "numbered"]) {
                Ok(out) => Ok(parse_ufw_status_output(&out, active)),
                Err(UfwError::Cancelled) => Ok(FirewallStatus {
                    active,
                    ufw_installed: true,
                    ..FirewallStatus::default()
                }),
                Err(e) => Err(e),
            }
        },
        callback,
    );
}

/// Supprime une règle par son numéro (`pkexec ufw --force delete <numero>`) puis recharge la liste.
pub fn delete_rule_async<C>(rule_number: u32, callback: C)
where
    C: FnOnce(Result<FirewallStatus, UfwError>) + 'static,
{
    run_in_background_thread(
        move || {
            let num_str = rule_number.to_string();
            run_pkexec_ufw(&["--force", "delete", &num_str])?;

            let active = check_systemd_ufw_active();
            match run_pkexec_ufw(&["status", "numbered"]) {
                Ok(out) => Ok(parse_ufw_status_output(&out, active)),
                Err(UfwError::Cancelled) => Ok(FirewallStatus {
                    active,
                    ufw_installed: true,
                    ..FirewallStatus::default()
                }),
                Err(e) => Err(e),
            }
        },
        callback,
    );
}
