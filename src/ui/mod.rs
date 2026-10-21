pub mod logs_view;
pub mod rules_view;
pub mod status_view;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use gtk4::gdk;

pub const APP_LOGO_SVG: &str = include_str!("../../resources/icons/scalable/apps/org.noos.Firewall.svg");

pub const APP_CSS: &str = r#"
.status-hero-box {
    padding: 18px 20px;
    border-radius: 14px;
    transition: all 180ms ease-in-out;
}

.status-hero-active {
    background-color: alpha(@success_bg_color, 0.14);
    border: 1px solid alpha(@success_color, 0.35);
}

.status-hero-inactive {
    background-color: alpha(@error_bg_color, 0.12);
    border: 1px solid alpha(@error_color, 0.30);
}

.status-pill {
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 0.85em;
    font-weight: 700;
}

.status-pill-active {
    background-color: alpha(@success_bg_color, 0.24);
    color: @success_color;
}

.status-pill-inactive {
    background-color: alpha(@error_bg_color, 0.22);
    color: @error_color;
}

.status-dot {
    min-width: 10px;
    min-height: 10px;
    border-radius: 999px;
}

.status-dot-active {
    background-color: @success_color;
}

.status-dot-inactive {
    background-color: @error_color;
}

.fw-badge {
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 0.76em;
    font-weight: 700;
    letter-spacing: 0.03em;
}

.fw-badge-num {
    padding: 2px 8px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.82em;
    font-weight: 700;
    background-color: alpha(@window_fg_color, 0.08);
}

.fw-badge-allow {
    background-color: alpha(@success_bg_color, 0.22);
    color: @success_color;
}

.fw-badge-deny {
    background-color: alpha(@error_bg_color, 0.22);
    color: @error_color;
}

.fw-badge-block {
    background-color: alpha(@error_bg_color, 0.26);
    color: @error_color;
}

.fw-badge-tcp {
    background-color: alpha(@accent_bg_color, 0.22);
    color: @accent_color;
}

.fw-badge-udp {
    background-color: alpha(#9141ac, 0.22);
    color: #c061cb;
}

.fw-badge-proto {
    background-color: alpha(@window_fg_color, 0.12);
    color: @window_fg_color;
}

.fw-badge-local {
    background-color: alpha(@accent_bg_color, 0.15);
    color: @accent_color;
}

.fw-badge-internet {
    background-color: alpha(@warning_bg_color, 0.24);
    color: @warning_color;
}

.fw-badge-dir {
    padding: 2px 7px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.76em;
    font-weight: 600;
    background-color: alpha(@window_fg_color, 0.08);
}

.policy-pill {
    padding: 3px 10px;
    border-radius: 8px;
    font-size: 0.80em;
    font-weight: 600;
    background-color: alpha(@window_fg_color, 0.07);
}
"#;

/// Charge la feuille de style CSS de l'application pour l'affichage actif.
pub fn load_css() {
    let provider = gtk4::CssProvider::new();
    provider.load_from_string(APP_CSS);

    if let Some(display) = gdk::Display::default() {
        gtk4::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

/// Installe l'icône SVG et l'entrée `.desktop` utilisateur si nécessaire et configure `IconTheme`.
pub fn init_icons_and_theme() {
    // Respect natif du mode sombre/clair via adw::StyleManager
    let style_manager = libadwaita::StyleManager::default();
    style_manager.set_color_scheme(libadwaita::ColorScheme::Default);

    let mut user_icon_dir: Option<PathBuf> = None;

    if let Some(home_os) = env::var_os("HOME") {
        let home = PathBuf::from(home_os);
        let icon_dir = home
            .join(".local")
            .join("share")
            .join("icons")
            .join("hicolor")
            .join("scalable")
            .join("apps");
        if fs::create_dir_all(&icon_dir).is_ok() {
            let icon_path = icon_dir.join("org.noos.Firewall.svg");
            let _ = fs::write(&icon_path, APP_LOGO_SVG);
            user_icon_dir = Some(icon_dir);
        }

        if !Path::new("/usr/share/applications/org.noos.Firewall.desktop").exists() {
            let apps_dir = home.join(".local").join("share").join("applications");
            if fs::create_dir_all(&apps_dir).is_ok() {
                let exec_cmd = env::current_exe()
                    .ok()
                    .and_then(|p| p.to_str().map(|s| format!("\"{s}\"")))
                    .unwrap_or_else(|| String::from("noos-firewall"));
                let desktop_content = format!(
                    "[Desktop Entry]\n\
                     Type=Application\n\
                     Version=1.0\n\
                     Name=Pare-feu\n\
                     Name[fr]=Pare-feu\n\
                     GenericName=Pare-feu UFW\n\
                     Comment=Gestion graphique native et moderne du pare-feu UFW sur Arch Linux\n\
                     Exec={exec_cmd}\n\
                     Icon=org.noos.Firewall\n\
                     Terminal=false\n\
                     Categories=System;Security;Network;GTK;GNOME;\n\
                     Keywords=firewall;ufw;pare-feu;securite;reseau;ports;noos;\n\
                     StartupNotify=true\n\
                     StartupWMClass=org.noos.Firewall\n"
                );
                let _ = fs::write(apps_dir.join("org.noos.Firewall.desktop"), desktop_content);
            }
        }
    }

    if let Some(display) = gdk::Display::default() {
        let icon_theme = gtk4::IconTheme::for_display(&display);
        if let Some(dir) = user_icon_dir {
            icon_theme.add_search_path(&dir);
        }
        let repo_icons = Path::new("/home/chomiam/Projets/noos-firewall/resources/icons");
        if repo_icons.is_dir() {
            icon_theme.add_search_path(repo_icons);
        }

        if icon_theme.has_icon("org.noos.Firewall") {
            gtk4::Window::set_default_icon_name("org.noos.Firewall");
        } else {
            gtk4::Window::set_default_icon_name("security-high-symbolic");
        }
    }
}
