use std::cell::Cell;
use std::rc::Rc;

use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::ufw;
use crate::ufw::models::{FirewallStatus, UfwError};

#[derive(Clone)]
pub struct StatusView {
    pub group: adw::PreferencesGroup,
    hero_box: gtk4::Box,
    shield_icon: gtk4::Image,
    status_dot: gtk4::Box,
    status_badge_label: gtk4::Label,
    status_badge_box: gtk4::Box,
    action_row: adw::ActionRow,
    switch: gtk4::Switch,
    spinner: gtk4::Spinner,
    incoming_policy_label: gtk4::Label,
    outgoing_policy_label: gtk4::Label,
    programmatic_guard: Rc<Cell<bool>>,
    current_active: Rc<Cell<bool>>,
}

impl StatusView {
    pub fn new<F>(on_status_changed: F, toast_overlay: &adw::ToastOverlay) -> Self
    where
        F: Fn(FirewallStatus) + 'static,
    {
        let group = adw::PreferencesGroup::builder()
            .title("Contrôle du Pare-feu")
            .description("Protection réseau système gérée par UFW (Uncomplicated Firewall)")
            .build();

        // Bandeau visuel d'état (Hero Card)
        let hero_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(16)
            .margin_bottom(10)
            .css_classes(["status-hero-box", "status-hero-inactive"])
            .build();

        let shield_icon = gtk4::Image::builder()
            .icon_name("security-low-symbolic")
            .pixel_size(42)
            .valign(gtk4::Align::Center)
            .build();
        hero_box.append(&shield_icon);

        let text_col = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(6)
            .hexpand(true)
            .valign(gtk4::Align::Center)
            .build();

        let top_badge_row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(10)
            .valign(gtk4::Align::Center)
            .build();

        let status_badge_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .valign(gtk4::Align::Center)
            .css_classes(["status-pill", "status-pill-inactive"])
            .build();

        let status_dot = gtk4::Box::builder()
            .valign(gtk4::Align::Center)
            .css_classes(["status-dot", "status-dot-inactive"])
            .build();

        let status_badge_label = gtk4::Label::builder()
            .label("Désactivé")
            .build();

        status_badge_box.append(&status_dot);
        status_badge_box.append(&status_badge_label);
        top_badge_row.append(&status_badge_box);

        let spinner = gtk4::Spinner::builder()
            .spinning(false)
            .visible(false)
            .valign(gtk4::Align::Center)
            .build();
        top_badge_row.append(&spinner);

        text_col.append(&top_badge_row);

        let policies_row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();

        let incoming_policy_label = gtk4::Label::builder()
            .label("Entrée par défaut : Bloquée")
            .css_classes(["policy-pill"])
            .build();

        let outgoing_policy_label = gtk4::Label::builder()
            .label("Sortie par défaut : Autorisée")
            .css_classes(["policy-pill"])
            .build();

        policies_row.append(&incoming_policy_label);
        policies_row.append(&outgoing_policy_label);
        text_col.append(&policies_row);

        hero_box.append(&text_col);
        group.set_header_suffix(None::<&gtk4::Widget>);

        let hero_row = adw::PreferencesRow::builder()
            .activatable(false)
            .focusable(false)
            .child(&hero_box)
            .build();
        group.add(&hero_row);

        // Ligne d'action principale avec l'interrupteur
        let switch = gtk4::Switch::builder()
            .valign(gtk4::Align::Center)
            .tooltip_text("Activer ou désactiver le pare-feu UFW (authentification Polkit)")
            .build();

        let action_row = adw::ActionRow::builder()
            .title("État du pare-feu UFW")
            .subtitle("Le pare-feu est actuellement désactivé. Activez-le pour filtrer les connexions entrantes.")
            .activatable_widget(&switch)
            .build();
        action_row.add_suffix(&switch);
        group.add(&action_row);

        let programmatic_guard = Rc::new(Cell::new(false));
        let current_active = Rc::new(Cell::new(false));

        let view = Self {
            group,
            hero_box,
            shield_icon,
            status_dot,
            status_badge_label,
            status_badge_box,
            action_row,
            switch: switch.clone(),
            spinner,
            incoming_policy_label,
            outgoing_policy_label,
            programmatic_guard: Rc::clone(&programmatic_guard),
            current_active: Rc::clone(&current_active),
        };

        let view_for_signal = view.clone();
        let toast_for_signal = toast_overlay.clone();
        let on_status_changed = Rc::new(on_status_changed);

        switch.connect_state_set(move |_sw, desired_state| {
            if view_for_signal.programmatic_guard.get() {
                return glib::Propagation::Proceed;
            }

            let previous_state = view_for_signal.current_active.get();
            view_for_signal.set_busy(true);

            let view_cb = view_for_signal.clone();
            let toast_cb = toast_for_signal.clone();
            let cb_changed = Rc::clone(&on_status_changed);

            ufw::set_enabled_async(desired_state, move |result| {
                view_cb.set_busy(false);
                match result {
                    Ok(new_status) => {
                        view_cb.apply_status(&new_status);
                        let msg = if new_status.active {
                            "Pare-feu activé — système protégé"
                        } else {
                            "Pare-feu désactivé"
                        };
                        toast_cb.add_toast(adw::Toast::new(msg));
                        cb_changed(new_status);
                    }
                    Err(UfwError::Cancelled) => {
                        // L'utilisateur a annulé la popup Polkit : restauration de l'état réel sans erreur
                        view_cb.set_switch_silently(previous_state);
                        toast_cb.add_toast(adw::Toast::new(
                            "Authentification annulée — l'état du pare-feu est inchangé",
                        ));
                    }
                    Err(err) => {
                        view_cb.set_switch_silently(previous_state);
                        toast_cb.add_toast(adw::Toast::new(&err.to_string()));
                    }
                }
            });

            // On contrôle manuellement l'état visuel du switch une fois pkexec terminé
            glib::Propagation::Stop
        });

        view
    }

    pub fn set_busy(&self, busy: bool) {
        self.switch.set_sensitive(!busy);
        self.spinner.set_visible(busy);
        self.spinner.set_spinning(busy);
    }

    pub fn set_switch_silently(&self, active: bool) {
        self.programmatic_guard.set(true);
        self.switch.set_active(active);
        self.switch.set_state(active);
        self.programmatic_guard.set(false);
    }

    pub fn apply_status(&self, status: &FirewallStatus) {
        self.current_active.set(status.active);
        self.set_switch_silently(status.active);

        self.incoming_policy_label
            .set_label(&format!("Entrée par défaut : {}", status.default_incoming));
        self.outgoing_policy_label
            .set_label(&format!("Sortie par défaut : {}", status.default_outgoing));

        if !status.ufw_installed {
            self.shield_icon.set_icon_name(Some("dialog-warning-symbolic"));
            self.status_badge_label.set_label("UFW non installé");
            self.action_row.set_subtitle(
                "Le paquet « ufw » est introuvable. Installez-le avec : sudo pacman -S ufw",
            );
            self.switch.set_sensitive(false);
            return;
        }

        if status.active {
            self.hero_box.remove_css_class("status-hero-inactive");
            self.hero_box.add_css_class("status-hero-active");

            self.status_badge_box.remove_css_class("status-pill-inactive");
            self.status_badge_box.add_css_class("status-pill-active");

            self.status_dot.remove_css_class("status-dot-inactive");
            self.status_dot.add_css_class("status-dot-active");

            self.shield_icon.set_icon_name(Some("security-high-symbolic"));
            self.status_badge_label.set_label("Protégé (Actif)");
            self.action_row.set_subtitle(
                "Le pare-feu UFW filtre activement le trafic réseau selon vos règles.",
            );
        } else {
            self.hero_box.remove_css_class("status-hero-active");
            self.hero_box.add_css_class("status-hero-inactive");

            self.status_badge_box.remove_css_class("status-pill-active");
            self.status_badge_box.add_css_class("status-pill-inactive");

            self.status_dot.remove_css_class("status-dot-active");
            self.status_dot.add_css_class("status-dot-inactive");

            self.shield_icon.set_icon_name(Some("security-low-symbolic"));
            self.status_badge_label.set_label("Désactivé");
            self.action_row.set_subtitle(
                "Le pare-feu est actuellement désactivé. Activez-le pour filtrer les connexions entrantes.",
            );
        }
    }
}
