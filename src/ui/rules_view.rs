use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::ufw;
use crate::ufw::cli::validate_port_spec;
use crate::ufw::models::{FirewallStatus, Protocol, Rule, RuleAction, UfwError};

#[derive(Clone)]
pub struct RulesView {
    pub group: adw::PreferencesGroup,
    list_box: gtk4::ListBox,
    add_btn: gtk4::Button,
    refresh_btn: gtk4::Button,
    parent_widget: gtk4::Widget,
    toast_overlay: adw::ToastOverlay,
    on_status_updated: Rc<dyn Fn(FirewallStatus)>,
    current_rules: Rc<RefCell<Vec<Rule>>>,
}

impl RulesView {
    pub fn new<W, F>(
        parent_window: &W,
        toast_overlay: &adw::ToastOverlay,
        on_status_updated: F,
    ) -> Self
    where
        W: IsA<gtk4::Widget>,
        F: Fn(FirewallStatus) + 'static,
    {
        let group = adw::PreferencesGroup::builder()
            .title("Ports & Règles du Pare-feu")
            .description("Règles actives issues de « ufw status numbered »")
            .build();

        let header_actions = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .valign(gtk4::Align::Center)
            .build();

        let refresh_btn = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text("Lire les règles numérotées (pkexec ufw status numbered)")
            .css_classes(["flat"])
            .build();

        let add_btn = gtk4::Button::builder()
            .child(
                &adw::ButtonContent::builder()
                    .icon_name("list-add-symbolic")
                    .label("Ajouter une règle")
                    .build(),
            )
            .tooltip_text("Ouvrir ou bloquer un port ou une plage de ports")
            .css_classes(["suggested-action"])
            .build();

        header_actions.append(&refresh_btn);
        header_actions.append(&add_btn);
        group.set_header_suffix(Some(&header_actions));

        let list_box = gtk4::ListBox::builder()
            .selection_mode(gtk4::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        group.add(&list_box);

        let view = Self {
            group,
            list_box,
            add_btn: add_btn.clone(),
            refresh_btn: refresh_btn.clone(),
            parent_widget: parent_window.clone().upcast::<gtk4::Widget>(),
            toast_overlay: toast_overlay.clone(),
            on_status_updated: Rc::new(on_status_updated),
            current_rules: Rc::new(RefCell::new(Vec::new())),
        };

        // Action bouton "Ajouter une règle"
        {
            let view_clone = view.clone();
            add_btn.connect_clicked(move |_| {
                view_clone.open_add_rule_dialog();
            });
        }

        // Action bouton "Actualiser"
        {
            let view_clone = view.clone();
            refresh_btn.connect_clicked(move |_| {
                view_clone.reload_rules_from_ufw();
            });
        }

        view.render_empty_state(false, false);
        view
    }

    pub fn reload_rules_from_ufw(&self) {
        self.refresh_btn.set_sensitive(false);
        let view_cb = self.clone();
        ufw::fetch_status_async(true, move |result| {
            view_cb.refresh_btn.set_sensitive(true);
            match result {
                Ok(status) => {
                    let count = status.rules.len();
                    (view_cb.on_status_updated)(status);
                    view_cb.toast_overlay.add_toast(adw::Toast::new(&format!(
                        "{count} règle(s) chargée(s)"
                    )));
                }
                Err(UfwError::Cancelled) => {
                    view_cb.toast_overlay.add_toast(adw::Toast::new(
                        "Lecture des règles annulée (Polkit)",
                    ));
                }
                Err(err) => {
                    view_cb
                        .toast_overlay
                        .add_toast(adw::Toast::new(&err.to_string()));
                }
            }
        });
    }

    pub fn apply_status(&self, status: &FirewallStatus) {
        *self.current_rules.borrow_mut() = status.rules.clone();
        self.add_btn.set_sensitive(status.ufw_installed);
        self.refresh_btn.set_sensitive(status.ufw_installed);

        while let Some(child) = self.list_box.first_child() {
            self.list_box.remove(&child);
        }

        if status.rules.is_empty() {
            self.render_empty_state(status.active, true);
            return;
        }

        for rule in &status.rules {
            let row = self.build_rule_row(rule);
            self.list_box.append(&row);
        }
    }

    fn render_empty_state(&self, firewall_active: bool, loaded: bool) {
        while let Some(child) = self.list_box.first_child() {
            self.list_box.remove(&child);
        }

        let subtitle = if !firewall_active {
            "Activez le pare-feu ou cliquez sur « Ajouter une règle » pour configurer vos ports."
        } else if loaded {
            "Aucune règle personnalisée. Cliquez sur « Actualiser » (icône ↻) pour lire « ufw status numbered » ou ajoutez une règle."
        } else {
            "Cliquez sur le bouton d'actualisation (↻) pour charger les règles numérotées ou ajoutez un port."
        };

        let empty_row = adw::ActionRow::builder()
            .title("Aucune règle affichée")
            .subtitle(subtitle)
            .sensitive(false)
            .build();
        empty_row.add_prefix(
            &gtk4::Image::builder()
                .icon_name("network-transmit-receive-symbolic")
                .pixel_size(20)
                .build(),
        );
        self.list_box.append(&empty_row);
    }

    fn build_rule_row(&self, rule: &Rule) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(rule.display_target())
            .subtitle(rule.display_subtitle())
            .build();

        // Préfixe : Numéro de règle (#1, #2, ...)
        let num_badge = gtk4::Label::builder()
            .label(format!("#{}", rule.number))
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge-num"])
            .tooltip_text(format!("Règle UFW numéro {}", rule.number))
            .build();
        row.add_prefix(&num_badge);

        // Suffixes : Badges Protocole, Direction, Action + Bouton Corbeille
        let suffix_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .valign(gtk4::Align::Center)
            .build();

        let proto_css = match rule.protocol {
            Protocol::Tcp => "fw-badge-tcp",
            Protocol::Udp => "fw-badge-udp",
            Protocol::Both => "fw-badge-proto",
        };
        let proto_badge = gtk4::Label::builder()
            .label(rule.protocol.label())
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge", proto_css])
            .build();

        let dir_badge = gtk4::Label::builder()
            .label(rule.direction.badge_label())
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge-dir"])
            .build();

        let action_css = if rule.action.is_allow() {
            "fw-badge-allow"
        } else {
            "fw-badge-deny"
        };
        let action_badge = gtk4::Label::builder()
            .label(rule.action.badge_label())
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge", action_css])
            .build();

        let delete_btn = gtk4::Button::builder()
            .icon_name("user-trash-symbolic")
            .valign(gtk4::Align::Center)
            .tooltip_text(format!("Supprimer la règle #{}", rule.number))
            .css_classes(["flat", "destructive-action"])
            .build();

        suffix_box.append(&proto_badge);
        suffix_box.append(&dir_badge);
        suffix_box.append(&action_badge);
        suffix_box.append(&delete_btn);

        row.add_suffix(&suffix_box);

        let view_clone = self.clone();
        let rule_clone = rule.clone();
        delete_btn.connect_clicked(move |_| {
            view_clone.confirm_delete_rule(&rule_clone);
        });

        row
    }

    fn confirm_delete_rule(&self, rule: &Rule) {
        let dialog = adw::AlertDialog::builder()
            .heading("Supprimer cette règle ?")
            .body(format!(
                "Voulez-vous vraiment supprimer la règle #{} ({} — {} {}) ?\n\nCommande exécutée : pkexec ufw --force delete {}",
                rule.number,
                rule.display_target(),
                rule.action.badge_label(),
                rule.protocol.label(),
                rule.number
            ))
            .default_response("cancel")
            .close_response("cancel")
            .build();

        dialog.add_response("cancel", "Annuler");
        dialog.add_response("delete", "Supprimer");
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);

        let view_clone = self.clone();
        let rule_num = rule.number;
        dialog.connect_response(Some("delete"), move |_, _| {
            view_clone.execute_delete_rule(rule_num);
        });

        dialog.present(Some(&self.parent_widget));
    }

    fn execute_delete_rule(&self, rule_number: u32) {
        self.refresh_btn.set_sensitive(false);
        let view_cb = self.clone();
        ufw::delete_rule_async(rule_number, move |result| {
            view_cb.refresh_btn.set_sensitive(true);
            match result {
                Ok(status) => {
                    (view_cb.on_status_updated)(status);
                    view_cb.toast_overlay.add_toast(adw::Toast::new(&format!(
                        "Règle #{rule_number} supprimée avec succès"
                    )));
                }
                Err(UfwError::Cancelled) => {
                    view_cb.toast_overlay.add_toast(adw::Toast::new(
                        "Suppression annulée (authentification Polkit)",
                    ));
                }
                Err(err) => {
                    view_cb
                        .toast_overlay
                        .add_toast(adw::Toast::new(&err.to_string()));
                }
            }
        });
    }

    fn open_add_rule_dialog(&self) {
        let dialog = adw::Dialog::builder()
            .title("Nouvelle règle de pare-feu")
            .content_width(440)
            .build();

        let toolbar_view = adw::ToolbarView::new();
        let header = adw::HeaderBar::builder()
            .show_start_title_buttons(false)
            .show_end_title_buttons(false)
            .build();

        let cancel_btn = gtk4::Button::builder().label("Annuler").build();
        let submit_btn = gtk4::Button::builder()
            .label("Ajouter")
            .css_classes(["suggested-action"])
            .build();

        header.pack_start(&cancel_btn);
        header.pack_end(&submit_btn);
        toolbar_view.add_top_bar(&header);

        let content_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(16)
            .margin_top(16)
            .margin_bottom(20)
            .margin_start(18)
            .margin_end(18)
            .build();

        let form_group = adw::PreferencesGroup::builder()
            .title("Paramètres de la règle")
            .description("Saisissez un port unique (ex. 22, 80, 8080) ou une plage de ports (ex. 1714:1764).")
            .build();

        let port_entry = adw::EntryRow::builder()
            .title("Port ou plage (1–65535)")
            .text("80")
            .build();
        form_group.add(&port_entry);

        let proto_model = gtk4::StringList::new(&["TCP", "UDP", "Les deux (TCP + UDP)"]);
        let proto_row = adw::ComboRow::builder()
            .title("Protocole")
            .subtitle("Protocole de transport ciblé")
            .model(&proto_model)
            .selected(0)
            .build();
        form_group.add(&proto_row);

        let action_model = gtk4::StringList::new(&["Autoriser (ALLOW)", "Bloquer (DENY)"]);
        let action_row = adw::ComboRow::builder()
            .title("Action")
            .subtitle("Comportement du pare-feu pour ce trafic")
            .model(&action_model)
            .selected(0)
            .build();
        form_group.add(&action_row);

        content_box.append(&form_group);

        let preview_label = gtk4::Label::builder()
            .label("Commande : pkexec ufw allow 80/tcp")
            .xalign(0.0)
            .wrap(true)
            .css_classes(["dim-label", "caption"])
            .build();
        content_box.append(&preview_label);

        let validation_label = gtk4::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .visible(false)
            .css_classes(["error"])
            .build();
        content_box.append(&validation_label);

        toolbar_view.set_content(Some(&content_box));
        dialog.set_child(Some(&toolbar_view));

        let update_validation = {
            let port_entry = port_entry.clone();
            let proto_row = proto_row.clone();
            let action_row = action_row.clone();
            let submit_btn = submit_btn.clone();
            let validation_label = validation_label.clone();
            let preview_label = preview_label.clone();

            Rc::new(move || {
                let raw = port_entry.text();
                let proto = Protocol::from_dropdown_index(proto_row.selected());
                let action = RuleAction::from_dropdown_index(action_row.selected());

                match validate_port_spec(&raw) {
                    Ok(valid_port) => {
                        validation_label.set_visible(false);
                        submit_btn.set_sensitive(true);
                        let cmd_preview = match proto.cli_suffix() {
                            Some(suffix) => {
                                format!("Commande : pkexec ufw {} {valid_port}/{suffix}", action.cli_arg())
                            }
                            None if valid_port.contains(':') => {
                                format!(
                                    "Commandes : pkexec ufw {0} {valid_port}/tcp (+ /udp)",
                                    action.cli_arg()
                                )
                            }
                            None => format!("Commande : pkexec ufw {} {valid_port}", action.cli_arg()),
                        };
                        preview_label.set_label(&cmd_preview);
                    }
                    Err(err) => {
                        validation_label.set_label(&err.to_string());
                        validation_label.set_visible(true);
                        submit_btn.set_sensitive(false);
                    }
                }
            })
        };

        {
            let upd = Rc::clone(&update_validation);
            port_entry.connect_changed(move |_| upd());
        }
        {
            let upd = Rc::clone(&update_validation);
            proto_row.connect_selected_notify(move |_| upd());
        }
        {
            let upd = Rc::clone(&update_validation);
            action_row.connect_selected_notify(move |_| upd());
        }

        {
            let dlg = dialog.clone();
            cancel_btn.connect_clicked(move |_| {
                dlg.close();
            });
        }

        {
            let dlg = dialog.clone();
            let view_clone = self.clone();
            let port_entry = port_entry.clone();
            let proto_row = proto_row.clone();
            let action_row = action_row.clone();

            submit_btn.connect_clicked(move |btn| {
                let port_text = port_entry.text().to_string();
                let protocol = Protocol::from_dropdown_index(proto_row.selected());
                let action = RuleAction::from_dropdown_index(action_row.selected());

                if validate_port_spec(&port_text).is_err() {
                    return;
                }

                btn.set_sensitive(false);
                dlg.close();

                let view_cb = view_clone.clone();
                ufw::add_rule_async(port_text.clone(), protocol, action, move |result| {
                    match result {
                        Ok(status) => {
                            (view_cb.on_status_updated)(status);
                            view_cb.toast_overlay.add_toast(adw::Toast::new(&format!(
                                "Règle ajoutée : {} {} ({})",
                                action.french_label(),
                                port_text.trim(),
                                protocol.label()
                            )));
                        }
                        Err(UfwError::Cancelled) => {
                            view_cb.toast_overlay.add_toast(adw::Toast::new(
                                "Ajout de règle annulé (authentification Polkit)",
                            ));
                        }
                        Err(err) => {
                            view_cb
                                .toast_overlay
                                .add_toast(adw::Toast::new(&err.to_string()));
                        }
                    }
                });
            });
        }

        dialog.present(Some(&self.parent_widget));
    }
}
