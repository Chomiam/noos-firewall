use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::logs;
use crate::logs::models::{describe_special_destination, LogEntry};
use crate::ufw;
use crate::ufw::models::{FirewallStatus, Protocol, RuleAction, UfwError};

#[derive(Clone)]
pub struct LogsView {
    pub page: adw::PreferencesPage,
    search_entry: gtk4::SearchEntry,
    refresh_btn: gtk4::Button,
    count_badge: gtk4::Label,
    list_box: gtk4::ListBox,
    entries: Rc<RefCell<Vec<LogEntry>>>,
    toast_overlay: adw::ToastOverlay,
    on_status_updated: Rc<dyn Fn(FirewallStatus)>,
}

impl LogsView {
    pub fn new<F>(toast_overlay: &adw::ToastOverlay, on_status_updated: F) -> Self
    where
        F: Fn(FirewallStatus) + 'static,
    {
        let page = adw::PreferencesPage::new();

        // Groupe de recherche et d'outils
        let controls_group = adw::PreferencesGroup::builder()
            .title("Journaux d'événements (UFW BLOCK)")
            .description(
                "Connexions entrantes bloquées avec résolution du nom de l'appareil et identification du service. Cliquez sur une ligne pour voir les détails complets.",
            )
            .build();

        let header_suffix = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .valign(gtk4::Align::Center)
            .build();

        let count_badge = gtk4::Label::builder()
            .label("0 blocage")
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge-num"])
            .build();

        let refresh_btn = gtk4::Button::builder()
            .child(
                &adw::ButtonContent::builder()
                    .icon_name("view-refresh-symbolic")
                    .label("Actualiser")
                    .build(),
            )
            .tooltip_text("Relire journalctl -k -g \"UFW BLOCK\" -n 150 --output=short-iso")
            .build();

        header_suffix.append(&count_badge);
        header_suffix.append(&refresh_btn);
        controls_group.set_header_suffix(Some(&header_suffix));

        let search_entry = gtk4::SearchEntry::builder()
            .placeholder_text(
                "Rechercher par nom d'appareil, IP, service (ex. SSH, mDNS, KDE Connect), port ou protocole…",
            )
            .hexpand(true)
            .margin_bottom(10)
            .build();
        controls_group.add(&search_entry);

        let list_box = gtk4::ListBox::builder()
            .selection_mode(gtk4::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        controls_group.add(&list_box);

        page.add(&controls_group);

        let view = Self {
            page,
            search_entry: search_entry.clone(),
            refresh_btn: refresh_btn.clone(),
            count_badge,
            list_box,
            entries: Rc::new(RefCell::new(Vec::new())),
            toast_overlay: toast_overlay.clone(),
            on_status_updated: Rc::new(on_status_updated),
        };

        // Filtrage en direct lors de la saisie dans la barre de recherche
        {
            let view_clone = view.clone();
            search_entry.connect_search_changed(move |_| {
                view_clone.render_filtered_rows();
            });
        }

        // Bouton Actualiser
        {
            let view_clone = view.clone();
            refresh_btn.connect_clicked(move |_| {
                view_clone.refresh_logs(true);
            });
        }

        view.render_filtered_rows();
        view
    }

    /// Recharge les logs depuis `journalctl` dans un thread d'arrière-plan.
    pub fn refresh_logs(&self, notify_toast: bool) {
        self.refresh_btn.set_sensitive(false);
        let view_cb = self.clone();

        logs::fetch_logs_async(move |result| {
            view_cb.refresh_btn.set_sensitive(true);
            match result {
                Ok(parsed_entries) => {
                    let total = parsed_entries.len();
                    *view_cb.entries.borrow_mut() = parsed_entries;
                    view_cb.render_filtered_rows();
                    if notify_toast {
                        view_cb.toast_overlay.add_toast(adw::Toast::new(&format!(
                            "Journaux actualisés ({total} événement(s))"
                        )));
                    }
                }
                Err(err_msg) => {
                    view_cb.toast_overlay.add_toast(adw::Toast::new(&err_msg));
                }
            }
        });
    }

    fn render_filtered_rows(&self) {
        while let Some(child) = self.list_box.first_child() {
            self.list_box.remove(&child);
        }

        let query = self.search_entry.text();
        let all_entries = self.entries.borrow();
        let filtered: Vec<&LogEntry> = all_entries
            .iter()
            .filter(|e| e.matches_filter(&query))
            .collect();

        let count = filtered.len();
        self.count_badge.set_label(&if count <= 1 {
            format!("{count} blocage")
        } else {
            format!("{count} blocages")
        });

        if filtered.is_empty() {
            let empty_title = if all_entries.is_empty() {
                "Aucun blocage UFW récent"
            } else {
                "Aucun résultat pour ce filtre"
            };
            let empty_sub = if all_entries.is_empty() {
                "Aucune entrée « UFW BLOCK » n'a été trouvée dans les 150 derniers événements noyau."
            } else {
                "Modifiez votre recherche par nom de machine, IP, service ou port."
            };

            let empty_row = adw::ActionRow::builder()
                .title(empty_title)
                .subtitle(empty_sub)
                .sensitive(false)
                .build();
            empty_row.add_prefix(
                &gtk4::Image::builder()
                    .icon_name("security-high-symbolic")
                    .pixel_size(20)
                    .build(),
            );
            self.list_box.append(&empty_row);
            return;
        }

        for entry in filtered {
            let row = self.build_log_expander_row(entry);
            self.list_box.append(&row);
        }
    }

    fn build_log_expander_row(&self, entry: &LogEntry) -> adw::ExpanderRow {
        let row = adw::ExpanderRow::builder()
            .title(glib::markup_escape_text(&entry.display_main_line()))
            .subtitle(glib::markup_escape_text(&entry.display_subtitle()))
            .build();

        // Préfixe : Badge rouge BLOQUÉ
        let blocked_badge = gtk4::Label::builder()
            .label("BLOQUÉ")
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge", "fw-badge-block"])
            .build();
        row.add_prefix(&blocked_badge);

        // Suffixes : Badge d'origine (Réseau local / Box / Internet) + Badge Protocole (TCP / UDP / IGMP)
        let suffix_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .valign(gtk4::Align::Center)
            .build();

        let origin_badge = gtk4::Label::builder()
            .label(entry.origin.badge_label())
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge", entry.origin.css_class()])
            .build();

        let proto_css = match entry.proto.as_str() {
            "TCP" => "fw-badge-tcp",
            "UDP" => "fw-badge-udp",
            _ => "fw-badge-proto",
        };
        let proto_badge = gtk4::Label::builder()
            .label(&entry.proto)
            .valign(gtk4::Align::Center)
            .css_classes(["fw-badge", proto_css])
            .build();

        suffix_box.append(&origin_badge);
        suffix_box.append(&proto_badge);
        row.add_suffix(&suffix_box);

        // --- Lignes de détails dépliables ---

        // 1. Explication en français clair
        let explanation_row = adw::ActionRow::builder()
            .title("Que signifie ce blocage ?")
            .subtitle(glib::markup_escape_text(&entry.detailed_explanation()))
            .build();
        explanation_row.add_prefix(
            &gtk4::Image::builder()
                .icon_name("dialog-information-symbolic")
                .valign(gtk4::Align::Center)
                .build(),
        );
        row.add_row(&explanation_row);

        // 2. Appareil / Machine source
        let host_detail = match (&entry.src_hostname, &entry.src_vendor, &entry.src_mac) {
            (Some(h), Some(v), Some(m)) => {
                format!("Nom : {h} · Adresse IP : {} · Fabricant : {v} (MAC {m})", entry.src)
            }
            (Some(h), None, Some(m)) => {
                format!("Nom : {h} · Adresse IP : {} · MAC : {m}", entry.src)
            }
            (Some(h), _, None) => format!("Nom : {h} · Adresse IP : {}", entry.src),
            (None, Some(v), Some(m)) => {
                format!(
                    "Nom d'hôte non publié · Adresse IP : {} · Appareil {v} (MAC {m})",
                    entry.src
                )
            }
            (None, None, Some(m)) => {
                format!(
                    "Nom d'hôte non publié · Adresse IP : {} · Adresse MAC : {m}",
                    entry.src
                )
            }
            (None, _, None) => format!(
                "Nom d'hôte non publié · Adresse IP : {} ({})",
                entry.src,
                entry.origin.badge_label()
            ),
        };
        let source_row = adw::ActionRow::builder()
            .title("Appareil source (émetteur)")
            .subtitle(glib::markup_escape_text(&host_detail))
            .build();
        source_row.add_prefix(
            &gtk4::Image::builder()
                .icon_name("computer-symbolic")
                .valign(gtk4::Align::Center)
                .build(),
        );
        row.add_row(&source_row);

        // 3. Flux technique et destination
        let dst_explanation = if let Some(special) = describe_special_destination(&entry.dst) {
            format!("{} ({special})", entry.dst)
        } else {
            format!("{} (votre ordinateur)", entry.dst)
        };
        let tech_subtitle = format!(
            "Flux : {} · Destination : {} · Interface : {}",
            entry.display_technical_flow(),
            dst_explanation,
            entry.interface_in.as_deref().unwrap_or("inconnue")
        );
        let tech_row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&format!(
                "Service visé : {}",
                entry.service_description()
            )))
            .subtitle(glib::markup_escape_text(&tech_subtitle))
            .build();
        tech_row.add_prefix(
            &gtk4::Image::builder()
                .icon_name("network-wired-symbolic")
                .valign(gtk4::Align::Center)
                .build(),
        );

        // Si le paquet cible un port TCP ou UDP précis, proposer un bouton rapide pour l'autoriser
        if let Some(dpt_str) = &entry.dpt {
            let maybe_proto = match entry.proto.as_str() {
                "TCP" => Some(Protocol::Tcp),
                "UDP" => Some(Protocol::Udp),
                _ => None,
            };
            if let Some(protocol) = maybe_proto {
                let allow_btn = gtk4::Button::builder()
                    .label(format!("Autoriser {}/{}", dpt_str, entry.proto))
                    .valign(gtk4::Align::Center)
                    .tooltip_text(format!(
                        "Ajouter une règle UFW pour autoriser le port {}/{}",
                        dpt_str,
                        entry.proto.to_lowercase()
                    ))
                    .css_classes(["suggested-action"])
                    .build();

                let port_to_allow = dpt_str.clone();
                let view_clone = self.clone();
                allow_btn.connect_clicked(move |btn| {
                    btn.set_sensitive(false);
                    let btn_cb = btn.clone();
                    let view_cb = view_clone.clone();
                    let port_copy = port_to_allow.clone();
                    ufw::add_rule_async(
                        port_to_allow.clone(),
                        protocol,
                        RuleAction::Allow,
                        move |res| {
                            btn_cb.set_sensitive(true);
                            match res {
                                Ok(new_status) => {
                                    (view_cb.on_status_updated)(new_status);
                                    view_cb.toast_overlay.add_toast(adw::Toast::new(&format!(
                                        "Port {}/{} autorisé dans UFW",
                                        port_copy,
                                        protocol.label()
                                    )));
                                }
                                Err(UfwError::Cancelled) => {
                                    view_cb.toast_overlay.add_toast(adw::Toast::new(
                                        "Autorisation annulée (authentification Polkit)",
                                    ));
                                }
                                Err(err) => {
                                    view_cb
                                        .toast_overlay
                                        .add_toast(adw::Toast::new(&err.to_string()));
                                }
                            }
                        },
                    );
                });

                tech_row.add_suffix(&allow_btn);
            }
        }

        row.add_row(&tech_row);

        row
    }
}
