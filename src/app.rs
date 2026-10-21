use std::cell::RefCell;
use std::rc::Rc;

use libadwaita as adw;
use libadwaita::prelude::*;

use crate::ufw;
use crate::ufw::models::FirewallStatus;
use crate::ui::logs_view::LogsView;
use crate::ui::rules_view::RulesView;
use crate::ui::status_view::StatusView;

pub fn build_main_window(app: &adw::Application) -> adw::ApplicationWindow {
    let toast_overlay = adw::ToastOverlay::new();
    let toolbar_view = adw::ToolbarView::new();

    let view_stack = adw::ViewStack::builder()
        .vexpand(true)
        .hexpand(true)
        .build();

    let view_switcher = adw::ViewSwitcher::builder()
        .stack(&view_stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build();

    let header_bar = adw::HeaderBar::builder()
        .title_widget(&view_switcher)
        .build();
    toolbar_view.add_top_bar(&header_bar);

    let switcher_bar = adw::ViewSwitcherBar::builder()
        .stack(&view_stack)
        .reveal(false)
        .build();
    toolbar_view.add_bottom_bar(&switcher_bar);

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Pare-feu")
        .icon_name("org.noos.Firewall")
        .default_width(880)
        .default_height(680)
        .width_request(420)
        .height_request(480)
        .content(&toast_overlay)
        .build();

    // Vue 1 : État & Règles
    let status_rules_page = adw::PreferencesPage::new();

    let rules_view_holder: Rc<RefCell<Option<RulesView>>> = Rc::new(RefCell::new(None));
    let status_view_holder: Rc<RefCell<Option<StatusView>>> = Rc::new(RefCell::new(None));

    let status_view = {
        let rules_holder = Rc::clone(&rules_view_holder);
        StatusView::new(
            move |new_status: FirewallStatus| {
                if let Some(rv) = rules_holder.borrow().as_ref() {
                    rv.apply_status(&new_status);
                }
            },
            &toast_overlay,
        )
    };
    *status_view_holder.borrow_mut() = Some(status_view.clone());

    let rules_view = {
        let status_holder = Rc::clone(&status_view_holder);
        let rules_holder = Rc::clone(&rules_view_holder);
        RulesView::new(&window, &toast_overlay, move |new_status: FirewallStatus| {
            if let Some(sv) = status_holder.borrow().as_ref() {
                sv.apply_status(&new_status);
            }
            if let Some(rv) = rules_holder.borrow().as_ref() {
                rv.apply_status(&new_status);
            }
        })
    };
    *rules_view_holder.borrow_mut() = Some(rules_view.clone());

    status_rules_page.add(&status_view.group);
    status_rules_page.add(&rules_view.group);

    view_stack.add_titled_with_icon(
        &status_rules_page,
        Some("status_rules"),
        "État & Règles",
        "security-high-symbolic",
    );

    // Vue 2 : Blocages récents (Journaux d'événements)
    let logs_view = {
        let status_holder = Rc::clone(&status_view_holder);
        let rules_holder = Rc::clone(&rules_view_holder);
        LogsView::new(&toast_overlay, move |new_status: FirewallStatus| {
            if let Some(sv) = status_holder.borrow().as_ref() {
                sv.apply_status(&new_status);
            }
            if let Some(rv) = rules_holder.borrow().as_ref() {
                rv.apply_status(&new_status);
            }
        })
    };
    view_stack.add_titled_with_icon(
        &logs_view.page,
        Some("logs"),
        "Blocages récents",
        "view-list-symbolic",
    );

    // Rafraîchissement automatique des logs à l'ouverture de l'onglet "Blocages récents"
    {
        let logs_view_clone = logs_view.clone();
        view_stack.connect_visible_child_name_notify(move |stack| {
            if stack.visible_child_name().as_deref() == Some("logs") {
                logs_view_clone.refresh_logs(false);
            }
        });
    }

    toolbar_view.set_content(Some(&view_stack));
    toast_overlay.set_child(Some(&toolbar_view));

    // Chargement initial non-bloquant de l'état UFW et des journaux
    {
        let sv = status_view.clone();
        let rv = rules_view.clone();
        ufw::fetch_status_async(true, move |res| {
            if let Ok(initial_status) = res {
                sv.apply_status(&initial_status);
                rv.apply_status(&initial_status);
            }
        });

        logs_view.refresh_logs(false);
    }

    window
}
