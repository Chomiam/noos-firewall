pub mod app;
pub mod logs;
pub mod ufw;
pub mod ui;

use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;

pub const APP_ID: &str = "org.noos.Firewall";

fn main() -> glib::ExitCode {
    let application = adw::Application::builder()
        .application_id(APP_ID)
        .build();

    application.connect_startup(|_| {
        ui::load_css();
        ui::init_icons_and_theme();
    });

    application.connect_activate(|app| {
        let window = app::build_main_window(app);
        window.present();
    });

    application.run()
}
