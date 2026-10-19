//! `rescue-gui`: one window, five steps. This skeleton proves the three
//! desktop builds; the steps arrive with the core's `Flow`.

struct RescueApp;

impl eframe::App for RescueApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Winnow Rescue");
            ui.label(format!("version {}", rescue_core::VERSION));
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([520.0, 360.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Winnow Rescue",
        options,
        Box::new(|_| Ok(Box::new(RescueApp))),
    )
}
