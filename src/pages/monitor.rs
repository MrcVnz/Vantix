//! The Monitor page on screen: the sample, the program list with its search and the row
//! opened on its processes, and the buttons of each row.

use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::{
    App, AppWindow, Feature, GpuCard, MONITOR_PAGE, Monitor, ProcessRow, ProgramRow, State, bind, bind_with,
    bind_with2, format_bytes, format_ghz, format_percent, format_speed, monitor, services, spark_paths,
};

/// The line a Monitor row shows after one of its buttons.
pub enum RowNote {
    Ending,
    Ended(monitor::EndOutcome),
    Stopping,
    Stopped,
    /// Stopped, and Windows started it again straight away.
    CameBack,
    StopFailed,
}

impl App {
    pub(crate) fn connect_monitor(self: &Rc<Self>, ui: &AppWindow) {
        let page = ui.global::<Monitor>();
        page.set_sort(monitor::sort() as i32);
        page.on_sorted(|key| {
            monitor::set_sort(match key {
                1 => monitor::Sort::Gpu,
                2 => monitor::Sort::Memory,
                _ => monitor::Sort::Cpu,
            })
        });
        // A search or a row opened shows at once, from the last sample.
        page.on_refilter(bind(self, |app| {
            let Some(snapshot) = monitor::snapshot() else { return };
            let mut state = app.state.borrow_mut();
            app.with_ui(|ui| show_programs(ui, &snapshot.programs, &mut state));
        }));
        page.on_end(bind_with(self, |app, i: i32| app.end_program(i)));
        page.on_stop_service(bind_with(self, |app, i: i32| app.stop_service(i)));
        page.on_eco(bind_with2(self, |app, i: i32, on: bool| {
            app.on_program(i, move |p| {
                monitor::set_eco(&p.name, &p.pids(), on);
            })
        }));
        page.on_trim(bind_with(self, |app, i: i32| {
            app.on_program(i, |p| {
                monitor::trim(&p.name, &p.pids());
            })
        }));
    }

    /// Samples only while the Monitor page is on screen.
    pub(crate) fn tick_monitor(&self) {
        let open = self.with_ui_value(|ui| ui.get_page() == MONITOR_PAGE).unwrap_or(false);
        if !open {
            monitor::unwatch();
            return;
        }
        monitor::watch();
        let snapshot = monitor::snapshot();
        let mut state = self.state.borrow_mut();
        self.with_ui(|ui| show(ui, snapshot.as_ref(), &mut state));
    }

    /// Runs a button of the Monitor page on its row's processes, off the UI thread. The
    /// next sample shows the result.
    fn on_program(self: &Rc<Self>, i: i32, f: impl FnOnce(&monitor::Program) + Send + 'static) {
        let Some(program) = self.state.borrow().programs.get(i as usize).cloned() else { return };
        self.run_job(move || f(&program), |_, _| {});
    }

    /// Ending takes about two seconds, since it goes back to see whether the program is
    /// really gone, so the row says "Ending..." meanwhile and then what happened.
    fn end_program(self: &Rc<Self>, i: i32) {
        let Some(program) = self.state.borrow().programs.get(i as usize).cloned() else { return };
        let name = program.name.clone();
        self.state.borrow_mut().ended = Some((name.clone(), RowNote::Ending, Instant::now()));
        self.tick_monitor();
        let ending = name.clone();
        self.run_job(
            move || monitor::end(&ending),
            move |app, outcome| {
                {
                    let mut state = app.state.borrow_mut();
                    // End may have been pressed on another row meanwhile, and that row
                    // owns the line now.
                    let mine = state
                        .ended
                        .as_ref()
                        .is_some_and(|(row, note, _)| *row == name && matches!(note, RowNote::Ending));
                    if mine {
                        state.ended =
                            outcome.map(|outcome| (name.clone(), RowNote::Ended(outcome), Instant::now()));
                    }
                }
                app.tick_monitor();
            },
        );
    }

    /// End found a service behind the program, so the row offers to stop the service
    /// instead. Like Stop on the Services page, nothing is written down: how the service
    /// starts doesn't change, and it runs again the next time something asks for it.
    fn stop_service(self: &Rc<Self>, i: i32) {
        let (name, names) = {
            let state = self.state.borrow();
            let Some(program) = state.programs.get(i as usize) else { return };
            match &state.ended {
                Some((row, RowNote::Ended(monitor::EndOutcome::Service { names, .. }), _))
                    if *row == program.name =>
                {
                    (program.name.clone(), names.clone())
                }
                _ => return,
            }
        };
        if names.iter().any(|service| services::blocked(service).is_some()) {
            return;
        }
        self.state.borrow_mut().ended = Some((name.clone(), RowNote::Stopping, Instant::now()));
        self.tick_monitor();
        let stopping = names.clone();
        self.run_job(
            move || {
                stopping
                    .iter()
                    .map(|service| services::run(service, false))
                    .collect::<windows::core::Result<Vec<bool>>>()
            },
            move |app, result| {
                {
                    let mut state = app.state.borrow_mut();
                    if let Some(Ok(running)) = &result {
                        for (service, &on) in names.iter().zip(running) {
                            if let Some(known) = state.services.iter_mut().find(|s| s.name == *service) {
                                known.running = on;
                            }
                        }
                    }
                    let mine = state
                        .ended
                        .as_ref()
                        .is_some_and(|(row, note, _)| *row == name && matches!(note, RowNote::Stopping));
                    if mine {
                        let note = match result {
                            Some(Ok(running)) if running.contains(&true) => RowNote::CameBack,
                            Some(Ok(_)) => RowNote::Stopped,
                            _ => RowNote::StopFailed,
                        };
                        state.ended = Some((name.clone(), note, Instant::now()));
                    }
                }
                app.tick_monitor();
            },
        );
    }
}

fn show(ui: &AppWindow, snapshot: Option<&monitor::Snapshot>, state: &mut State) {
    let m = ui.global::<Monitor>();
    // The facts cost nothing to read, so they're on screen before the first sample.
    if m.get_cpu_name().is_empty() {
        let info = monitor::cpu_info();
        m.set_cpu_name(info.name.as_str().into());
        m.set_cpu_cores(info.cores.to_string().into());
        m.set_cpu_threads(info.threads.to_string().into());
        m.set_cpu_hybrid(
            match info.performance {
                0 => String::new(),
                performance => format!("{} + {}", performance, info.cores.saturating_sub(performance)),
            }
            .into(),
        );
        m.set_cpu_base(format_ghz(f64::from(info.base_mhz)).into());
        m.set_cpu_l3(format_bytes(info.l3).into());
        let features: Vec<Feature> = info
            .features
            .iter()
            .map(|&kind| Feature { text: monitor::FEATURES[kind].into(), kind: kind as i32 })
            .collect();
        m.set_features(ModelRc::new(VecModel::from(features)));
        let cards: Vec<GpuCard> = monitor::adapters()
            .iter()
            .map(|card| GpuCard {
                name: card.name.as_str().into(),
                driver: [card.driver.as_str(), card.wddm.as_str()]
                    .iter()
                    .filter(|part| !part.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" · ")
                    .into(),
                memory: format!("- / {}", format_bytes(card.memory)).into(),
                ..Default::default()
            })
            .collect();
        m.set_has_gpu(!cards.is_empty());
        m.set_gpus(ModelRc::new(VecModel::from(cards)));
    }
    // The bars, from the sample or flat while there is none.
    let set_cores = |loads: Option<&[f32]>| {
        let groups: Vec<ModelRc<f32>> = monitor::cpu_info()
            .groups
            .iter()
            .map(|core| {
                let core: Vec<f32> = core
                    .iter()
                    .map(|&thread| loads.and_then(|l| l.get(thread)).copied().unwrap_or(0.0))
                    .collect();
                ModelRc::new(VecModel::from(core))
            })
            .collect();
        m.set_core_groups(ModelRc::new(VecModel::from(groups)));
    };
    let Some(s) = snapshot else {
        m.set_measured(false);
        set_cores(None);
        state.programs.clear();
        m.set_programs(ModelRc::default());
        m.set_program_count(0);
        m.set_process_count(0);
        return;
    };
    m.set_measured(s.measured);
    let dash = |text: String| if s.measured { text } else { "-".to_string() };
    let percent = |value: f64| value.round().clamp(0.0, 100.0) as u32;
    // Rates scale to the busiest second of the minute, with a floor so idle noise stays flat.
    let scaled = |series: &VecDeque<f64>, floor: f64| {
        let top = series.iter().copied().fold(floor, f64::max);
        series.iter().map(|v| (v / top * 100.0).round() as u32).collect::<Vec<_>>()
    };

    set_cores(s.measured.then_some(s.cores.as_slice()));
    m.set_cpu_load(dash(format!("{:.0}%", s.cpu)).into());
    m.set_cpu_clock(if s.mhz > 0.0 { format_ghz(s.mhz) } else { String::new() }.into());
    let (line, area) = spark_paths(s.history[0].iter().map(|v| percent(*v)));
    m.set_cpu_line(line.into());
    m.set_cpu_area(area.into());

    if let Some(gpu) = s.gpus.first() {
        m.set_gpu_load(dash(format!("{:.0}%", gpu.load)).into());
        m.set_gpu_memory(
            dash(format!("{} / {}", format_bytes(gpu.memory_used), format_bytes(gpu.memory_total))).into(),
        );
        let (line, area) = spark_paths(s.history[1].iter().map(|v| percent(*v)));
        m.set_gpu_line(line.into());
        m.set_gpu_area(area.into());
    }
    // One card per graphics card, in the order the cards were listed in.
    if s.measured
        && let Some(cards) = m.get_gpus().as_any().downcast_ref::<VecModel<GpuCard>>()
    {
        for (i, gpu) in s.gpus.iter().enumerate() {
            let Some(mut card) = cards.row_data(i) else { continue };
            card.memory =
                format!("{} / {}", format_bytes(gpu.memory_used), format_bytes(gpu.memory_total)).into();
            card.memory_fraction = if gpu.memory_total == 0 {
                0.0
            } else {
                (gpu.memory_used as f64 / gpu.memory_total as f64) as f32
            };
            card.engines = ModelRc::new(VecModel::from(gpu.engines.to_vec()));
            cards.set_row_data(i, card);
        }
    }

    let read: f64 = s.disks.iter().map(|d| d.read).sum();
    let write: f64 = s.disks.iter().map(|d| d.write).sum();
    let active = s.disks.iter().map(|d| d.active).fold(0.0, f32::max);
    m.set_disk_load(dash(format!("{active:.0}%")).into());
    m.set_disk_read(dash(format_speed(read)).into());
    m.set_disk_write(dash(format_speed(write)).into());
    let (line, area) = spark_paths(s.history[2].iter().map(|v| percent(*v)));
    m.set_disk_line(line.into());
    m.set_disk_area(area.into());

    m.set_net_total(format_speed(s.net[0] + s.net[1]).into());
    m.set_net_down(format_speed(s.net[0]).into());
    m.set_net_up(format_speed(s.net[1]).into());
    let (line, area) = spark_paths(scaled(&s.history[3], 100.0 * 1024.0).into_iter());
    m.set_net_line(line.into());
    m.set_net_area(area.into());

    show_programs(ui, &s.programs, state);
}

/// Every program that matches the search, in the sample's order unless the pointer is
/// over the list.
fn show_programs(ui: &AppWindow, all: &[monitor::Program], state: &mut State) {
    let m = ui.global::<Monitor>();
    m.set_program_count(all.len() as i32);
    m.set_process_count(all.iter().map(|p| p.processes.len()).sum::<usize>() as i32);
    let search = m.get_search().trim().to_lowercase();
    // By the name the row shows, without ".exe", or "exe" would find everything.
    let found =
        |p: &monitor::Program| search.is_empty() || shown_name(&p.name).to_lowercase().contains(&search);

    // While the pointer is over the list, rows keep their place and only their numbers
    // change, so a button never moves away from under it. Programs started meanwhile go
    // at the end, and a search typed meanwhile still applies.
    let programs: Vec<monitor::Program> = if m.get_hovering() && !state.programs.is_empty() {
        let fresh: HashMap<&str, &monitor::Program> = all.iter().map(|p| (p.name.as_str(), p)).collect();
        let mut kept: Vec<monitor::Program> = state
            .programs
            .iter()
            .filter(|old| found(old))
            .map(|old| fresh.get(old.name.as_str()).map_or_else(|| old.clone(), |p| (*p).clone()))
            .collect();
        let shown: std::collections::HashSet<&str> = state.programs.iter().map(|p| p.name.as_str()).collect();
        kept.extend(all.iter().filter(|p| found(p) && !shown.contains(p.name.as_str())).cloned());
        kept
    } else {
        all.iter().filter(|p| found(p)).cloned().collect()
    };
    // A note stays on its row for four seconds, a service long enough to press Stop
    // service, and "Ending..." or "Stopping..." never outstays the work.
    let ended = state.ended.take().filter(|(_, note, at)| {
        let keep = match note {
            RowNote::Ending | RowNote::Stopping => 25,
            RowNote::Ended(monitor::EndOutcome::Service { .. }) => 15,
            _ => 4,
        };
        at.elapsed() < Duration::from_secs(keep)
    });
    let status = |name: &str| -> (i32, SharedString, bool) {
        let none = SharedString::default;
        match ended.as_ref().filter(|(row, ..)| row == name).map(|(_, note, _)| note) {
            None => (0, none(), false),
            Some(RowNote::Ending) => (1, none(), false),
            Some(RowNote::Ended(monitor::EndOutcome::Ended)) => (2, none(), false),
            Some(RowNote::Ended(monitor::EndOutcome::Protected)) => (3, none(), false),
            Some(RowNote::Ended(monitor::EndOutcome::Service { display, names })) => {
                (4, display.as_str().into(), names.iter().all(|service| services::blocked(service).is_none()))
            }
            Some(RowNote::Ended(monitor::EndOutcome::Reopened(parent))) => (5, parent.as_str().into(), false),
            Some(RowNote::Ended(monitor::EndOutcome::Core)) => (6, none(), false),
            Some(RowNote::Ended(monitor::EndOutcome::Failed)) => (7, none(), false),
            Some(RowNote::Stopping) => (8, none(), false),
            Some(RowNote::Stopped) => (9, none(), false),
            Some(RowNote::CameBack) => (10, none(), false),
            Some(RowNote::StopFailed) => (11, none(), false),
        }
    };
    let open = m.get_open();
    let rows: Vec<ProgramRow> = programs
        .iter()
        .map(|p| {
            let (status, status_name, can_stop) = status(&p.name);
            let name: SharedString = shown_name(&p.name).into();
            // Only the open row carries its processes: a hundred models a second for rows
            // nobody looks at would be waste.
            let processes = if name == open {
                let lines: Vec<ProcessRow> = p
                    .processes
                    .iter()
                    .map(|process| ProcessRow {
                        pid: process.pid as i32,
                        cpu: format_percent(process.cpu).into(),
                        gpu: format_percent(process.gpu).into(),
                        memory: format_bytes(process.memory).into(),
                    })
                    .collect();
                ModelRc::new(VecModel::from(lines))
            } else {
                ModelRc::default()
            };
            ProgramRow {
                name,
                count: p.processes.len() as i32,
                cpu: format_percent(p.cpu).into(),
                gpu: format_percent(p.gpu).into(),
                memory: format_bytes(p.memory).into(),
                eco: p.eco.map_or(-1, i32::from),
                can_end: p.can_end,
                status,
                status_name,
                can_stop,
                processes,
            }
        })
        .collect();
    state.programs = programs;
    state.ended = ended;
    // In place, so the list keeps its scroll position and each row its state, like a
    // pending End.
    let model = m.get_programs();
    match model.as_any().downcast_ref::<VecModel<ProgramRow>>() {
        Some(current) => {
            let count = rows.len();
            for (i, row) in rows.into_iter().enumerate() {
                if i < current.row_count() {
                    current.set_row_data(i, row);
                } else {
                    current.push(row);
                }
            }
            while current.row_count() > count {
                current.remove(current.row_count() - 1);
            }
        }
        None => m.set_programs(ModelRc::new(VecModel::from(rows))),
    }
}

/// "chrome.exe" as "chrome", whatever the case of the extension.
fn shown_name(name: &str) -> &str {
    match name.len().checked_sub(4) {
        Some(cut) if name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(".exe") => &name[..cut],
        _ => name,
    }
}
