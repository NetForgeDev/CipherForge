#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::Engine as _;
use chrono::Local;
use eframe::egui;
use rand::seq::{IndexedRandom, SliceRandom};
use rand::{Rng, RngCore};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::watch;
use url::Url;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_REPO_URL: &str = "https://github.com/NetForgeDev/CipherForge";
const GITHUB_RELEASES_URL: &str = "https://github.com/NetForgeDev/CipherForge/releases/latest";
const GITHUB_API_LATEST: &str =
    "https://api.github.com/repos/NetForgeDev/CipherForge/releases/latest";
const XRAY_FORK_URL: &str = "https://github.com/patterniha/Xray-core/releases";
const XRAY_API_LATEST: &str =
    "https://api.github.com/repos/patterniha/Xray-core/releases/latest";

const DEFAULT_FINALMASK_STR: &str = r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["114","1"],"delays":["1"],"maxSplit":"11"}}]}"#;

const REFERENCE_CIPHER: &str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";

// ================= Refined Slate-Obsidian Palette =================
const BG_MAIN: egui::Color32 = egui::Color32::from_rgb(10, 14, 24);
const BG_CARD: egui::Color32 = egui::Color32::from_rgb(17, 24, 39);
const BG_ELEVATED: egui::Color32 = egui::Color32::from_rgb(26, 35, 54);
const BG_HOVER: egui::Color32 = egui::Color32::from_rgb(36, 48, 74);
const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(9, 13, 22);
const BORDER_CLR: egui::Color32 = egui::Color32::from_rgb(38, 51, 77);
const BORDER_FOCUS: egui::Color32 = egui::Color32::from_rgb(99, 102, 241);

const FG_TEXT: egui::Color32 = egui::Color32::from_rgb(248, 250, 252);
const FG_SECONDARY: egui::Color32 = egui::Color32::from_rgb(203, 213, 225);
const FG_MUTED: egui::Color32 = egui::Color32::from_rgb(148, 163, 184);

const INDIGO: egui::Color32 = egui::Color32::from_rgb(99, 102, 241);
const INDIGO_SOFT: egui::Color32 = egui::Color32::from_rgb(30, 38, 76);
const EMERALD: egui::Color32 = egui::Color32::from_rgb(16, 185, 129);
const EMERALD_HI: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);
const EMERALD_SOFT: egui::Color32 = egui::Color32::from_rgb(14, 46, 42);
const ROSE: egui::Color32 = egui::Color32::from_rgb(244, 63, 94);
const ROSE_HI: egui::Color32 = egui::Color32::from_rgb(251, 113, 133);
const ROSE_SOFT: egui::Color32 = egui::Color32::from_rgb(58, 22, 34);
const SKY: egui::Color32 = egui::Color32::from_rgb(56, 189, 248);
const AMBER: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
const AMBER_SOFT: egui::Color32 = egui::Color32::from_rgb(56, 42, 16);
const PURPLE: egui::Color32 = egui::Color32::from_rgb(192, 132, 252);
const PURPLE_SOFT: egui::Color32 = egui::Color32::from_rgb(46, 28, 72);

// ================= Data Types =================
#[derive(Clone, Copy, PartialEq, Eq)]
enum Strategy {
    Engineered,
    Hybrid,
    AllTemplates,
    BrowsersOnly,
    SemiPython,
    MobileAead,
    Schannel,
}

impl Strategy {
    const ALL: [Self; 7] = [
        Self::Engineered,
        Self::Hybrid,
        Self::AllTemplates,
        Self::BrowsersOnly,
        Self::SemiPython,
        Self::MobileAead,
        Self::Schannel,
    ];

    fn label(&self) -> &'static str {
        match self {
            Self::Engineered => "From-Scratch Engineered (Rule-Based + Mutation)",
            Self::Hybrid => "Hybrid (Engineered + Standard Templates)",
            Self::AllTemplates => "All Standard Templates (Smart Mix)",
            Self::BrowsersOnly => "Browsers Only (Chrome / Firefox)",
            Self::SemiPython => "Semi-Python (Classic F&F Style)",
            Self::MobileAead => "Mobile Pure-AEAD (Compact)",
            Self::Schannel => "Windows Schannel (Enterprise)",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointPreset {
    WorkerSafe,
    CloudflareDirect,
    Custom,
}

impl EndpointPreset {
    fn label(&self) -> &'static str {
        match self {
            Self::WorkerSafe => "Worker-Safe (Non-Cloudflare)",
            Self::CloudflareDirect => "Cloudflare (Direct / VPS)",
            Self::Custom => "Custom Endpoints",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Console,
    Results,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResultSort {
    BestPing,
    BestUpload,
    BestDownload,
    OrderFound,
}

#[derive(Clone, Copy)]
enum LogLevel {
    Info,
    Pass,
    Fail,
    Warn,
    Cipher,
}

#[derive(Clone)]
struct LogEntry {
    time: String,
    text: String,
    level: LogLevel,
}

#[derive(Clone)]
struct WorkingResult {
    index: usize,
    tag: String,
    ping_ms: u64,
    dl_kbps: u64,
    ul_kbps: u64,
    cipher: String,
}

enum WorkerMsg {
    Log(String, LogLevel),
    Progress { tried: usize, pct: f32 },
    Found(WorkingResult),
    Finished { stopped: bool },
}

#[derive(Clone)]
struct ReleaseInfo {
    tag: String,
    html_url: String,
    asset_name: Option<String>,
    download_url: Option<String>,
}

enum AppUpdateState {
    Idle,
    Checking,
    UpToDate(String),
    Available(ReleaseInfo),
    Updating { stage: String, progress: f32 },
    Error(String),
}

enum AppUpdateMsg {
    CheckResult(Result<ReleaseInfo, String>),
    Progress { stage: String, progress: f32 },
    ReadyToRestart(PathBuf),
    Failed(String),
}

enum XrayUpdateState {
    Idle,
    Checking,
    UpToDate(String),
    Available(ReleaseInfo),
    Installing { stage: String, progress: f32 },
    Installed(String),
    Error(String),
}

enum XrayMsg {
    VersionDetected(Option<String>),
    CheckResult(Result<ReleaseInfo, String>),
    Progress { stage: String, progress: f32 },
    InstallDone { path: PathBuf, tag: String },
    InstallFailed(String),
}

#[derive(Clone)]
struct ScanParams {
    xray_path: PathBuf,
    output_path: PathBuf,
    base_cfg: Value,
    summary: String,
    target_found: usize,
    max_attempts: usize,
    timeout_secs: u64,
    run_ref: bool,
    strategy: Strategy,
    override_fm: bool,
    fm_obj: Option<Value>,
    ping_url: String,
    dl_url: String,
    ul_url: String,
}

struct TempGuard(PathBuf);
impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ================= Clipboard & Input Helpers =================
fn read_clipboard() -> Option<String> {
    arboard::Clipboard::new()
        .ok()
        .and_then(|mut cb| cb.get_text().ok())
}

fn write_clipboard(ui: &egui::Ui, text: &str) {
    ui.copy_text(text.to_string());
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(text.to_string());
    }
}

/// Attaches a native-feeling right-click context menu (Paste / Copy / Cut / Clear)
/// to any TextEdit response. Returns `true` if `text` was modified.
fn attach_text_context_menu(resp: &egui::Response, text: &mut String, trim_paste: bool) -> bool {
    let mut modified = false;
    resp.context_menu(|ui| {
        ui.set_min_width(135.0);
        if ui.button("Paste").clicked() {
            if let Some(clip) = read_clipboard() {
                *text = if trim_paste {
                    clip.trim().to_string()
                } else {
                    clip
                };
                modified = true;
            }
            ui.close();
        }
        if ui
            .add_enabled(!text.is_empty(), egui::Button::new("Copy"))
            .clicked()
        {
            write_clipboard(ui, text);
            ui.close();
        }
        if ui
            .add_enabled(!text.is_empty(), egui::Button::new("Cut"))
            .clicked()
        {
            write_clipboard(ui, text);
            text.clear();
            modified = true;
            ui.close();
        }
        ui.separator();
        if ui
            .add_enabled(!text.is_empty(), egui::Button::new("Clear"))
            .clicked()
        {
            text.clear();
            modified = true;
            ui.close();
        }
    });
    modified
}

/// Precision numeric stepper (`[ - ] [ value ] [ + ]`) with exact fixed dimensions
/// so multiple rows align laser-straight vertically.
struct NumInput {
    value: usize,
    buf: String,
    min: usize,
    max: usize,
    step: usize,
}

impl NumInput {
    const TOTAL_WIDTH: f32 = 114.0;
    const HEIGHT: f32 = 26.0;

    fn new(value: usize, min: usize, max: usize, step: usize) -> Self {
        let clamped = value.clamp(min, max);
        Self {
            value: clamped,
            buf: clamped.to_string(),
            min,
            max,
            step,
        }
    }

    fn set(&mut self, v: usize) {
        self.value = v.clamp(self.min, self.max);
        self.buf = self.value.to_string();
    }

    fn draw(&mut self, ui: &mut egui::Ui, id_salt: &str) {
        ui.allocate_ui_with_layout(
            egui::vec2(Self::TOTAL_WIDTH, Self::HEIGHT),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_width(Self::TOTAL_WIDTH);
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.spacing_mut().button_padding = egui::vec2(0.0, 0.0);

                let can_dec = self.value > self.min;
                let dec_btn = egui::Button::new(
                    egui::RichText::new("-")
                        .size(14.5)
                        .strong()
                        .color(if can_dec { FG_TEXT } else { FG_MUTED }),
                )
                .fill(BG_ELEVATED);
                if ui
                    .add_enabled_ui(can_dec, |ui| {
                        ui.add_sized(egui::vec2(26.0, Self::HEIGHT), dec_btn)
                    })
                    .inner
                    .clicked()
                {
                    self.set(self.value.saturating_sub(self.step));
                }

                let resp = ui.add_sized(
                    egui::vec2(54.0, Self::HEIGHT),
                    egui::TextEdit::singleline(&mut self.buf)
                        .id_salt(id_salt)
                        .align(egui::Align2::CENTER_CENTER)
                        .margin(egui::Margin::symmetric(4, 3))
                        .font(egui::TextStyle::Monospace),
                );

                let menu_changed = attach_text_context_menu(&resp, &mut self.buf, true);

                if resp.changed() || menu_changed {
                    self.buf.retain(|c| c.is_ascii_digit());
                    if let Ok(parsed) = self.buf.parse::<usize>() {
                        self.value = parsed.clamp(self.min, self.max);
                        if parsed > self.max {
                            self.buf = self.value.to_string();
                        }
                    }
                }

                if resp.lost_focus() {
                    if self.buf.is_empty() {
                        self.buf = self.value.to_string();
                    } else if let Ok(parsed) = self.buf.parse::<usize>() {
                        self.set(parsed);
                    } else {
                        self.buf = self.value.to_string();
                    }
                }

                let can_inc = self.value < self.max;
                let inc_btn = egui::Button::new(
                    egui::RichText::new("+")
                        .size(14.5)
                        .strong()
                        .color(if can_inc { FG_TEXT } else { FG_MUTED }),
                )
                .fill(BG_ELEVATED);
                if ui
                    .add_enabled_ui(can_inc, |ui| {
                        ui.add_sized(egui::vec2(26.0, Self::HEIGHT), inc_btn)
                    })
                    .inner
                    .clicked()
                {
                    self.set(self.value.saturating_add(self.step));
                }
            },
        );
    }
}

// ================= Path Discovery, Version Comparison & Updaters =================
fn xray_bin_name() -> &'static str {
    if cfg!(windows) { "xray.exe" } else { "xray" }
}

fn xray_expected_asset_name() -> &'static str {
    if cfg!(target_os = "windows") {
        if cfg!(target_arch = "aarch64") {
            "Xray-windows-arm64-v8a.zip"
        } else {
            "Xray-windows-64.zip"
        }
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "Xray-macos-arm64-v8a.zip"
        } else {
            "Xray-macos-64.zip"
        }
    } else if cfg!(target_arch = "aarch64") {
        "Xray-linux-arm64-v8a.zip"
    } else {
        "Xray-linux-64.zip"
    }
}

fn cleanup_old_self_update_binary() {
    if let Ok(exe) = std::env::current_exe() {
        let old = old_exe_path(&exe);
        if old.exists() {
            let _ = std::fs::remove_file(&old);
        }
    }
}

fn old_exe_path(exe: &Path) -> PathBuf {
    let mut os = exe.as_os_str().to_os_string();
    os.push(".old");
    PathBuf::from(os)
}

fn resolve_base_dir() -> PathBuf {
    let bin_name = xray_bin_name();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
        && dir.join(bin_name).exists()
    {
        return dir.to_path_buf();
    }
    if let Ok(cwd) = std::env::current_dir()
        && cwd.join(bin_name).exists()
    {
        return cwd;
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn parse_version_parts(s: &str) -> Vec<u64> {
    let clean = s.trim().trim_start_matches(['v', 'V']);
    let mut parts = Vec::new();
    for seg in clean.split(['.', '-', '_']) {
        let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            if !parts.is_empty() {
                break;
            }
            continue;
        }
        if let Ok(n) = digits.parse::<u64>() {
            parts.push(n);
        }
    }
    parts
}

fn is_newer_version(latest: &str, current: &str) -> bool {
    let a = parse_version_parts(latest);
    let b = parse_version_parts(current);
    if a.is_empty() {
        return false;
    }
    if b.is_empty() {
        return true;
    }
    let len = a.len().max(b.len());
    for i in 0..len {
        let va = *a.get(i).unwrap_or(&0);
        let vb = *b.get(i).unwrap_or(&0);
        if va != vb {
            return va > vb;
        }
    }
    false
}

fn format_version_tag(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('v') || trimmed.starts_with('V') {
        format!("v{}", &trimmed[1..])
    } else {
        format!("v{trimmed}")
    }
}

fn format_mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

fn spawn_detect_xray_version(path: PathBuf, tx: Sender<XrayMsg>) {
    std::thread::spawn(move || {
        if !path.exists() {
            let _ = tx.send(XrayMsg::VersionDetected(None));
            return;
        }

        let mut cmd = std::process::Command::new(&path);
        cmd.arg("version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let parsed = cmd.output().ok().and_then(|out| {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            for line in combined.lines() {
                let l = line.trim();
                if l.to_lowercase().starts_with("xray ") {
                    let token = l.split_whitespace().nth(1)?;
                    if !parse_version_parts(token).is_empty() {
                        return Some(format_version_tag(token));
                    }
                }
            }
            None
        });

        let _ = tx.send(XrayMsg::VersionDetected(parsed));
    });
}

async fn fetch_github_release(
    api_url: &str,
    fallback_html: &str,
    preferred_asset: Option<&str>,
) -> Result<ReleaseInfo, String> {
    let client = reqwest::Client::builder()
        .user_agent(format!("CipherForge/{APP_VERSION}"))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(api_url)
        .send()
        .await
        .map_err(|e| format!("Network error: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GitHub API HTTP {}", resp.status()));
    }
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let data: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;

    let tag = data
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or("No tag_name in release response")?
        .to_string();
    let html_url = data
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_html)
        .to_string();

    let mut asset_name: Option<String> = None;
    let mut download_url: Option<String> = None;

    if let Some(assets) = data.get("assets").and_then(|v| v.as_array()) {
        // 1. Exact preferred asset match (case-insensitive)
        if let Some(pref) = preferred_asset {
            for a in assets {
                if let (Some(name), Some(url)) = (
                    a.get("name").and_then(|v| v.as_str()),
                    a.get("browser_download_url").and_then(|v| v.as_str()),
                ) && name.eq_ignore_ascii_case(pref)
                {
                    asset_name = Some(name.to_string());
                    download_url = Some(url.to_string());
                    break;
                }
            }
        }
        // 2. Platform-aware ZIP fallback
        if download_url.is_none() {
            let os_hint = if cfg!(target_os = "windows") {
                "windows"
            } else if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            };
            for a in assets {
                if let (Some(name), Some(url)) = (
                    a.get("name").and_then(|v| v.as_str()),
                    a.get("browser_download_url").and_then(|v| v.as_str()),
                ) {
                    let lower = name.to_lowercase();
                    if lower.ends_with(".zip") && lower.contains(os_hint) {
                        asset_name = Some(name.to_string());
                        download_url = Some(url.to_string());
                        break;
                    }
                }
            }
        }
        // 3. Any .zip fallback
        if download_url.is_none() {
            for a in assets {
                if let (Some(name), Some(url)) = (
                    a.get("name").and_then(|v| v.as_str()),
                    a.get("browser_download_url").and_then(|v| v.as_str()),
                ) && name.to_lowercase().ends_with(".zip")
                {
                    asset_name = Some(name.to_string());
                    download_url = Some(url.to_string());
                    break;
                }
            }
        }
    }

    Ok(ReleaseInfo {
        tag,
        html_url,
        asset_name,
        download_url,
    })
}

async fn download_file_with_progress(
    url: &str,
    dest: &Path,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .user_agent(format!("CipherForge/{APP_VERSION}"))
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?;

    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Download HTTP {}", resp.status()));
    }

    let total = resp.content_length();
    let mut file =
        std::fs::File::create(dest).map_err(|e| format!("Cannot create temp archive: {e}"))?;
    let mut downloaded: u64 = 0;
    let mut last_report = Instant::now();

    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Download stream interrupted: {e}"))?
    {
        file.write_all(&chunk)
            .map_err(|e| format!("Failed writing archive: {e}"))?;
        downloaded += chunk.len() as u64;
        if last_report.elapsed() >= Duration::from_millis(70) {
            on_progress(downloaded, total);
            last_report = Instant::now();
        }
    }
    file.flush().map_err(|e| e.to_string())?;
    on_progress(downloaded, total);
    Ok(())
}

/// Extracts ONLY the single target binary (ignoring .dat, docs, and all other files)
/// from `zip_path` into `dest_file`.
fn extract_single_binary_from_zip(
    zip_path: &Path,
    target_names: &[&str],
    dest_file: &Path,
) -> Result<(), String> {
    let file =
        std::fs::File::open(zip_path).map_err(|e| format!("Failed opening ZIP archive: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("Invalid ZIP archive: {e}"))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("ZIP entry error: {e}"))?;
        if entry.is_dir() {
            continue;
        }
        let Some(fname) = Path::new(entry.name())
            .file_name()
            .and_then(|n| n.to_str())
        else {
            continue;
        };

        if target_names.iter().any(|t| fname.eq_ignore_ascii_case(t)) {
            let mut out = std::fs::File::create(dest_file)
                .map_err(|e| format!("Cannot create extracted binary: {e}"))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|e| format!("Extraction write failed: {e}"))?;
            out.flush().map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dest_file, std::fs::Permissions::from_mode(0o755));
            }
            return Ok(());
        }
    }

    Err(format!(
        "Target binary ({}) was not found inside the ZIP archive.",
        target_names.join(" / ")
    ))
}

fn spawn_app_update_check(tx: Sender<AppUpdateMsg>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let res = match rt {
            Ok(rt) => rt.block_on(fetch_github_release(
                GITHUB_API_LATEST,
                GITHUB_RELEASES_URL,
                None,
            )),
            Err(e) => Err(e.to_string()),
        };
        let _ = tx.send(AppUpdateMsg::CheckResult(res));
    });
}

fn spawn_app_self_update(download_url: String, tx: Sender<AppUpdateMsg>) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(AppUpdateMsg::Failed(e.to_string()));
                return;
            }
        };

        let result: Result<PathBuf, String> = rt.block_on(async {
            let current_exe =
                std::env::current_exe().map_err(|e| format!("Cannot resolve current exe: {e}"))?;
            let exe_dir = current_exe
                .parent()
                .ok_or("Cannot determine application directory")?;
            let current_name = current_exe
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(if cfg!(windows) {
                    "CipherForge.exe"
                } else {
                    "CipherForge"
                })
                .to_string();

            let zip_path = std::env::temp_dir().join(format!(
                "cipherforge_app_update_{}_{}.zip",
                std::process::id(),
                rand::rng().random_range(1000..9999)
            ));
            let _zip_guard = TempGuard(zip_path.clone());

            let _ = tx.send(AppUpdateMsg::Progress {
                stage: "Connecting to GitHub...".into(),
                progress: 0.05,
            });

            download_file_with_progress(&download_url, &zip_path, |dl, total| {
                let (pct, label) = if let Some(tot) = total
                    && tot > 0
                {
                    let frac = (dl as f32 / tot as f32).clamp(0.0, 1.0);
                    (
                        0.05 + frac * 0.75,
                        format!("Downloading update... {} / {}", format_mb(dl), format_mb(tot)),
                    )
                } else {
                    (0.4, format!("Downloading update... {}", format_mb(dl)))
                };
                let _ = tx.send(AppUpdateMsg::Progress {
                    stage: label,
                    progress: pct,
                });
            })
            .await?;

            let _ = tx.send(AppUpdateMsg::Progress {
                stage: "Extracting CipherForge executable...".into(),
                progress: 0.85,
            });

            let staged_exe = exe_dir.join(format!("{current_name}.new"));
            let _staged_guard = TempGuard(staged_exe.clone());

            let default_name = if cfg!(windows) {
                "CipherForge.exe"
            } else {
                "CipherForge"
            };
            {
                // Scoped so the ZIP file handle closes cleanly before TempGuard removes it
                extract_single_binary_from_zip(
                    &zip_path,
                    &[current_name.as_str(), default_name],
                    &staged_exe,
                )?;
            }

            let _ = tx.send(AppUpdateMsg::Progress {
                stage: "Installing update & cleaning up...".into(),
                progress: 0.95,
            });

            let old_exe = old_exe_path(&current_exe);
            if old_exe.exists() {
                let _ = std::fs::remove_file(&old_exe);
            }

            std::fs::rename(&current_exe, &old_exe).map_err(|e| {
                format!("Cannot replace running executable (check folder permissions): {e}")
            })?;

            if let Err(e) = std::fs::rename(&staged_exe, &current_exe) {
                // Roll back cleanly so the app is never left broken
                let _ = std::fs::rename(&old_exe, &current_exe);
                return Err(format!("Failed moving updated binary into place: {e}"));
            }

            // Explicit drop cleans up the temporary ZIP right before restart
            drop(_zip_guard);

            Ok(current_exe)
        });

        match result {
            Ok(exe_path) => {
                let _ = tx.send(AppUpdateMsg::ReadyToRestart(exe_path));
            }
            Err(e) => {
                let _ = tx.send(AppUpdateMsg::Failed(e));
            }
        }
    });
}

fn spawn_xray_update_check(tx: Sender<XrayMsg>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let res = match rt {
            Ok(rt) => rt.block_on(fetch_github_release(
                XRAY_API_LATEST,
                XRAY_FORK_URL,
                Some(xray_expected_asset_name()),
            )),
            Err(e) => Err(e.to_string()),
        };
        let _ = tx.send(XrayMsg::CheckResult(res));
    });
}

/// Downloads the Xray ZIP (either from an already-fetched ReleaseInfo or by fetching latest first),
/// extracts ONLY `xray.exe` / `xray` (skipping `.dat` and other files), replaces cleanly,
/// and deletes the ZIP archive automatically.
fn spawn_xray_download_install(
    release_opt: Option<ReleaseInfo>,
    target_path: PathBuf,
    tx: Sender<XrayMsg>,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(XrayMsg::InstallFailed(e.to_string()));
                return;
            }
        };

        let result: Result<(PathBuf, String), String> = rt.block_on(async {
            let release = match release_opt {
                Some(r) => r,
                None => {
                    let _ = tx.send(XrayMsg::Progress {
                        stage: "Fetching latest patterniha/Xray-core release...".into(),
                        progress: 0.05,
                    });
                    fetch_github_release(
                        XRAY_API_LATEST,
                        XRAY_FORK_URL,
                        Some(xray_expected_asset_name()),
                    )
                    .await?
                }
            };

            let dl_url = release
                .download_url
                .ok_or("No compatible ZIP asset found in latest Xray release.")?;

            if let Some(parent) = target_path.parent()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Cannot create target directory: {e}"))?;
            }

            let zip_path = std::env::temp_dir().join(format!(
                "cipherforge_xray_{}_{}.zip",
                std::process::id(),
                rand::rng().random_range(1000..9999)
            ));
            let _zip_guard = TempGuard(zip_path.clone());

            let _ = tx.send(XrayMsg::Progress {
                stage: format!("Downloading {}...", release.tag),
                progress: 0.1,
            });

            let tag_for_cb = release.tag.clone();
            download_file_with_progress(&dl_url, &zip_path, |dl, total| {
                let (pct, label) = if let Some(tot) = total
                    && tot > 0
                {
                    let frac = (dl as f32 / tot as f32).clamp(0.0, 1.0);
                    (
                        0.1 + frac * 0.72,
                        format!(
                            "Downloading Xray {}... {} / {}",
                            tag_for_cb,
                            format_mb(dl),
                            format_mb(tot)
                        ),
                    )
                } else {
                    (
                        0.45,
                        format!("Downloading Xray {}... {}", tag_for_cb, format_mb(dl)),
                    )
                };
                let _ = tx.send(XrayMsg::Progress {
                    stage: label,
                    progress: pct,
                });
            })
            .await?;

            let _ = tx.send(XrayMsg::Progress {
                stage: format!("Extracting {} only...", xray_bin_name()),
                progress: 0.86,
            });

            let staged_path = {
                let mut os = target_path.as_os_str().to_os_string();
                os.push(".new");
                PathBuf::from(os)
            };
            let _staged_guard = TempGuard(staged_path.clone());

            {
                extract_single_binary_from_zip(&zip_path, &[xray_bin_name()], &staged_path)?;
            }

            let _ = tx.send(XrayMsg::Progress {
                stage: "Replacing core binary & cleaning up ZIP...".into(),
                progress: 0.95,
            });

            let backup_path = {
                let mut os = target_path.as_os_str().to_os_string();
                os.push(".bak");
                PathBuf::from(os)
            };
            let had_existing = target_path.exists();
            if had_existing {
                if backup_path.exists() {
                    let _ = std::fs::remove_file(&backup_path);
                }
                std::fs::rename(&target_path, &backup_path).map_err(|e| {
                    format!("Cannot replace existing Xray binary (is it running?): {e}")
                })?;
            }

            if let Err(e) = std::fs::rename(&staged_path, &target_path) {
                if had_existing {
                    let _ = std::fs::rename(&backup_path, &target_path);
                }
                return Err(format!("Failed installing new Xray binary: {e}"));
            }
            if had_existing {
                let _ = std::fs::remove_file(&backup_path);
            }

            // _zip_guard drops here, automatically removing the temporary ZIP archive
            Ok((target_path, format_version_tag(&release.tag)))
        });

        match result {
            Ok((path, tag)) => {
                let _ = tx.send(XrayMsg::InstallDone { path, tag });
            }
            Err(e) => {
                let _ = tx.send(XrayMsg::InstallFailed(e));
            }
        }
    });
}

// ================= Proxy Link Parser & Exporter =================
fn percent_decode_str(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push(((h << 4) | l) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0x0F) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

fn build_exported_config(
    raw_input: &str,
    cipher: &str,
    override_fm: bool,
    fm_input: &str,
) -> Result<String, String> {
    let text = raw_input.trim();
    if text.is_empty() {
        return Err("No proxy link or JSON entered.".into());
    }

    let fm_str = if override_fm {
        let parsed: Value = serde_json::from_str(fm_input.trim())
            .map_err(|e| format!("Invalid Final Mask JSON: {e}"))?;
        Some((
            serde_json::to_string(&parsed).map_err(|e| e.to_string())?,
            parsed,
        ))
    } else {
        None
    };

    if text.starts_with('{') {
        let base: Value = serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {e}"))?;
        let mut cfg = if base.get("outbounds").is_some() {
            base
        } else {
            json!({ "outbounds": [base] })
        };
        if let Some(outs) = cfg.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
            for out in outs.iter_mut() {
                if let Some(stream) = out
                    .get_mut("streamSettings")
                    .and_then(|s| s.as_object_mut())
                    && (stream.contains_key("tlsSettings")
                        || stream.get("security").and_then(|v| v.as_str()) == Some("tls"))
                {
                    if let Some((_, fm_val)) = &fm_str {
                        stream.remove("finalMask");
                        stream.insert("finalmask".into(), fm_val.clone());
                    }
                    let tls = stream.entry("tlsSettings").or_insert_with(|| json!({}));
                    if let Some(tls_obj) = tls.as_object_mut() {
                        tls_obj.insert("fingerprint".into(), json!("unsafe"));
                        tls_obj.insert("cipherSuites".into(), json!(cipher));
                    }
                    break;
                }
            }
        }
        return serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string());
    }

    let lower = text.to_lowercase();
    if lower.starts_with("vless://") || lower.starts_with("trojan://") {
        let u = Url::parse(text).map_err(|e| format!("Invalid URI: {e}"))?;
        let scheme = u.scheme();
        let host = u.host_str().ok_or("Missing host in URI")?;
        let port = u.port().unwrap_or(443);
        let user = u.username();

        let mut pairs: Vec<(String, String)> = Vec::new();
        for (k, v) in u.query_pairs() {
            let key = k.into_owned();
            if key == "fp" || key == "cs" {
                continue;
            }
            if fm_str.is_some() && (key == "fm" || key == "finalmask") {
                continue;
            }
            pairs.push((key, v.into_owned()));
        }

        pairs.push(("fp".into(), "unsafe".into()));
        pairs.push(("cs".into(), cipher.into()));
        if let Some((fm_compact, _)) = &fm_str {
            pairs.push(("fm".into(), fm_compact.clone()));
        }

        let query_str = pairs
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    percent_encode_component(k),
                    percent_encode_component(v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        let mut out = format!("{scheme}://{user}@{host}:{port}?{query_str}");
        if let Some(frag) = u.fragment()
            && !frag.is_empty()
        {
            out.push('#');
            out.push_str(frag);
        }
        return Ok(out);
    }

    if lower.starts_with("vmess://") {
        let raw_b64 = text[8..].split('#').next().unwrap_or("").trim();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(raw_b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw_b64))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(raw_b64))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw_b64))
            .map_err(|_| "Invalid VMess Base64 payload".to_string())?;
        let mut vm: Value =
            serde_json::from_slice(&decoded).map_err(|e| format!("Invalid VMess JSON: {e}"))?;
        if let Some(obj) = vm.as_object_mut() {
            obj.insert("fp".into(), json!("unsafe"));
            obj.insert("cs".into(), json!(cipher));
            if let Some((fm_compact, _)) = &fm_str {
                obj.insert("fm".into(), json!(fm_compact));
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&vm).map_err(|e| e.to_string())?);
        return Ok(format!("vmess://{encoded}"));
    }

    Err("Unsupported format for link export.".into())
}

fn build_stream_settings(
    network: &str,
    security: &str,
    sni: &str,
    alpn_raw: &str,
    host_header: &str,
    path: &str,
    allow_insecure: bool,
    mode: &str,
    service_name: &str,
    authority: &str,
    extra_raw: &str,
) -> Result<Value, String> {
    let mut net = network.trim().to_lowercase();
    if net.is_empty() || net == "raw" {
        net = "tcp".to_string();
    }
    let sec = if security.trim().is_empty() {
        "none".to_string()
    } else {
        security.trim().to_lowercase()
    };

    if sec == "reality" {
        return Err("Reality links use uTLS and do not support custom TLS cipherSuites.".into());
    }

    let mut stream = json!({
        "network": net,
        "security": sec,
    });

    if sec == "tls" {
        let mut tls_cfg = json!({ "fingerprint": "unsafe" });
        if !sni.is_empty() {
            tls_cfg["serverName"] = json!(sni);
        }
        if !alpn_raw.is_empty() {
            let alpns: Vec<String> = alpn_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !alpns.is_empty() {
                tls_cfg["alpn"] = json!(alpns);
            }
        }
        if allow_insecure {
            tls_cfg["allowInsecure"] = json!(true);
        }
        stream["tlsSettings"] = tls_cfg;
    }

    let clean_path = if path.is_empty() { "/" } else { path };

    match net.as_str() {
        "ws" => {
            let mut ws = json!({ "path": clean_path });
            if !host_header.is_empty() {
                ws["headers"] = json!({ "Host": host_header });
            }
            stream["wsSettings"] = ws;
        }
        "xhttp" | "splithttp" => {
            let key = if net == "xhttp" {
                "xhttpSettings"
            } else {
                "splithttpSettings"
            };
            let mut x = json!({ "path": clean_path });
            if !host_header.is_empty() {
                x["host"] = json!(host_header);
            }
            if !mode.is_empty() {
                x["mode"] = json!(mode);
            }
            if !extra_raw.is_empty()
                && let Ok(parsed_extra) = serde_json::from_str::<Value>(extra_raw)
            {
                x["extra"] = parsed_extra;
            }
            stream[key] = x;
        }
        "httpupgrade" => {
            let mut hu = json!({ "path": clean_path });
            if !host_header.is_empty() {
                hu["host"] = json!(host_header);
            }
            stream["httpupgradeSettings"] = hu;
        }
        "grpc" => {
            let svc = if !service_name.is_empty() {
                service_name
            } else {
                path
            };
            let mut g = json!({ "serviceName": svc });
            if mode == "multi" {
                g["multiMode"] = json!(true);
            }
            if !authority.is_empty() {
                g["authority"] = json!(authority);
            }
            stream["grpcSettings"] = g;
        }
        "h2" => {
            let mut h2 = json!({ "path": clean_path });
            if !host_header.is_empty() {
                let hosts: Vec<String> = host_header
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                h2["host"] = json!(hosts);
            }
            stream["httpSettings"] = h2;
        }
        _ => {}
    }

    Ok(stream)
}

fn parse_proxy_input(raw: &str) -> Result<(Value, String), String> {
    let text = raw.trim();
    if text.is_empty() {
        return Err("Paste a vless://, trojan://, vmess:// link or JSON config.".into());
    }

    if text.starts_with('{') {
        let obj: Value = serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {e}"))?;
        if obj.get("outbounds").is_some() {
            return Ok((obj, "JSON Config".into()));
        }
        if let Some(proto) = obj.get("protocol").and_then(|v| v.as_str())
            && obj.get("settings").is_some()
        {
            return Ok((
                json!({ "outbounds": [obj] }),
                format!("JSON Outbound ({})", proto.to_uppercase()),
            ));
        }
        return Err("JSON must contain 'outbounds' or a valid outbound object.".into());
    }

    let lower = text.to_lowercase();

    if lower.starts_with("vless://") || lower.starts_with("trojan://") {
        let is_vless = lower.starts_with("vless://");
        let u = Url::parse(text).map_err(|e| format!("Invalid URI: {e}"))?;
        let host = u
            .host_str()
            .map(|h| h.trim_matches(|c| c == '[' || c == ']').to_string())
            .filter(|h| !h.is_empty())
            .ok_or("Missing host in URI")?;
        let port = u.port().unwrap_or(443);
        let cred = percent_decode_str(u.username());
        if cred.is_empty() {
            return Err(if is_vless {
                "Missing UUID in VLESS link"
            } else {
                "Missing password in Trojan link"
            }
            .into());
        }

        let mut qs = std::collections::HashMap::<String, String>::new();
        for (k, v) in u.query_pairs() {
            qs.insert(k.into_owned(), v.into_owned());
        }

        let default_sec = if is_vless { "none" } else { "tls" };
        let security = qs
            .get("security")
            .map(|s| s.as_str())
            .unwrap_or(default_sec);
        let network = qs.get("type").map(|s| s.as_str()).unwrap_or("tcp");
        let sni = qs.get("sni").map(|s| s.as_str()).unwrap_or("");
        let alpn = qs.get("alpn").map(|s| s.as_str()).unwrap_or("");
        let host_hdr = qs.get("host").map(|s| s.as_str()).unwrap_or("");
        let path = qs.get("path").map(|s| s.as_str()).unwrap_or("/");
        let insecure = matches!(
            qs.get("allowInsecure")
                .or_else(|| qs.get("insecure"))
                .map(|s| s.as_str()),
            Some("1" | "true" | "True")
        );

        let stream = build_stream_settings(
            network,
            security,
            sni,
            alpn,
            host_hdr,
            path,
            insecure,
            qs.get("mode").map(|s| s.as_str()).unwrap_or(""),
            qs.get("serviceName").map(|s| s.as_str()).unwrap_or(""),
            qs.get("authority").map(|s| s.as_str()).unwrap_or(""),
            qs.get("extra").map(|s| s.as_str()).unwrap_or(""),
        )?;

        let outbound = if is_vless {
            let mut user = json!({
                "id": cred,
                "encryption": qs.get("encryption").map(|s| s.as_str()).unwrap_or("none"),
            });
            if let Some(flow) = qs.get("flow")
                && !flow.is_empty()
            {
                user["flow"] = json!(flow);
            }
            json!({
                "tag": "proxy",
                "protocol": "vless",
                "settings": { "vnext": [{ "address": host, "port": port, "users": [user] }] },
                "streamSettings": stream
            })
        } else {
            json!({
                "tag": "proxy",
                "protocol": "trojan",
                "settings": { "servers": [{ "address": host, "port": port, "password": cred }] },
                "streamSettings": stream
            })
        };

        let remark = u
            .fragment()
            .map(percent_decode_str)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.clone());
        let proto_name = if is_vless { "VLESS" } else { "TROJAN" };
        let sni_disp = if sni.is_empty() { &host } else { sni };
        let summary = format!(
            "{proto_name} • {} • {} • SNI: {sni_disp} ({remark})",
            network.to_uppercase(),
            security.to_uppercase()
        );
        return Ok((json!({ "outbounds": [outbound] }), summary));
    }

    if lower.starts_with("vmess://") {
        let raw_b64 = text[8..].split('#').next().unwrap_or("").trim();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(raw_b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw_b64))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(raw_b64))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw_b64))
            .map_err(|_| "Invalid VMess Base64 payload".to_string())?;
        let vm: Value =
            serde_json::from_slice(&decoded).map_err(|e| format!("Invalid VMess JSON: {e}"))?;

        let host = vm
            .get("add")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let port: u16 = match vm.get("port") {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(443) as u16,
            Some(Value::String(s)) => s.parse().unwrap_or(443),
            _ => 443,
        };
        let uuid = vm
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if host.is_empty() || uuid.is_empty() {
            return Err("Invalid VMess link (missing address or id).".into());
        }
        let aid: u64 = match vm.get("aid") {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
            Some(Value::String(s)) => s.parse().unwrap_or(0),
            _ => 0,
        };
        let scy = vm
            .get("scy")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("auto");
        let network = vm.get("net").and_then(|v| v.as_str()).unwrap_or("tcp");
        let security = if vm
            .get("tls")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .eq_ignore_ascii_case("tls")
        {
            "tls"
        } else {
            "none"
        };
        let sni = vm.get("sni").and_then(|v| v.as_str()).unwrap_or("");
        let alpn = vm.get("alpn").and_then(|v| v.as_str()).unwrap_or("");
        let host_hdr = vm.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let path = vm.get("path").and_then(|v| v.as_str()).unwrap_or("/");
        let mode = vm.get("type").and_then(|v| v.as_str()).unwrap_or("");

        let stream = build_stream_settings(
            network, security, sni, alpn, host_hdr, path, false, mode, "", "", "",
        )?;
        let outbound = json!({
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{ "id": uuid, "alterId": aid, "security": scy }]
                }]
            },
            "streamSettings": stream
        });
        let remark = vm
            .get("ps")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(&host);
        let sni_disp = if sni.is_empty() { &host } else { sni };
        let summary = format!(
            "VMESS • {} • {} • SNI: {sni_disp} ({remark})",
            network.to_uppercase(),
            security.to_uppercase()
        );
        return Ok((json!({ "outbounds": [outbound] }), summary));
    }

    Err("Unsupported format. Use vless://, trojan://, vmess://, or Xray JSON.".into())
}

// ================= Engineered Cipher DNA + Standard Templates =================
#[derive(Clone, Copy)]
enum Bias {
    Aes256,
    Aes128,
    ChaCha,
}

impl Bias {
    fn tag(&self) -> &'static str {
        match self {
            Self::Aes256 => "256",
            Self::Aes128 => "128",
            Self::ChaCha => "cha",
        }
    }

    fn order(&self) -> [&'static str; 3] {
        match self {
            Self::Aes256 => ["256", "128", "cha"],
            Self::Aes128 => ["128", "cha", "256"],
            Self::ChaCha => ["cha", "128", "256"],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Grouping {
    CipherFirst,
    AuthFirst,
    RsaFirst,
}

impl Grouping {
    fn tag(&self) -> &'static str {
        match self {
            Self::CipherFirst => "Cip",
            Self::AuthFirst => "Auth",
            Self::RsaFirst => "Rsa",
        }
    }
}

#[derive(Clone)]
struct CipherDna {
    bias: Bias,
    grouping: Grouping,
    t13_count: usize,
    aead_count: usize,
    tail_ecdhe_idx: Vec<usize>,
    tail_rsa_idx: Vec<usize>,
    shuffle_t13: bool,
}

const TAIL_ECDHE_CBC: [(&str, &str); 3] = [
    (
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    ),
    (
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    ),
    (
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    ),
];

const TAIL_STATIC_RSA: [&str; 4] = [
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
];

fn tls13_suite(fam: &str) -> &'static str {
    match fam {
        "256" => "TLS_AES_256_GCM_SHA384",
        "128" => "TLS_AES_128_GCM_SHA256",
        _ => "TLS_CHACHA20_POLY1305_SHA256",
    }
}

fn aead_pair(fam: &str) -> (&'static str, &'static str) {
    match fam {
        "256" => (
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        "128" => (
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        _ => (
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
    }
}

fn sample_vec<T: Clone>(items: &[T], k: usize, rng: &mut impl Rng) -> Vec<T> {
    let mut v = items.to_vec();
    v.shuffle(rng);
    v.truncate(k.min(v.len()));
    v
}

fn dedup_join(items: Vec<&str>) -> String {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for s in items {
        if seen.insert(s) {
            out.push(s);
        }
    }
    out.join(":")
}

fn create_random_dna(rng: &mut impl Rng) -> CipherDna {
    let bias = *[Bias::Aes256, Bias::Aes128, Bias::ChaCha]
        .choose(rng)
        .unwrap();
    let grouping = *[Grouping::CipherFirst, Grouping::AuthFirst, Grouping::RsaFirst]
        .choose(rng)
        .unwrap();
    let t13_count = *[2usize, 3, 3].choose(rng).unwrap();
    let aead_count = *[2usize, 3, 3].choose(rng).unwrap();
    let ecdhe_k = *[0usize, 1, 2, 2, 3].choose(rng).unwrap();
    let rsa_k = if ecdhe_k > 0 || rng.random_bool(0.4) {
        *[0usize, 0, 1, 2, 3].choose(rng).unwrap()
    } else {
        0
    };
    let mut tail_ecdhe_idx = sample_vec(&[0usize, 1, 2], ecdhe_k, rng);
    tail_ecdhe_idx.sort_unstable();
    let mut tail_rsa_idx = sample_vec(&[0usize, 1, 2, 3], rsa_k, rng);
    tail_rsa_idx.sort_unstable();

    CipherDna {
        bias,
        grouping,
        t13_count,
        aead_count,
        tail_ecdhe_idx,
        tail_rsa_idx,
        shuffle_t13: rng.random_bool(0.4),
    }
}

fn mutate_dna(parent: &CipherDna, rng: &mut impl Rng) -> CipherDna {
    let mut dna = parent.clone();
    let mut ops = vec![0u8, 1, 2, 3, 4, 5];
    ops.shuffle(rng);
    let m_count = rng.random_range(1..=2);
    for op in ops.into_iter().take(m_count) {
        match op {
            0 => {
                let choices: Vec<Grouping> =
                    [Grouping::CipherFirst, Grouping::AuthFirst, Grouping::RsaFirst]
                        .into_iter()
                        .filter(|g| *g != dna.grouping)
                        .collect();
                dna.grouping = *choices.choose(rng).unwrap();
            }
            1 => {
                let choices: Vec<Bias> = [Bias::Aes256, Bias::Aes128, Bias::ChaCha]
                    .into_iter()
                    .filter(|b| b.tag() != dna.bias.tag())
                    .collect();
                dna.bias = *choices.choose(rng).unwrap();
            }
            2 => {
                let delta: isize = if rng.random_bool(0.5) { 1 } else { -1 };
                let k = (dna.tail_ecdhe_idx.len() as isize + delta)
                    .clamp(0, TAIL_ECDHE_CBC.len() as isize) as usize;
                let mut idx = sample_vec(&[0usize, 1, 2], k, rng);
                idx.sort_unstable();
                dna.tail_ecdhe_idx = idx;
            }
            3 => {
                let delta: isize = if rng.random_bool(0.5) { 1 } else { -1 };
                let k = (dna.tail_rsa_idx.len() as isize + delta)
                    .clamp(0, TAIL_STATIC_RSA.len() as isize) as usize;
                let mut idx = sample_vec(&[0usize, 1, 2, 3], k, rng);
                idx.sort_unstable();
                dna.tail_rsa_idx = idx;
            }
            4 => {
                dna.t13_count = if dna.t13_count == 3 { 2 } else { 3 };
                dna.shuffle_t13 = !dna.shuffle_t13;
            }
            _ => {
                dna.aead_count = if dna.aead_count == 3 { 2 } else { 3 };
            }
        }
    }
    dna
}

fn render_dna(dna: &CipherDna, is_mutation: bool, rng: &mut impl Rng) -> (String, String) {
    let order = dna.bias.order();
    let mut t13: Vec<&str> = order[..dna.t13_count]
        .iter()
        .map(|f| tls13_suite(f))
        .collect();
    if dna.shuffle_t13 {
        t13.shuffle(rng);
    }

    let fams = &order[..dna.aead_count];
    let mut aead = Vec::new();
    match dna.grouping {
        Grouping::CipherFirst => {
            for f in fams {
                let (ecdsa, rsa) = aead_pair(f);
                aead.push(ecdsa);
                aead.push(rsa);
            }
        }
        Grouping::AuthFirst => {
            for f in fams {
                aead.push(aead_pair(f).0);
            }
            for f in fams {
                aead.push(aead_pair(f).1);
            }
        }
        Grouping::RsaFirst => {
            for f in fams {
                let (ecdsa, rsa) = aead_pair(f);
                aead.push(rsa);
                aead.push(ecdsa);
            }
        }
    }

    let mut tail = Vec::new();
    match dna.grouping {
        Grouping::AuthFirst => {
            for &i in &dna.tail_ecdhe_idx {
                tail.push(TAIL_ECDHE_CBC[i].0);
            }
            for &i in &dna.tail_ecdhe_idx {
                tail.push(TAIL_ECDHE_CBC[i].1);
            }
        }
        Grouping::RsaFirst => {
            for &i in &dna.tail_ecdhe_idx {
                tail.push(TAIL_ECDHE_CBC[i].1);
                tail.push(TAIL_ECDHE_CBC[i].0);
            }
        }
        Grouping::CipherFirst => {
            for &i in &dna.tail_ecdhe_idx {
                tail.push(TAIL_ECDHE_CBC[i].0);
                tail.push(TAIL_ECDHE_CBC[i].1);
            }
        }
    }
    for &i in &dna.tail_rsa_idx {
        tail.push(TAIL_STATIC_RSA[i]);
    }

    let mut all = Vec::new();
    all.extend(t13);
    all.extend(aead);
    all.extend(tail);
    let joined = dedup_join(all);
    let suite_count = joined.split(':').count();
    let prefix = if is_mutation { "Mut" } else { "Eng" };
    let tag = format!(
        "{prefix}({}|{}|{}s)",
        dna.bias.tag(),
        dna.grouping.tag(),
        suite_count
    );
    (tag, joined)
}

fn gen_semi_python(rng: &mut impl Rng) -> (String, String) {
    let t13 = sample_vec(
        &[
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        ],
        3,
        rng,
    );
    let pairs = sample_vec(
        &[aead_pair("256"), aead_pair("128"), aead_pair("cha")],
        3,
        rng,
    );
    let mut all = t13;
    for (e, r) in pairs {
        all.push(e);
        all.push(r);
    }
    let tk = rng.random_range(1..=3);
    for (e, r) in sample_vec(&TAIL_ECDHE_CBC, tk, rng) {
        all.push(e);
        all.push(r);
    }
    ("Semi-Python".into(), dedup_join(all))
}

fn gen_chrome_style(rng: &mut impl Rng) -> (String, String) {
    let mut t13 = vec![
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ];
    if rng.random_bool(0.4) {
        t13.swap(1, 2);
    }
    let mut blocks = vec![aead_pair("128"), aead_pair("256"), aead_pair("cha")];
    if rng.random_bool(0.5) {
        blocks.swap(1, 2);
    }
    let mut all = t13;
    for (e, r) in blocks {
        all.push(e);
        all.push(r);
    }
    let tail_pool = [
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
    ];
    let tk = rng.random_range(2..=5);
    all.extend(sample_vec(&tail_pool, tk, rng));
    ("Chrome-Like".into(), dedup_join(all))
}

fn gen_firefox_style(rng: &mut impl Rng) -> (String, String) {
    let mut t13 = vec![
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
    ];
    if rng.random_bool(0.35) {
        t13.shuffle(rng);
    }
    let core = if rng.random_bool(0.5) {
        vec![
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ]
    } else {
        vec![
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ]
    };
    let tail_pool = [
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
    ];
    let tk = rng.random_range(2..=5);
    let mut all = t13;
    all.extend(core);
    all.extend(sample_vec(&tail_pool, tk, rng));
    ("Firefox-Like".into(), dedup_join(all))
}

fn gen_mobile_aead(rng: &mut impl Rng) -> (String, String) {
    let k13 = rng.random_range(2..=3);
    let mut all = sample_vec(
        &[
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
        ],
        k13,
        rng,
    );
    let kp = rng.random_range(2..=3);
    for (e, r) in sample_vec(
        &[aead_pair("cha"), aead_pair("128"), aead_pair("256")],
        kp,
        rng,
    ) {
        all.push(e);
        all.push(r);
    }
    ("Mobile-AEAD".into(), dedup_join(all))
}

fn gen_schannel_style(rng: &mut impl Rng) -> (String, String) {
    let mut all = vec![
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ];
    if rng.random_bool(0.5) {
        all.push("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        all.push("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
    }
    let tail_pool = [
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
    ];
    let tk = rng.random_range(3..=tail_pool.len());
    all.extend(sample_vec(&tail_pool, tk, rng));
    ("Schannel-Like".into(), dedup_join(all))
}

fn generate_candidate(
    strategy: Strategy,
    winning_dnas: &[(u64, u64, CipherDna)],
    rng: &mut impl Rng,
) -> (String, String, Option<CipherDna>) {
    let use_engineered = match strategy {
        Strategy::Engineered => true,
        Strategy::Hybrid => rng.random_bool(0.6),
        _ => false,
    };

    if use_engineered {
        if !winning_dnas.is_empty() && rng.random_bool(0.55) {
            let mut sorted = winning_dnas.to_vec();
            sorted.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
            sorted.truncate(3);
            let (_, _, parent) = sorted.choose(rng).unwrap();
            let dna = mutate_dna(parent, rng);
            let (tag, cs) = render_dna(&dna, true, rng);
            return (tag, cs, Some(dna));
        }
        let dna = create_random_dna(rng);
        let (tag, cs) = render_dna(&dna, false, rng);
        return (tag, cs, Some(dna));
    }

    let (tag, cs) = match strategy {
        Strategy::BrowsersOnly => {
            if rng.random_bool(0.5) {
                gen_chrome_style(rng)
            } else {
                gen_firefox_style(rng)
            }
        }
        Strategy::SemiPython => gen_semi_python(rng),
        Strategy::MobileAead => gen_mobile_aead(rng),
        Strategy::Schannel => gen_schannel_style(rng),
        _ => match rng.random_range(0..5) {
            0 => gen_semi_python(rng),
            1 => gen_chrome_style(rng),
            2 => gen_firefox_style(rng),
            3 => gen_mobile_aead(rng),
            _ => gen_schannel_style(rng),
        },
    };
    (tag, cs, None)
}

// ================= Xray Process & Reqwest Probe =================
fn get_free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(listener.local_addr().map_err(|e| e.to_string())?.port())
}

fn prepare_temp_config(
    base_cfg: &Value,
    cipher_str: Option<&str>,
    test_port: u16,
    override_fm: bool,
    fm_obj: &Option<Value>,
) -> Result<Value, String> {
    let mut cfg = base_cfg.clone();
    let root = cfg
        .as_object_mut()
        .ok_or("Config root must be a JSON object")?;

    root.insert("log".into(), json!({ "loglevel": "warning" }));
    root.remove("fakedns");
    root.remove("dns");
    root.remove("api");
    root.remove("stats");

    let socks_tag = "socks-test";
    root.insert(
        "inbounds".into(),
        json!([{
            "tag": socks_tag,
            "port": test_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true }
        }]),
    );

    let mut proxy_tag: Option<String> = None;
    if let Some(outbounds) = root.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
        for out in outbounds.iter_mut() {
            let Some(out_obj) = out.as_object_mut() else {
                continue;
            };
            let is_tls_out = out_obj
                .get("streamSettings")
                .and_then(|s| s.as_object())
                .map(|s| {
                    s.contains_key("tlsSettings")
                        || s.get("security").and_then(|v| v.as_str()) == Some("tls")
                })
                .unwrap_or(false);

            if is_tls_out {
                let tag = out_obj
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("proxy-test")
                    .to_string();
                out_obj.insert("tag".into(), json!(tag));
                proxy_tag = Some(tag);

                if let Some(stream) = out_obj
                    .get_mut("streamSettings")
                    .and_then(|s| s.as_object_mut())
                {
                    if override_fm
                        && let Some(fm) = fm_obj
                    {
                        stream.remove("finalMask");
                        stream.insert("finalmask".into(), fm.clone());
                    }
                    if let Some(cs) = cipher_str {
                        let tls = stream.entry("tlsSettings").or_insert_with(|| json!({}));
                        if let Some(tls_obj) = tls.as_object_mut() {
                            tls_obj.insert("cipherSuites".into(), json!(cs));
                            tls_obj.insert("fingerprint".into(), json!("unsafe"));
                        }
                    }
                }
                break;
            }
        }
    }

    let p_tag = proxy_tag
        .ok_or("No TLS outbound found. Make sure your proxy uses TLS (not Reality).")?;
    root.insert(
        "routing".into(),
        json!({
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field",
                "inboundTag": [socks_tag],
                "outboundTag": p_tag
            }]
        }),
    );

    Ok(cfg)
}

async fn run_single_probe(
    params: &ScanParams,
    cipher: &str,
    payload: &[u8],
    stop_rx: &mut watch::Receiver<bool>,
) -> Result<(u64, u64, u64), String> {
    let port = get_free_port()?;
    let cfg = prepare_temp_config(
        &params.base_cfg,
        Some(cipher),
        port,
        params.override_fm,
        &params.fm_obj,
    )?;

    let temp_name = format!(
        "xray_cs_{}_{}.json",
        std::process::id(),
        rand::rng().random_range(10000..99999)
    );
    let cfg_path = std::env::temp_dir().join(temp_name);
    let cfg_bytes = serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?;
    std::fs::write(&cfg_path, cfg_bytes).map_err(|e| e.to_string())?;
    let _guard = TempGuard(cfg_path.clone());

    let mut cmd = tokio::process::Command::new(&params.xray_path);
    cmd.arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(parent) = params.xray_path.parent() {
        cmd.current_dir(parent);
    }
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to launch xray: {e}"))?;

    let start_wait = Instant::now();
    let mut ready = false;
    while start_wait.elapsed() < Duration::from_secs(5) {
        if *stop_rx.borrow() {
            let _ = child.kill().await;
            return Err("Cancelled".into());
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut msg = String::new();
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_string(&mut msg).await;
            }
            if let Some(mut err) = child.stderr.take() {
                let mut e_str = String::new();
                let _ = err.read_to_string(&mut e_str).await;
                if !e_str.is_empty() {
                    msg.push('\n');
                    msg.push_str(&e_str);
                }
            }
            let clean = msg.trim();
            return Err(if clean.is_empty() {
                format!("Xray exited with {status}")
            } else {
                format!("Xray error: {clean}")
            });
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(45)).await;
    }

    if !ready {
        let _ = child.kill().await;
        return Err("Xray startup timeout (port did not open in 5s)".into());
    }

    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
        .map_err(|e| format!("Proxy build error: {e}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(params.timeout_secs))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let probe_fut = async {
        let t0 = Instant::now();
        let resp = client
            .get(&params.ping_url)
            .send()
            .await
            .map_err(|e| format!("Ping error: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("Ping HTTP {}", resp.status()));
        }
        let ping_ms = t0.elapsed().as_millis() as u64;

        let t1 = Instant::now();
        let dl_resp = client
            .get(&params.dl_url)
            .send()
            .await
            .map_err(|e| format!("Ping OK ({ping_ms}ms) | DL error: {e}"))?;
        if !dl_resp.status().is_success() {
            return Err(format!(
                "Ping OK ({ping_ms}ms) | DL HTTP {}",
                dl_resp.status()
            ));
        }
        let dl_bytes = dl_resp
            .bytes()
            .await
            .map_err(|e| format!("Ping OK ({ping_ms}ms) | DL read error: {e}"))?;
        let dl_secs = t1.elapsed().as_secs_f64().max(0.001);
        let dl_kbps = ((dl_bytes.len() as f64 / 1024.0) / dl_secs) as u64;

        let t2 = Instant::now();
        let ul_resp = client
            .post(&params.ul_url)
            .body(payload.to_vec())
            .send()
            .await
            .map_err(|e| format!("Ping OK ({ping_ms}ms), DL {dl_kbps}KB/s | UL error: {e}"))?;
        if !ul_resp.status().is_success() {
            return Err(format!(
                "Ping OK ({ping_ms}ms), DL {dl_kbps}KB/s | UL HTTP {}",
                ul_resp.status()
            ));
        }
        let ul_secs = t2.elapsed().as_secs_f64().max(0.001);
        let ul_kbps = (((payload.len() as f64) / 1024.0) / ul_secs) as u64;
        if ul_kbps < 3 {
            return Err(format!("Upload throttled ({ul_kbps} KB/s)"));
        }

        Ok((ping_ms, dl_kbps, ul_kbps))
    };

    let result = tokio::select! {
        _ = stop_rx.changed() => Err("Cancelled".into()),
        res = probe_fut => res,
    };

    let _ = child.kill().await;
    let _ = child.wait().await;
    result
}

fn spawn_worker(params: ScanParams, tx: Sender<WorkerMsg>, mut stop_rx: watch::Receiver<bool>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime failed");

        rt.block_on(async move {
            let mut rng = rand::rng();
            let mut payload = vec![0u8; 50 * 1024];
            rng.fill_bytes(&mut payload);

            let mut tested = HashSet::new();
            let mut winning_dnas: Vec<(u64, u64, CipherDna)> = Vec::new();
            let mut found_list: Vec<WorkingResult> = Vec::new();

            let _ = tx.send(WorkerMsg::Log(
                "----------------------------------------------------------------".into(),
                LogLevel::Info,
            ));
            let _ = tx.send(WorkerMsg::Log(
                format!("Target: {}", params.summary),
                LogLevel::Info,
            ));
            let _ = tx.send(WorkerMsg::Log(
                format!(
                    "Engine: {}  |  Stop after: {}",
                    params.strategy.label(),
                    if params.target_found == 0 {
                        "Unlimited".into()
                    } else {
                        params.target_found.to_string()
                    }
                ),
                LogLevel::Info,
            ));

            if params.run_ref && !*stop_rx.borrow() {
                tested.insert(REFERENCE_CIPHER.to_string());
                match run_single_probe(&params, REFERENCE_CIPHER, &payload, &mut stop_rx).await {
                    Ok((ping, dl, ul)) => {
                        let _ = tx.send(WorkerMsg::Log(
                            format!(
                                "[REF] [PASS] Ping: {ping}ms | DL: {dl} KB/s | UL: {ul} KB/s"
                            ),
                            LogLevel::Info,
                        ));
                    }
                    Err(e) if e != "Cancelled" => {
                        let _ = tx.send(WorkerMsg::Log(format!("[REF] [FAIL] {e}"), LogLevel::Warn));
                    }
                    Err(_) => {}
                }
            }

            for attempt in 1..=params.max_attempts {
                if *stop_rx.borrow() {
                    break;
                }
                if params.target_found > 0 && found_list.len() >= params.target_found {
                    break;
                }

                let (mut label, mut cs, mut dna) = (String::new(), String::new(), None);
                for _ in 0..30 {
                    let cand = generate_candidate(params.strategy, &winning_dnas, &mut rng);
                    label = cand.0;
                    cs = cand.1;
                    dna = cand.2;
                    if !tested.contains(&cs) {
                        break;
                    }
                }
                tested.insert(cs.clone());

                match run_single_probe(&params, &cs, &payload, &mut stop_rx).await {
                    Ok((ping, dl, ul)) => {
                        if let Some(d) = dna {
                            winning_dnas.push((ping, ul, d));
                        }
                        let item = WorkingResult {
                            index: found_list.len() + 1,
                            tag: label.clone(),
                            ping_ms: ping,
                            dl_kbps: dl,
                            ul_kbps: ul,
                            cipher: cs.clone(),
                        };
                        found_list.push(item.clone());
                        let _ = tx.send(WorkerMsg::Found(item));
                        let _ = tx.send(WorkerMsg::Log(
                            format!(
                                "[{attempt}/{}] [{label}] [PASS] Ping: {ping}ms | DL: {dl} KB/s | UL: {ul} KB/s",
                                params.max_attempts
                            ),
                            LogLevel::Pass,
                        ));
                        let _ = tx.send(WorkerMsg::Log(format!("   -> {cs}"), LogLevel::Cipher));
                    }
                    Err(e) if e != "Cancelled" => {
                        let _ = tx.send(WorkerMsg::Log(
                            format!("[{attempt}/{}] [{label}] [FAIL] {e}", params.max_attempts),
                            LogLevel::Fail,
                        ));
                    }
                    Err(_) => break,
                }

                let pct = if params.target_found > 0 {
                    (found_list.len() as f32 / params.target_found as f32).min(1.0)
                } else {
                    attempt as f32 / params.max_attempts as f32
                };
                let _ = tx.send(WorkerMsg::Progress {
                    tried: attempt,
                    pct,
                });
            }

            if !found_list.is_empty() {
                found_list.sort_by(|a, b| {
                    a.ping_ms
                        .cmp(&b.ping_ms)
                        .then_with(|| b.ul_kbps.cmp(&a.ul_kbps))
                });
                let mut content = String::new();
                for r in &found_list {
                    content.push_str(&format!(
                        "[{}] Ping={}ms | DL={}KB/s | UL={}KB/s\n{}\n\n",
                        r.tag, r.ping_ms, r.dl_kbps, r.ul_kbps, r.cipher
                    ));
                }
                if let Err(e) = std::fs::write(&params.output_path, content) {
                    let _ = tx.send(WorkerMsg::Log(
                        format!("Failed saving results: {e}"),
                        LogLevel::Warn,
                    ));
                } else {
                    let _ = tx.send(WorkerMsg::Log(
                        format!(
                            "Saved {} working cipher(s) to {}",
                            found_list.len(),
                            params.output_path.display()
                        ),
                        LogLevel::Info,
                    ));
                }
            } else if !*stop_rx.borrow() {
                let _ = tx.send(WorkerMsg::Log(
                    "Finished with 0 working ciphers found.".into(),
                    LogLevel::Warn,
                ));
            }

            let _ = tx.send(WorkerMsg::Finished {
                stopped: *stop_rx.borrow(),
            });
        });
    });
}

// ================= GUI App =================
struct CipherStudioApp {
    base_dir: PathBuf,
    xray_path: PathBuf,
    xray_version: Option<String>,
    xray_detecting: bool,
    xray_state: XrayUpdateState,
    xray_tx: Sender<XrayMsg>,
    xray_rx: Receiver<XrayMsg>,
    show_xray_modal: bool,

    proxy_input: String,
    expand_link: bool,
    expand_fm: bool,
    hide_settings: bool,
    show_about: bool,
    parsed_summary: Result<String, String>,

    target_found: NumInput,
    max_attempts: NumInput,
    timeout_secs: NumInput,
    run_ref: bool,
    strategy: Strategy,

    preset: EndpointPreset,
    ping_url: String,
    dl_url: String,
    ul_url: String,

    override_fm: bool,
    fm_input: String,

    active_tab: ActiveTab,
    result_sort: ResultSort,
    is_running: bool,
    is_stopping: bool,
    status_label: String,
    tried_count: usize,
    progress_pct: f32,

    logs: Vec<LogEntry>,
    results: Vec<WorkingResult>,

    rx: Option<Receiver<WorkerMsg>>,
    stop_tx: Option<watch::Sender<bool>>,

    app_update_state: AppUpdateState,
    app_update_tx: Sender<AppUpdateMsg>,
    app_update_rx: Receiver<AppUpdateMsg>,
}

impl CipherStudioApp {
    fn configure_theme(ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG_MAIN;
        visuals.window_fill = BG_CARD;
        visuals.extreme_bg_color = BG_INPUT;
        visuals.faint_bg_color = BG_ELEVATED;

        visuals.widgets.noninteractive.bg_fill = BG_CARD;
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER_CLR);
        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, FG_SECONDARY);
        visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(7);

        visuals.widgets.inactive.bg_fill = BG_ELEVATED;
        visuals.widgets.inactive.weak_bg_fill = BG_ELEVATED;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER_CLR);
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, FG_TEXT);
        visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(7);

        visuals.widgets.hovered.bg_fill = BG_HOVER;
        visuals.widgets.hovered.weak_bg_fill = BG_HOVER;
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, BORDER_FOCUS);
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, FG_TEXT);
        visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(7);

        visuals.widgets.active.bg_fill = INDIGO;
        visuals.widgets.active.weak_bg_fill = INDIGO;
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, BORDER_FOCUS);
        visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, FG_TEXT);
        visuals.widgets.active.corner_radius = egui::CornerRadius::same(7);

        visuals.selection.bg_fill = INDIGO_SOFT;
        visuals.selection.stroke = egui::Stroke::new(1.0, INDIGO);
        visuals.window_corner_radius = egui::CornerRadius::same(10);
        visuals.window_stroke = egui::Stroke::new(1.0, BORDER_CLR);
        visuals.menu_corner_radius = egui::CornerRadius::same(8);

        ctx.all_styles_mut(move |style| {
            style.visuals = visuals.clone();

            style
                .text_styles
                .insert(egui::TextStyle::Heading, egui::FontId::proportional(20.0));
            style
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::proportional(13.0));
            style
                .text_styles
                .insert(egui::TextStyle::Button, egui::FontId::proportional(12.5));
            style
                .text_styles
                .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.5));
            style
                .text_styles
                .insert(egui::TextStyle::Small, egui::FontId::proportional(11.5));

            style.spacing.item_spacing = egui::vec2(8.0, 7.0);
            style.spacing.button_padding = egui::vec2(10.0, 5.0);
            style.spacing.interact_size = egui::vec2(40.0, 26.0);
            style.spacing.menu_margin = egui::Margin::same(8);
            style.spacing.window_margin = egui::Margin::same(14);
            style.spacing.icon_width = 15.0;
            style.spacing.icon_spacing = 7.0;
        });
    }

    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::configure_theme(&cc.egui_ctx);

        let base_dir = resolve_base_dir();
        let xray_path = base_dir.join(xray_bin_name());
        let (xray_tx, xray_rx) = mpsc::channel();
        let (app_update_tx, app_update_rx) = mpsc::channel();

        let mut app = Self {
            base_dir: base_dir.clone(),
            xray_path: xray_path.clone(),
            xray_version: None,
            xray_detecting: false,
            xray_state: XrayUpdateState::Idle,
            xray_tx,
            xray_rx,
            show_xray_modal: false,

            proxy_input: String::new(),
            expand_link: false,
            expand_fm: false,
            hide_settings: false,
            show_about: false,
            parsed_summary: Err(
                "Waiting for a proxy link (vless://, trojan://, vmess:// or JSON)".into(),
            ),
            target_found: NumInput::new(5, 0, 500, 1),
            max_attempts: NumInput::new(40, 1, 1000, 5),
            timeout_secs: NumInput::new(15, 3, 60, 1),
            run_ref: true,
            strategy: Strategy::Engineered,
            preset: EndpointPreset::WorkerSafe,
            ping_url: "https://www.gstatic.com/generate_204".into(),
            dl_url: "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js".into(),
            ul_url: "https://postman-echo.com/post".into(),
            override_fm: true,
            fm_input: DEFAULT_FINALMASK_STR.into(),
            active_tab: ActiveTab::Console,
            result_sort: ResultSort::BestPing,
            is_running: false,
            is_stopping: false,
            status_label: "IDLE".into(),
            tried_count: 0,
            progress_pct: 0.0,
            logs: Vec::new(),
            results: Vec::new(),
            rx: None,
            stop_tx: None,
            app_update_state: AppUpdateState::Idle,
            app_update_tx,
            app_update_rx,
        };
        app.push_log(
            format!("CipherForge v{APP_VERSION} ready. Xray: {}", xray_path.display()),
            LogLevel::Info,
        );
        app.push_log(
            "Paste a VLESS / Trojan / VMess link in the left panel and click 'Start Search'.",
            LogLevel::Info,
        );
        app.trigger_xray_version_detect();
        app
    }

    fn push_log(&mut self, text: impl Into<String>, level: LogLevel) {
        self.logs.push(LogEntry {
            time: Local::now().format("%H:%M:%S").to_string(),
            text: text.into(),
            level,
        });
        if self.logs.len() > 2000 {
            let drain = self.logs.len() - 2000;
            self.logs.drain(0..drain);
        }
    }

    fn refresh_proxy_badge(&mut self) {
        if self.proxy_input.trim().is_empty() {
            self.parsed_summary = Err(
                "Waiting for a proxy link (vless://, trojan://, vmess:// or JSON)".into(),
            );
            return;
        }
        self.parsed_summary = parse_proxy_input(&self.proxy_input).map(|(_, s)| s);
    }

    fn trigger_xray_version_detect(&mut self) {
        self.xray_version = None;
        if !self.xray_path.exists() {
            self.xray_detecting = false;
            return;
        }
        self.xray_detecting = true;
        spawn_detect_xray_version(self.xray_path.clone(), self.xray_tx.clone());
    }

    fn trigger_xray_update_check(&mut self) {
        if matches!(
            self.xray_state,
            XrayUpdateState::Checking | XrayUpdateState::Installing { .. }
        ) {
            return;
        }
        self.xray_state = XrayUpdateState::Checking;
        spawn_xray_update_check(self.xray_tx.clone());
    }

    fn trigger_xray_install(&mut self, release: Option<ReleaseInfo>) {
        if self.is_running
            || matches!(
                self.xray_state,
                XrayUpdateState::Checking | XrayUpdateState::Installing { .. }
            )
        {
            return;
        }
        let target_path = if self.xray_path.exists() {
            self.xray_path.clone()
        } else {
            self.base_dir.join(xray_bin_name())
        };
        self.xray_state = XrayUpdateState::Installing {
            stage: "Preparing Xray Core download...".into(),
            progress: 0.02,
        };
        spawn_xray_download_install(release, target_path, self.xray_tx.clone());
    }

    fn trigger_app_update_check(&mut self) {
        if matches!(
            self.app_update_state,
            AppUpdateState::Checking | AppUpdateState::Updating { .. }
        ) {
            return;
        }
        self.app_update_state = AppUpdateState::Checking;
        spawn_app_update_check(self.app_update_tx.clone());
    }

    fn trigger_app_self_update(&mut self, download_url: String) {
        if self.is_running
            || matches!(
                self.app_update_state,
                AppUpdateState::Checking | AppUpdateState::Updating { .. }
            )
        {
            return;
        }
        self.app_update_state = AppUpdateState::Updating {
            stage: "Preparing update download...".into(),
            progress: 0.02,
        };
        spawn_app_self_update(download_url, self.app_update_tx.clone());
    }

    fn poll_background_tasks(&mut self) {
        // 1. Scan Worker
        let mut finished = false;
        let mut drained = Vec::new();
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                drained.push(msg);
            }
        }
        for msg in drained {
            match msg {
                WorkerMsg::Log(txt, lvl) => self.push_log(txt, lvl),
                WorkerMsg::Progress { tried, pct } => {
                    self.tried_count = tried;
                    self.progress_pct = pct;
                }
                WorkerMsg::Found(item) => self.results.push(item),
                WorkerMsg::Finished { stopped } => {
                    self.is_running = false;
                    self.is_stopping = false;
                    self.status_label = if stopped {
                        "STOPPED".into()
                    } else {
                        "DONE".into()
                    };
                    finished = true;
                }
            }
        }
        if finished {
            self.rx = None;
            self.stop_tx = None;
        }

        // 2. Xray Core Manager Messages
        let mut xray_msgs = Vec::new();
        while let Ok(msg) = self.xray_rx.try_recv() {
            xray_msgs.push(msg);
        }
        for msg in xray_msgs {
            match msg {
                XrayMsg::VersionDetected(ver) => {
                    self.xray_detecting = false;
                    self.xray_version = ver;
                }
                XrayMsg::CheckResult(Ok(info)) => {
                    let latest_disp = format_version_tag(&info.tag);
                    let needs_update = match &self.xray_version {
                        Some(curr) => is_newer_version(&info.tag, curr),
                        None => true,
                    };
                    if !self.xray_path.exists() || needs_update {
                        self.push_log(
                            format!("Xray Core update available: {latest_disp}"),
                            LogLevel::Warn,
                        );
                        self.xray_state = XrayUpdateState::Available(info);
                    } else {
                        self.push_log(
                            format!("Xray Core is up to date ({latest_disp})."),
                            LogLevel::Info,
                        );
                        self.xray_state = XrayUpdateState::UpToDate(latest_disp);
                    }
                }
                XrayMsg::CheckResult(Err(e)) => {
                    self.push_log(format!("Xray update check failed: {e}"), LogLevel::Warn);
                    self.xray_state = XrayUpdateState::Error(e);
                }
                XrayMsg::Progress { stage, progress } => {
                    self.xray_state = XrayUpdateState::Installing { stage, progress };
                }
                XrayMsg::InstallDone { path, tag } => {
                    self.xray_path = path.clone();
                    self.push_log(
                        format!("Xray Core {tag} installed cleanly at {}", path.display()),
                        LogLevel::Pass,
                    );
                    self.xray_state = XrayUpdateState::Installed(tag);
                    self.trigger_xray_version_detect();
                }
                XrayMsg::InstallFailed(e) => {
                    self.push_log(format!("Xray Core install failed: {e}"), LogLevel::Fail);
                    self.xray_state = XrayUpdateState::Error(e);
                }
            }
        }

        // 3. CipherForge App Self-Updater Messages
        let mut app_msgs = Vec::new();
        while let Ok(msg) = self.app_update_rx.try_recv() {
            app_msgs.push(msg);
        }
        for msg in app_msgs {
            match msg {
                AppUpdateMsg::CheckResult(Ok(info)) => {
                    if is_newer_version(&info.tag, APP_VERSION) {
                        self.push_log(
                            format!("CipherForge update available: {} -> {}", info.tag, info.html_url),
                            LogLevel::Warn,
                        );
                        self.app_update_state = AppUpdateState::Available(info);
                    } else {
                        self.push_log(
                            format!("CipherForge is up to date (v{APP_VERSION})."),
                            LogLevel::Info,
                        );
                        self.app_update_state =
                            AppUpdateState::UpToDate(format_version_tag(&info.tag));
                    }
                }
                AppUpdateMsg::CheckResult(Err(e)) => {
                    self.push_log(format!("App update check failed: {e}"), LogLevel::Warn);
                    self.app_update_state = AppUpdateState::Error(e);
                }
                AppUpdateMsg::Progress { stage, progress } => {
                    self.app_update_state = AppUpdateState::Updating { stage, progress };
                }
                AppUpdateMsg::ReadyToRestart(exe_path) => {
                    self.push_log(
                        "CipherForge updated successfully. Restarting...",
                        LogLevel::Pass,
                    );
                    let mut cmd = std::process::Command::new(&exe_path);
                    if let Some(dir) = exe_path.parent() {
                        cmd.current_dir(dir);
                    }
                    match cmd.spawn() {
                        Ok(_) => std::process::exit(0),
                        Err(e) => {
                            self.app_update_state = AppUpdateState::Error(format!(
                                "Updated on disk, but auto-restart failed ({e}). Please reopen CipherForge manually."
                            ));
                        }
                    }
                }
                AppUpdateMsg::Failed(e) => {
                    self.push_log(format!("CipherForge self-update failed: {e}"), LogLevel::Fail);
                    self.app_update_state = AppUpdateState::Error(e);
                }
            }
        }
    }

    fn start_scan(&mut self) {
        if !self.xray_path.exists() {
            self.push_log(
                format!(
                    "Xray binary not found at: {}. Open Xray Core Manager to download or select it.",
                    self.xray_path.display()
                ),
                LogLevel::Fail,
            );
            self.show_xray_modal = true;
            return;
        }
        let (base_cfg, summary) = match parse_proxy_input(&self.proxy_input) {
            Ok(v) => v,
            Err(e) => {
                self.push_log(format!("Invalid proxy link: {e}"), LogLevel::Fail);
                return;
            }
        };
        let fm_obj = if self.override_fm {
            match serde_json::from_str::<Value>(self.fm_input.trim()) {
                Ok(v) => Some(v),
                Err(e) => {
                    self.push_log(format!("Invalid Final Mask JSON: {e}"), LogLevel::Fail);
                    return;
                }
            }
        } else {
            None
        };

        self.results.clear();
        self.tried_count = 0;
        self.progress_pct = 0.0;
        self.is_running = true;
        self.is_stopping = false;
        self.status_label = "RUNNING".into();

        let (tx, rx) = mpsc::channel();
        let (stop_tx, stop_rx) = watch::channel(false);
        self.rx = Some(rx);
        self.stop_tx = Some(stop_tx);

        let params = ScanParams {
            xray_path: self.xray_path.clone(),
            output_path: self.base_dir.join("working_ciphers.txt"),
            base_cfg,
            summary,
            target_found: self.target_found.value,
            max_attempts: self.max_attempts.value.max(1),
            timeout_secs: (self.timeout_secs.value as u64).max(3),
            run_ref: self.run_ref,
            strategy: self.strategy,
            override_fm: self.override_fm,
            fm_obj,
            ping_url: self.ping_url.trim().to_string(),
            dl_url: self.dl_url.trim().to_string(),
            ul_url: self.ul_url.trim().to_string(),
        };
        spawn_worker(params, tx, stop_rx);
    }

    fn stop_scan(&mut self) {
        if let Some(tx) = &self.stop_tx {
            let _ = tx.send(true);
            self.is_stopping = true;
            self.status_label = "STOPPING...".into();
            self.push_log(
                "Stop requested. Terminating active test...",
                LogLevel::Warn,
            );
        }
    }

    fn best_result(&self) -> Option<&WorkingResult> {
        self.results.iter().min_by(|a, b| {
            a.ping_ms
                .cmp(&b.ping_ms)
                .then_with(|| b.ul_kbps.cmp(&a.ul_kbps))
        })
    }

    fn sorted_results(&self) -> Vec<&WorkingResult> {
        let mut list: Vec<&WorkingResult> = self.results.iter().collect();
        match self.result_sort {
            ResultSort::BestPing => {
                list.sort_by(|a, b| {
                    a.ping_ms
                        .cmp(&b.ping_ms)
                        .then_with(|| b.ul_kbps.cmp(&a.ul_kbps))
                });
            }
            ResultSort::BestUpload => {
                list.sort_by(|a, b| {
                    b.ul_kbps
                        .cmp(&a.ul_kbps)
                        .then_with(|| a.ping_ms.cmp(&b.ping_ms))
                });
            }
            ResultSort::BestDownload => {
                list.sort_by(|a, b| {
                    b.dl_kbps
                        .cmp(&a.dl_kbps)
                        .then_with(|| a.ping_ms.cmp(&b.ping_ms))
                });
            }
            ResultSort::OrderFound => {
                list.sort_by_key(|r| r.index);
            }
        }
        list
    }

    fn has_active_background_work(&self) -> bool {
        self.is_running
            || self.xray_detecting
            || matches!(
                self.xray_state,
                XrayUpdateState::Checking | XrayUpdateState::Installing { .. }
            )
            || matches!(
                self.app_update_state,
                AppUpdateState::Checking | AppUpdateState::Updating { .. }
            )
    }

    // ================= Reusable UI Building Blocks =================
    fn card_frame() -> egui::Frame {
        egui::Frame {
            fill: BG_CARD,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(10),
            inner_margin: egui::Margin::symmetric(14, 11),
            ..Default::default()
        }
    }

    fn modal_section_frame() -> egui::Frame {
        egui::Frame {
            fill: BG_INPUT,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(8),
            inner_margin: egui::Margin::symmetric(12, 10),
            ..Default::default()
        }
    }

    fn draw_progress_bar(ui: &mut egui::Ui, progress: f32, fill_color: egui::Color32, height: f32) {
        let bar_w = ui.available_width();
        let (bar_rect, _) =
            ui.allocate_exact_size(egui::vec2(bar_w, height), egui::Sense::hover());
        ui.painter()
            .rect_filled(bar_rect, egui::CornerRadius::same(4), BG_ELEVATED);
        let pct = progress.clamp(0.0, 1.0);
        if pct > 0.0 {
            let mut fill_rect = bar_rect;
            fill_rect.set_width((bar_rect.width() * pct).max(10.0));
            ui.painter()
                .rect_filled(fill_rect, egui::CornerRadius::same(4), fill_color);
        }
    }

    /// Sidebar card locked to an exact outer width so every card aligns flush left & right.
    fn sidebar_card(
        ui: &mut egui::Ui,
        outer_w: f32,
        min_outer_h: f32,
        add_contents: impl FnOnce(&mut egui::Ui),
    ) {
        let inner_w = (outer_w - 26.0).max(200.0);
        let inner_min_h = (min_outer_h - 20.0).max(0.0);
        egui::Frame {
            fill: BG_CARD,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(10),
            inner_margin: egui::Margin::symmetric(12, 9),
            ..Default::default()
        }
        .show(ui, |ui| {
            ui.set_width(inner_w);
            if inner_min_h > 0.0 {
                ui.set_min_height(inner_min_h);
            }
            ui.spacing_mut().item_spacing.y = 5.0;
            add_contents(ui);
        });
    }

    fn draw_dot(ui: &mut egui::Ui, color: egui::Color32, radius: f32) {
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(radius * 2.0 + 2.0, radius * 2.0 + 2.0),
            egui::Sense::hover(),
        );
        ui.painter().circle_filled(rect.center(), radius, color);
    }

    fn draw_section_title(ui: &mut egui::Ui, title: &str, accent: egui::Color32) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            Self::draw_dot(ui, accent, 3.8);
            ui.label(
                egui::RichText::new(title)
                    .size(11.5)
                    .color(FG_TEXT)
                    .strong(),
            );
        });
    }

    fn draw_kpi(
        ui: &mut egui::Ui,
        label: &str,
        value: &str,
        sublabel: &str,
        accent: egui::Color32,
        has_value: bool,
    ) {
        egui::Frame {
            fill: BG_CARD,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(10),
            inner_margin: egui::Margin::symmetric(14, 11),
            ..Default::default()
        }
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.set_min_height(56.0);

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                Self::draw_dot(ui, accent, 3.5);
                ui.label(
                    egui::RichText::new(label)
                        .size(11.5)
                        .color(FG_MUTED)
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(sublabel).size(11.0).color(FG_MUTED));
                });
            });

            ui.add_space(6.0);

            let val_color = if has_value { FG_TEXT } else { FG_MUTED };
            ui.label(
                egui::RichText::new(value)
                    .size(21.0)
                    .color(val_color)
                    .strong(),
            );
        });
    }

    fn draw_metric_chip(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
        egui::Frame {
            fill: BG_INPUT,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(6),
            inner_margin: egui::Margin::symmetric(8, 3),
            ..Default::default()
        }
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(12.0).color(color).strong());
        });
    }

    fn draw_header(&mut self, ui: &mut egui::Ui) {
        egui::Frame {
            fill: BG_CARD,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(10),
            inner_margin: egui::Margin::symmetric(16, 9),
            ..Default::default()
        }
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Brand block
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("CipherForge")
                                .size(19.5)
                                .color(FG_TEXT)
                                .strong(),
                        );
                        egui::Frame {
                            fill: INDIGO_SOFT,
                            stroke: egui::Stroke::new(1.0, INDIGO),
                            corner_radius: egui::CornerRadius::same(6),
                            inner_margin: egui::Margin::symmetric(7, 2),
                            ..Default::default()
                        }
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(format!("v{APP_VERSION}"))
                                    .size(11.5)
                                    .color(SKY)
                                    .strong(),
                            );
                        });
                    });
                    ui.label(
                        egui::RichText::new(
                            "TLS Cipher Suite Scanner & Evolutionary Optimizer for the F&F Method",
                        )
                        .size(12.0)
                        .color(FG_MUTED),
                    );
                });

                // Right controls
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;

                    // Tight status pill (right_to_left places label on right, dot on left => "● IDLE")
                    let (st_bg, st_border, st_dot, st_fg) = match self.status_label.as_str() {
                        "RUNNING" => (EMERALD_SOFT, EMERALD, EMERALD_HI, EMERALD_HI),
                        "STOPPING..." => (BG_ELEVATED, AMBER, AMBER, AMBER),
                        "DONE" => (INDIGO_SOFT, INDIGO, SKY, SKY),
                        "STOPPED" => (ROSE_SOFT, ROSE, ROSE_HI, ROSE_HI),
                        _ => (BG_ELEVATED, BORDER_CLR, FG_MUTED, FG_SECONDARY),
                    };
                    egui::Frame {
                        fill: st_bg,
                        stroke: egui::Stroke::new(1.0, st_border),
                        corner_radius: egui::CornerRadius::same(7),
                        inner_margin: egui::Margin::symmetric(11, 5),
                        ..Default::default()
                    }
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            ui.label(
                                egui::RichText::new(&self.status_label)
                                    .size(12.0)
                                    .color(st_fg)
                                    .strong(),
                            );
                            Self::draw_dot(ui, st_dot, 3.5);
                        });
                    });

                    // About / App Update button
                    let app_has_update =
                        matches!(self.app_update_state, AppUpdateState::Available(_));
                    let about_btn = if app_has_update {
                        egui::Button::new(
                            egui::RichText::new("Update Available")
                                .size(12.5)
                                .color(AMBER)
                                .strong(),
                        )
                        .fill(AMBER_SOFT)
                        .stroke(egui::Stroke::new(1.0, AMBER))
                    } else {
                        egui::Button::new("About")
                    };
                    if ui.add(about_btn).clicked() {
                        self.show_about = true;
                    }

                    if ui.button("GitHub").clicked() {
                        ui.ctx()
                            .open_url(egui::OpenUrl::new_tab(GITHUB_REPO_URL));
                    }

                    let toggle_lbl = if self.hide_settings {
                        "Show Settings"
                    } else {
                        "Hide Settings"
                    };
                    if ui.button(toggle_lbl).clicked() {
                        self.hide_settings = !self.hide_settings;
                    }

                    // Xray Core Manager status pill button
                    let xray_ok = self.xray_path.exists();
                    let xray_has_update =
                        matches!(self.xray_state, XrayUpdateState::Available(_));
                    let xray_installing =
                        matches!(self.xray_state, XrayUpdateState::Installing { .. });

                    let (x_text, x_clr, x_fill, x_stroke) = if xray_installing {
                        (
                            "Xray: Updating...".to_string(),
                            SKY,
                            INDIGO_SOFT,
                            INDIGO,
                        )
                    } else if !xray_ok {
                        (
                            "Xray Missing".to_string(),
                            ROSE_HI,
                            ROSE_SOFT,
                            ROSE,
                        )
                    } else if xray_has_update {
                        let v_part = self
                            .xray_version
                            .as_deref()
                            .unwrap_or("Ready");
                        (
                            format!("Xray {v_part} • Update"),
                            AMBER,
                            AMBER_SOFT,
                            AMBER,
                        )
                    } else if let Some(ver) = &self.xray_version {
                        (
                            format!("Xray {ver}"),
                            EMERALD_HI,
                            EMERALD_SOFT,
                            EMERALD,
                        )
                    } else {
                        (
                            "Xray: Ready".to_string(),
                            EMERALD_HI,
                            EMERALD_SOFT,
                            EMERALD,
                        )
                    };

                    let x_btn = egui::Button::new(
                        egui::RichText::new(x_text)
                            .size(12.5)
                            .color(x_clr)
                            .strong(),
                    )
                    .fill(x_fill)
                    .stroke(egui::Stroke::new(1.0, x_stroke));

                    let x_resp = ui.add(x_btn).on_hover_text(format!(
                        "Xray Core Manager\nPath: {}\nClick to check updates, download core, or change path.",
                        self.xray_path.display()
                    ));
                    if x_resp.clicked() {
                        self.show_xray_modal = true;
                    }
                });
            });
        });
    }

    fn draw_settings_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
        let sidebar_total_h = ui.available_height();

        egui::ScrollArea::vertical()
            .id_salt("settings_sidebar_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 8.0;
                let card_w = ui.available_width();
                let start_y = ui.cursor().top();

                // ---- Card 1: Proxy Target ----
                Self::sidebar_card(ui, card_w, 0.0, |ui| {
                    ui.horizontal(|ui| {
                        Self::draw_section_title(ui, "PROXY TARGET", SKY);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 5.0;
                            if ui
                                .button(if self.expand_link { "Compact" } else { "Expand" })
                                .clicked()
                            {
                                self.expand_link = !self.expand_link;
                            }
                            if ui.button("Load .json").clicked()
                                && let Some(path) = rfd::FileDialog::new()
                                    .add_filter("JSON", &["json"])
                                    .pick_file()
                                && let Ok(content) = std::fs::read_to_string(&path)
                            {
                                if let Ok(obj) = serde_json::from_str::<Value>(&content)
                                    && let Some(outs) =
                                        obj.get("outbounds").and_then(|v| v.as_array())
                                {
                                    for o in outs {
                                        if let Some(s) = o.get("streamSettings")
                                            && let Some(fm) =
                                                s.get("finalmask").or_else(|| s.get("finalMask"))
                                        {
                                            self.fm_input = fm.to_string();
                                            break;
                                        }
                                    }
                                }
                                self.proxy_input = content;
                                self.refresh_proxy_badge();
                            }
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("Paste").color(FG_TEXT).strong(),
                                    )
                                    .fill(INDIGO),
                                )
                                .clicked()
                                && let Some(txt) = read_clipboard()
                            {
                                self.proxy_input = txt.trim().to_string();
                                self.refresh_proxy_badge();
                            }
                        });
                    });

                    let (rows, max_h) = if self.expand_link {
                        (6, 124.0)
                    } else {
                        (2, 48.0)
                    };
                    let mut changed = false;
                    egui::ScrollArea::vertical()
                        .id_salt("proxy_input_scroll")
                        .max_height(max_h)
                        .show(ui, |ui| {
                            let resp = ui.add(
                                egui::TextEdit::multiline(&mut self.proxy_input)
                                    .desired_rows(rows)
                                    .desired_width(f32::INFINITY)
                                    .margin(egui::Margin::symmetric(9, 6))
                                    .hint_text("Paste vless://, trojan://, vmess:// or Xray JSON...")
                                    .font(egui::TextStyle::Monospace),
                            );
                            if resp.changed()
                                || attach_text_context_menu(&resp, &mut self.proxy_input, true)
                            {
                                changed = true;
                            }
                        });
                    if changed {
                        self.refresh_proxy_badge();
                    }

                    // Clean status indicator (visually distinct from input boxes)
                    ui.add_space(1.0);
                    match &self.parsed_summary {
                        Ok(s) => {
                            egui::Frame {
                                fill: EMERALD_SOFT,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(6),
                                inner_margin: egui::Margin::symmetric(9, 5),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal_wrapped(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    Self::draw_dot(ui, EMERALD_HI, 3.2);
                                    ui.label(
                                        egui::RichText::new("Parsed:")
                                            .size(11.5)
                                            .color(EMERALD_HI)
                                            .strong(),
                                    );
                                    ui.label(
                                        egui::RichText::new(s)
                                            .size(11.5)
                                            .color(FG_TEXT),
                                    );
                                });
                            });
                        }
                        Err(e) if self.proxy_input.trim().is_empty() => {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                Self::draw_dot(ui, FG_MUTED, 2.8);
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(e)
                                            .size(11.5)
                                            .color(FG_MUTED)
                                            .italics(),
                                    )
                                    .wrap(),
                                );
                            });
                        }
                        Err(e) => {
                            egui::Frame {
                                fill: ROSE_SOFT,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(6),
                                inner_margin: egui::Margin::symmetric(9, 5),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal_wrapped(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    Self::draw_dot(ui, ROSE_HI, 3.2);
                                    ui.label(
                                        egui::RichText::new(e)
                                            .size(11.5)
                                            .color(ROSE_HI),
                                    );
                                });
                            });
                        }
                    }
                });

                // ---- Card 2: Scan & Generation Engine ----
                Self::sidebar_card(ui, card_w, 0.0, |ui| {
                    Self::draw_section_title(ui, "SCAN & GENERATION ENGINE", INDIGO);
                    ui.add_space(2.0);

                    let row_gap = 8.0;
                    let lbl_w = (ui.available_width() - NumInput::TOTAL_WIDTH - row_gap).max(120.0);

                    // Row 1
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = row_gap;
                        ui.allocate_ui_with_layout(
                            egui::vec2(lbl_w, NumInput::HEIGHT),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(lbl_w);
                                ui.label(
                                    egui::RichText::new("Target working ciphers (0 = unlimited)")
                                        .size(12.5)
                                        .color(FG_SECONDARY),
                                );
                            },
                        );
                        self.target_found.draw(ui, "num_target_found");
                    });

                    // Row 2
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = row_gap;
                        ui.allocate_ui_with_layout(
                            egui::vec2(lbl_w, NumInput::HEIGHT),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(lbl_w);
                                ui.label(
                                    egui::RichText::new("Max scan attempts")
                                        .size(12.5)
                                        .color(FG_SECONDARY),
                                );
                            },
                        );
                        self.max_attempts.draw(ui, "num_max_attempts");
                    });

                    // Row 3
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = row_gap;
                        ui.allocate_ui_with_layout(
                            egui::vec2(lbl_w, NumInput::HEIGHT),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(lbl_w);
                                ui.label(
                                    egui::RichText::new("HTTP timeout (seconds)")
                                        .size(12.5)
                                        .color(FG_SECONDARY),
                                );
                            },
                        );
                        self.timeout_secs.draw(ui, "num_timeout_secs");
                    });

                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new("Generation Strategy")
                            .size(11.5)
                            .color(FG_MUTED),
                    );
                    egui::ComboBox::from_id_salt("strategy_cb")
                        .width(ui.available_width())
                        .selected_text(self.strategy.label())
                        .show_ui(ui, |ui| {
                            for s in Strategy::ALL {
                                ui.selectable_value(&mut self.strategy, s, s.label());
                            }
                        });

                    ui.add_space(1.0);
                    ui.checkbox(
                        &mut self.run_ref,
                        egui::RichText::new("Run [REF] F&F baseline benchmark first")
                            .size(12.5)
                            .color(FG_SECONDARY),
                    );
                });

                // ---- Card 3: Test Endpoints ----
                Self::sidebar_card(ui, card_w, 0.0, |ui| {
                    Self::draw_section_title(ui, "TEST ENDPOINTS", PURPLE);
                    ui.add_space(2.0);

                    let label_w = 84.0;

                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.allocate_ui_with_layout(
                            egui::vec2(label_w, 26.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(label_w);
                                ui.label(
                                    egui::RichText::new("Preset")
                                        .size(12.5)
                                        .color(FG_SECONDARY),
                                );
                            },
                        );
                        let prev = self.preset;
                        egui::ComboBox::from_id_salt("preset_cb")
                            .width(ui.available_width())
                            .selected_text(self.preset.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.preset,
                                    EndpointPreset::WorkerSafe,
                                    EndpointPreset::WorkerSafe.label(),
                                );
                                ui.selectable_value(
                                    &mut self.preset,
                                    EndpointPreset::CloudflareDirect,
                                    EndpointPreset::CloudflareDirect.label(),
                                );
                                ui.selectable_value(
                                    &mut self.preset,
                                    EndpointPreset::Custom,
                                    EndpointPreset::Custom.label(),
                                );
                            });
                        if self.preset != prev {
                            match self.preset {
                                EndpointPreset::WorkerSafe => {
                                    self.ping_url =
                                        "https://www.gstatic.com/generate_204".into();
                                    self.dl_url = "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js".into();
                                    self.ul_url = "https://postman-echo.com/post".into();
                                }
                                EndpointPreset::CloudflareDirect => {
                                    self.ping_url =
                                        "https://cp.cloudflare.com/generate_204".into();
                                    self.dl_url =
                                        "https://speed.cloudflare.com/__down?bytes=100000".into();
                                    self.ul_url = "https://speed.cloudflare.com/__up".into();
                                }
                                EndpointPreset::Custom => {}
                            }
                        }
                    });

                    for (lbl, val) in [
                        ("Ping (204)", &mut self.ping_url),
                        ("Download", &mut self.dl_url),
                        ("Upload", &mut self.ul_url),
                    ] {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            ui.allocate_ui_with_layout(
                                egui::vec2(label_w, 26.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.set_width(label_w);
                                    ui.label(
                                        egui::RichText::new(lbl)
                                            .size(12.5)
                                            .color(FG_SECONDARY),
                                    );
                                },
                            );
                            let resp = ui.add(
                                egui::TextEdit::singleline(val)
                                    .desired_width(ui.available_width())
                                    .margin(egui::Margin::symmetric(8, 5))
                                    .font(egui::TextStyle::Monospace),
                            );
                            if resp.changed() || attach_text_context_menu(&resp, val, true) {
                                self.preset = EndpointPreset::Custom;
                            }
                        });
                    }
                });

                // ---- Card 4: Final Mask (stretches cleanly to align flush with bottom of console) ----
                let used_h = ui.cursor().top() - start_y;
                let rem_h = (sidebar_total_h - used_h).max(132.0);
                let fm_min_outer_h = if self.expand_fm {
                    rem_h.max(210.0)
                } else {
                    rem_h
                };

                Self::sidebar_card(ui, card_w, fm_min_outer_h, |ui| {
                    ui.horizontal(|ui| {
                        Self::draw_section_title(ui, "FINAL MASK", AMBER);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 5.0;
                            if ui
                                .button(if self.expand_fm { "Compact" } else { "Expand" })
                                .clicked()
                            {
                                self.expand_fm = !self.expand_fm;
                            }
                            if ui.button("Validate").clicked() {
                                match serde_json::from_str::<Value>(self.fm_input.trim()) {
                                    Ok(v) => {
                                        self.fm_input = v.to_string();
                                        self.push_log("Final Mask JSON is valid.", LogLevel::Info);
                                    }
                                    Err(e) => self.push_log(
                                        format!("Final Mask JSON error: {e}"),
                                        LogLevel::Fail,
                                    ),
                                }
                            }
                            if ui.button("F&F Default").clicked() {
                                self.fm_input = DEFAULT_FINALMASK_STR.into();
                            }
                        });
                    });

                    ui.checkbox(
                        &mut self.override_fm,
                        egui::RichText::new("Apply / Override finalmask JSON")
                            .size(12.5)
                            .color(FG_SECONDARY),
                    );

                    let editor_h = ui.available_height().max(54.0);
                    ui.add_enabled_ui(self.override_fm, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("fm_input_scroll")
                            .min_scrolled_height(editor_h)
                            .max_height(editor_h)
                            .show(ui, |ui| {
                                let resp = ui.add(
                                    egui::TextEdit::multiline(&mut self.fm_input)
                                        .desired_width(f32::INFINITY)
                                        .min_size(egui::vec2(ui.available_width(), editor_h))
                                        .margin(egui::Margin::symmetric(9, 7))
                                        .font(egui::TextStyle::Monospace),
                                );
                                attach_text_context_menu(&resp, &mut self.fm_input, false);
                            });
                    });
                });
            });
    }

    fn draw_main_workspace(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing = egui::vec2(10.0, 8.0);

        let best_ping_val = self.results.iter().map(|r| r.ping_ms).min();
        let best_ul_val = self.results.iter().map(|r| r.ul_kbps).max();

        let found_str = if self.target_found.value > 0 {
            format!("{} / {}", self.results.len(), self.target_found.value)
        } else {
            format!("{}", self.results.len())
        };
        let found_sub = if self.target_found.value > 0 {
            format!("Goal: {}", self.target_found.value)
        } else {
            "Unlimited".into()
        };
        let tried_sub = format!("Max: {}", self.max_attempts.value);
        let best_ping_str = best_ping_val
            .map(|p| format!("{p} ms"))
            .unwrap_or_else(|| "—".into());
        let best_ul_str = best_ul_val
            .map(|u| format!("{u} KB/s"))
            .unwrap_or_else(|| "—".into());

        // ---- Row 1: 4 Spaced & Balanced KPI Cards ----
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            ui.columns(4, |cols| {
                Self::draw_kpi(
                    &mut cols[0],
                    "FOUND",
                    &found_str,
                    &found_sub,
                    EMERALD,
                    !self.results.is_empty(),
                );
                Self::draw_kpi(
                    &mut cols[1],
                    "TRIED",
                    &self.tried_count.to_string(),
                    &tried_sub,
                    SKY,
                    self.tried_count > 0,
                );
                Self::draw_kpi(
                    &mut cols[2],
                    "BEST PING",
                    &best_ping_str,
                    "Lowest",
                    AMBER,
                    best_ping_val.is_some(),
                );
                Self::draw_kpi(
                    &mut cols[3],
                    "BEST UPLOAD",
                    &best_ul_str,
                    "Peak",
                    PURPLE,
                    best_ul_val.is_some(),
                );
            });
        });

        ui.add_space(2.0);

        // ---- Row 2: Unified Action Bar & Progress Card ----
        Self::card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;

                // Single Dynamic Start / Stop / Stopping Button
                if !self.is_running {
                    let btn = egui::Button::new(
                        egui::RichText::new("Start Search")
                            .size(13.5)
                            .color(BG_MAIN)
                            .strong(),
                    )
                    .fill(EMERALD)
                    .min_size(egui::vec2(142.0, 34.0));
                    if ui.add(btn).clicked() {
                        self.start_scan();
                    }
                } else if !self.is_stopping {
                    let btn = egui::Button::new(
                        egui::RichText::new("Stop Search")
                            .size(13.5)
                            .color(FG_TEXT)
                            .strong(),
                    )
                    .fill(ROSE)
                    .min_size(egui::vec2(142.0, 34.0));
                    if ui.add(btn).clicked() {
                        self.stop_scan();
                    }
                } else {
                    let btn = egui::Button::new(
                        egui::RichText::new("Stopping...")
                            .size(13.5)
                            .color(BG_MAIN)
                            .strong(),
                    )
                    .fill(AMBER)
                    .min_size(egui::vec2(142.0, 34.0));
                    ui.add_enabled(false, btn);
                }

                let has_best = self.best_result().is_some();

                let cs_btn = egui::Button::new(
                    egui::RichText::new("Copy Best CS")
                        .size(12.5)
                        .color(if has_best { FG_TEXT } else { FG_MUTED })
                        .strong(),
                )
                .fill(if has_best { INDIGO_SOFT } else { BG_ELEVATED })
                .stroke(egui::Stroke::new(
                    1.0,
                    if has_best { INDIGO } else { BORDER_CLR },
                ))
                .min_size(egui::vec2(122.0, 34.0));

                if ui.add(cs_btn).clicked() {
                    if let Some(best) = self.best_result() {
                        let cs = best.cipher.clone();
                        let tag = best.tag.clone();
                        let ping = best.ping_ms;
                        let ul = best.ul_kbps;
                        write_clipboard(ui, &cs);
                        self.push_log(
                            format!("Copied best cipher ({tag}, Ping={ping}ms, UL={ul}KB/s)."),
                            LogLevel::Info,
                        );
                    } else {
                        self.push_log("No working ciphers found yet.", LogLevel::Warn);
                    }
                }

                let cfg_btn = egui::Button::new(
                    egui::RichText::new("Copy Best Config")
                        .size(12.5)
                        .color(if has_best { FG_TEXT } else { FG_MUTED })
                        .strong(),
                )
                .fill(if has_best { PURPLE_SOFT } else { BG_ELEVATED })
                .stroke(egui::Stroke::new(
                    1.0,
                    if has_best { PURPLE } else { BORDER_CLR },
                ))
                .min_size(egui::vec2(138.0, 34.0));

                if ui.add(cfg_btn).clicked() {
                    if let Some(best) = self.best_result() {
                        let cs = best.cipher.clone();
                        let tag = best.tag.clone();
                        let ping = best.ping_ms;
                        match build_exported_config(
                            &self.proxy_input,
                            &cs,
                            self.override_fm,
                            &self.fm_input,
                        ) {
                            Ok(exported) => {
                                write_clipboard(ui, &exported);
                                self.push_log(
                                    format!(
                                        "Copied full F&F config ({tag}, Ping={ping}ms) to clipboard!"
                                    ),
                                    LogLevel::Info,
                                );
                            }
                            Err(e) => self.push_log(format!("Export error: {e}"), LogLevel::Fail),
                        }
                    } else {
                        self.push_log("No working ciphers found yet.", LogLevel::Warn);
                    }
                }

                // Right-aligned live progress readout
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let pct_int = (self.progress_pct.clamp(0.0, 1.0) * 100.0).round() as u32;
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ui.label(
                        egui::RichText::new(format!("{pct_int}%"))
                            .size(13.5)
                            .color(if pct_int > 0 { EMERALD_HI } else { FG_MUTED })
                            .strong(),
                    );
                    ui.label(egui::RichText::new("•").size(12.0).color(BORDER_CLR));
                    ui.label(
                        egui::RichText::new(format!(
                            "{} / {} attempts",
                            self.tried_count, self.max_attempts.value
                        ))
                        .size(12.5)
                        .color(FG_MUTED),
                    );
                });
            });

            ui.add_space(9.0);
            Self::draw_progress_bar(ui, self.progress_pct, EMERALD, 7.0);
        });

        ui.add_space(2.0);

        // ---- Row 3: Output Workspace (Console / Working Results) ----
        Self::card_frame().show(ui, |ui| {
            let avail = ui.available_size();
            ui.set_min_size(egui::vec2(avail.x, avail.y.max(240.0)));

            // Tab Header Bar
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;

                let console_active = self.active_tab == ActiveTab::Console;
                let console_btn = egui::Button::new(
                    egui::RichText::new("Live Console")
                        .size(12.5)
                        .color(if console_active { FG_TEXT } else { FG_MUTED })
                        .strong(),
                )
                .fill(if console_active {
                    INDIGO_SOFT
                } else {
                    BG_ELEVATED
                })
                .stroke(egui::Stroke::new(
                    1.0,
                    if console_active { INDIGO } else { BORDER_CLR },
                ));
                if ui.add(console_btn).clicked() {
                    self.active_tab = ActiveTab::Console;
                }

                let results_active = self.active_tab == ActiveTab::Results;
                let results_btn = egui::Button::new(
                    egui::RichText::new(format!("Working Results ({})", self.results.len()))
                        .size(12.5)
                        .color(if results_active { FG_TEXT } else { FG_MUTED })
                        .strong(),
                )
                .fill(if results_active {
                    INDIGO_SOFT
                } else {
                    BG_ELEVATED
                })
                .stroke(egui::Stroke::new(
                    1.0,
                    if results_active { INDIGO } else { BORDER_CLR },
                ));
                if ui.add(results_btn).clicked() {
                    self.active_tab = ActiveTab::Results;
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    match self.active_tab {
                        ActiveTab::Console => {
                            if ui.button("Clear Log").clicked() {
                                self.logs.clear();
                            }
                            if ui.button("Copy All").clicked() {
                                let all_logs = self
                                    .logs
                                    .iter()
                                    .map(|e| format!("[{}] {}", e.time, e.text))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                write_clipboard(ui, &all_logs);
                                self.push_log(
                                    "Copied full console log to clipboard.",
                                    LogLevel::Info,
                                );
                            }
                        }
                        ActiveTab::Results => {
                            for (mode, label) in [
                                (ResultSort::OrderFound, "Order"),
                                (ResultSort::BestDownload, "Download"),
                                (ResultSort::BestUpload, "Upload"),
                                (ResultSort::BestPing, "Best Ping"),
                            ] {
                                ui.selectable_value(&mut self.result_sort, mode, label);
                            }
                            ui.label(egui::RichText::new("Sort:").size(12.0).color(FG_MUTED));
                        }
                    }
                });
            });

            ui.add_space(7.0);

            // Sunken Output Viewport
            egui::Frame {
                fill: BG_INPUT,
                stroke: egui::Stroke::new(1.0, BORDER_CLR),
                corner_radius: egui::CornerRadius::same(8),
                inner_margin: egui::Margin::same(12),
                ..Default::default()
            }
            .show(ui, |ui| {
                let inner_avail = ui.available_size();
                ui.set_min_size(egui::vec2(inner_avail.x, inner_avail.y.max(180.0)));

                match self.active_tab {
                    ActiveTab::Console => {
                        let mut copy_line_req: Option<String> = None;
                        let mut clear_log_req = false;

                        egui::ScrollArea::vertical()
                            .id_salt("console_scroll")
                            .stick_to_bottom(true)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 4.0;
                                if self.logs.is_empty() {
                                    ui.label(
                                        egui::RichText::new("Console is empty.")
                                            .size(12.5)
                                            .color(FG_MUTED),
                                    );
                                } else {
                                    for entry in &self.logs {
                                        let color = match entry.level {
                                            LogLevel::Info => SKY,
                                            LogLevel::Pass => EMERALD_HI,
                                            LogLevel::Fail => ROSE_HI,
                                            LogLevel::Warn => AMBER,
                                            LogLevel::Cipher => PURPLE,
                                        };
                                        let full_line = format!("[{}] {}", entry.time, entry.text);
                                        let resp = ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&full_line)
                                                    .monospace()
                                                    .size(12.5)
                                                    .color(color),
                                            )
                                            .wrap()
                                            .sense(egui::Sense::click()),
                                        );
                                        resp.context_menu(|ui| {
                                            if ui.button("Copy Line").clicked() {
                                                copy_line_req = Some(full_line.clone());
                                                ui.close();
                                            }
                                            if ui.button("Clear Log").clicked() {
                                                clear_log_req = true;
                                                ui.close();
                                            }
                                        });
                                    }
                                }
                            });

                        if let Some(line) = copy_line_req {
                            write_clipboard(ui, &line);
                        }
                        if clear_log_req {
                            self.logs.clear();
                        }
                    }
                    ActiveTab::Results => {
                        let sorted = self.sorted_results();
                        let mut copy_cs_msg: Option<(String, String)> = None;
                        let mut copy_cfg_msg: Option<(String, String)> = None;

                        egui::ScrollArea::vertical()
                            .id_salt("results_scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 8.0;
                                if sorted.is_empty() {
                                    ui.add_space(24.0);
                                    ui.vertical_centered(|ui| {
                                        ui.label(
                                            egui::RichText::new("No working cipher suites yet")
                                                .size(15.0)
                                                .color(FG_SECONDARY)
                                                .strong(),
                                        );
                                        ui.add_space(4.0);
                                        ui.label(
                                            egui::RichText::new(
                                                "Paste a valid proxy link and click 'Start Search' to begin scanning.",
                                            )
                                            .size(12.5)
                                            .color(FG_MUTED),
                                        );
                                    });
                                } else {
                                    for r in sorted {
                                        egui::Frame {
                                            fill: BG_CARD,
                                            stroke: egui::Stroke::new(1.0, BORDER_CLR),
                                            corner_radius: egui::CornerRadius::same(8),
                                            inner_margin: egui::Margin::symmetric(12, 10),
                                            ..Default::default()
                                        }
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.spacing_mut().item_spacing.x = 8.0;
                                                ui.label(
                                                    egui::RichText::new(format!("#{}", r.index))
                                                        .size(13.0)
                                                        .color(FG_MUTED)
                                                        .strong(),
                                                );
                                                ui.label(
                                                    egui::RichText::new(&r.tag)
                                                        .size(13.0)
                                                        .color(SKY)
                                                        .strong(),
                                                );
                                                Self::draw_metric_chip(
                                                    ui,
                                                    &format!("Ping {} ms", r.ping_ms),
                                                    AMBER,
                                                );
                                                Self::draw_metric_chip(
                                                    ui,
                                                    &format!("DL {} KB/s", r.dl_kbps),
                                                    EMERALD_HI,
                                                );
                                                Self::draw_metric_chip(
                                                    ui,
                                                    &format!("UL {} KB/s", r.ul_kbps),
                                                    PURPLE,
                                                );

                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        ui.spacing_mut().item_spacing.x = 6.0;
                                                        if ui
                                                            .add(
                                                                egui::Button::new(
                                                                    egui::RichText::new(
                                                                        "Copy Config",
                                                                    )
                                                                    .color(FG_TEXT)
                                                                    .strong(),
                                                                )
                                                                .fill(INDIGO),
                                                            )
                                                            .clicked()
                                                        {
                                                            copy_cfg_msg = Some((
                                                                r.cipher.clone(),
                                                                r.tag.clone(),
                                                            ));
                                                        }
                                                        if ui.button("Copy CS").clicked() {
                                                            copy_cs_msg = Some((
                                                                r.cipher.clone(),
                                                                r.tag.clone(),
                                                            ));
                                                        }
                                                    },
                                                );
                                            });

                                            ui.add_space(6.0);

                                            egui::Frame {
                                                fill: BG_INPUT,
                                                stroke: egui::Stroke::new(1.0, BORDER_CLR),
                                                corner_radius: egui::CornerRadius::same(6),
                                                inner_margin: egui::Margin::symmetric(10, 7),
                                                ..Default::default()
                                            }
                                            .show(ui, |ui| {
                                                ui.set_min_width(ui.available_width());
                                                let resp = ui.add(
                                                    egui::Label::new(
                                                        egui::RichText::new(&r.cipher)
                                                            .monospace()
                                                            .size(12.0)
                                                            .color(FG_SECONDARY),
                                                    )
                                                    .wrap()
                                                    .sense(egui::Sense::click()),
                                                );
                                                resp.context_menu(|ui| {
                                                    if ui.button("Copy Cipher Suite").clicked() {
                                                        copy_cs_msg = Some((
                                                            r.cipher.clone(),
                                                            r.tag.clone(),
                                                        ));
                                                        ui.close();
                                                    }
                                                    if ui.button("Copy Full Config").clicked() {
                                                        copy_cfg_msg = Some((
                                                            r.cipher.clone(),
                                                            r.tag.clone(),
                                                        ));
                                                        ui.close();
                                                    }
                                                });
                                            });
                                        });
                                    }
                                }
                            });

                        if let Some((cs, tag)) = copy_cs_msg {
                            write_clipboard(ui, &cs);
                            self.push_log(
                                format!("Copied CS ({tag}) to clipboard."),
                                LogLevel::Info,
                            );
                        }
                        if let Some((cs, tag)) = copy_cfg_msg {
                            match build_exported_config(
                                &self.proxy_input,
                                &cs,
                                self.override_fm,
                                &self.fm_input,
                            ) {
                                Ok(exported) => {
                                    write_clipboard(ui, &exported);
                                    self.push_log(
                                        format!("Copied full F&F config ({tag}) to clipboard!"),
                                        LogLevel::Info,
                                    );
                                }
                                Err(e) => {
                                    self.push_log(format!("Export error: {e}"), LogLevel::Fail)
                                }
                            }
                        }
                    }
                }
            });
        });
    }

    // ================= Xray Core Manager Modal =================
    fn draw_xray_window(&mut self, ctx: &egui::Context) {
        if !self.show_xray_modal {
            return;
        }
        let mut open = self.show_xray_modal;
        let mut req_check = false;
        let mut req_install: Option<Option<ReleaseInfo>> = None;
        let mut req_dismiss = false;
        let mut req_browse = false;
        let mut req_refresh = false;

        egui::Window::new("Xray Core Manager")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size([520.0, 365.0])
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                let exists = self.xray_path.exists();
                let busy = matches!(
                    self.xray_state,
                    XrayUpdateState::Checking | XrayUpdateState::Installing { .. }
                );

                // Top subtitle & repo link
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Compatible Core Source:")
                            .size(12.5)
                            .color(FG_MUTED),
                    );
                    ui.hyperlink_to("patterniha/Xray-core", XRAY_FORK_URL);
                });

                ui.add_space(6.0);

                // ---- Section 1: Installed Core Status & Path ----
                Self::modal_section_frame().show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 7.0;

                    ui.horizontal(|ui| {
                        Self::draw_section_title(ui, "INSTALLED CORE", SKY);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (badge_bg, badge_fg, badge_txt) = if exists {
                                (EMERALD_SOFT, EMERALD_HI, "Ready")
                            } else {
                                (ROSE_SOFT, ROSE_HI, "Not Found")
                            };
                            egui::Frame {
                                fill: badge_bg,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(5),
                                inner_margin: egui::Margin::symmetric(8, 2),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(badge_txt)
                                        .size(11.5)
                                        .color(badge_fg)
                                        .strong(),
                                );
                            });
                        });
                    });

                    // Version row
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Core Version:")
                                .size(12.5)
                                .color(FG_MUTED),
                        );
                        let (ver_txt, ver_clr) = if !exists {
                            ("Not installed".to_string(), ROSE_HI)
                        } else if self.xray_detecting {
                            ("Detecting...".to_string(), SKY)
                        } else if let Some(v) = &self.xray_version {
                            (v.clone(), EMERALD_HI)
                        } else {
                            ("Unknown (custom binary)".to_string(), AMBER)
                        };
                        ui.label(egui::RichText::new(ver_txt).size(13.0).color(ver_clr).strong());
                    });

                    // Path display + Browse / Refresh buttons
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Binary Path:")
                                .size(12.5)
                                .color(FG_MUTED),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            if ui
                                .add_enabled(!busy && exists, egui::Button::new("Refresh"))
                                .clicked()
                            {
                                req_refresh = true;
                            }
                            if ui
                                .add_enabled(!busy && !self.is_running, egui::Button::new("Browse..."))
                                .clicked()
                            {
                                req_browse = true;
                            }
                        });
                    });

                    egui::Frame {
                        fill: BG_CARD,
                        stroke: egui::Stroke::new(1.0, BORDER_CLR),
                        corner_radius: egui::CornerRadius::same(6),
                        inner_margin: egui::Margin::symmetric(9, 6),
                        ..Default::default()
                    }
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(self.xray_path.display().to_string())
                                    .monospace()
                                    .size(11.5)
                                    .color(FG_SECONDARY),
                            )
                            .wrap(),
                        );
                    });
                });

                ui.add_space(8.0);

                // ---- Section 2: Download & Auto-Update ----
                Self::modal_section_frame().show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 8.0;

                    Self::draw_section_title(ui, "DOWNLOAD & UPDATES", EMERALD);

                    if self.is_running {
                        egui::Frame {
                            fill: AMBER_SOFT,
                            stroke: egui::Stroke::new(1.0, AMBER),
                            corner_radius: egui::CornerRadius::same(6),
                            inner_margin: egui::Margin::symmetric(9, 6),
                            ..Default::default()
                        }
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.label(
                                egui::RichText::new(
                                    "Stop the active scan before downloading or updating Xray Core.",
                                )
                                .size(12.0)
                                .color(AMBER),
                            );
                        });
                    }

                    // Primary action row
                    if !exists {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!(
                                    "No {} binary found. Download the latest compatible build directly (extracts {} only and deletes the ZIP).",
                                    xray_bin_name(),
                                    xray_bin_name()
                                ))
                                .size(12.0)
                                .color(FG_SECONDARY),
                            )
                            .wrap(),
                        );

                        ui.horizontal(|ui| {
                            let dl_btn = egui::Button::new(
                                egui::RichText::new("Download Latest Xray Core")
                                    .size(13.0)
                                    .color(BG_MAIN)
                                    .strong(),
                            )
                            .fill(EMERALD)
                            .min_size(egui::vec2(196.0, 32.0));
                            if ui.add_enabled(!busy && !self.is_running, dl_btn).clicked() {
                                req_install = Some(None);
                            }

                            if ui
                                .add_enabled(!busy, egui::Button::new("Check Latest Version"))
                                .clicked()
                            {
                                req_check = true;
                            }
                        });
                    } else {
                        ui.horizontal(|ui| {
                            let chk_btn = egui::Button::new(
                                egui::RichText::new("Check for Updates")
                                    .size(12.5)
                                    .color(FG_TEXT)
                                    .strong(),
                            )
                            .fill(INDIGO)
                            .min_size(egui::vec2(150.0, 30.0));
                            if ui.add_enabled(!busy, chk_btn).clicked() {
                                req_check = true;
                            }

                            ui.label(
                                egui::RichText::new(format!(
                                    "Extracts {} only • auto-cleans ZIP",
                                    xray_bin_name()
                                ))
                                .size(11.5)
                                .color(FG_MUTED),
                            );
                        });
                    }

                    // Dynamic state area
                    match &self.xray_state {
                        XrayUpdateState::Idle => {}
                        XrayUpdateState::Checking => {
                            ui.label(
                                egui::RichText::new("Checking GitHub releases for patterniha/Xray-core...")
                                    .size(12.0)
                                    .color(SKY),
                            );
                        }
                        XrayUpdateState::UpToDate(tag) => {
                            egui::Frame {
                                fill: EMERALD_SOFT,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(6),
                                inner_margin: egui::Margin::symmetric(10, 7),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Xray Core is up to date ({tag})."
                                    ))
                                    .size(12.5)
                                    .color(EMERALD_HI)
                                    .strong(),
                                );
                            });
                        }
                        XrayUpdateState::Available(info) => {
                            let latest_tag = format_version_tag(&info.tag);
                            let curr_disp = self
                                .xray_version
                                .as_deref()
                                .unwrap_or("Not installed");
                            let asset_disp = info
                                .asset_name
                                .as_deref()
                                .unwrap_or(xray_expected_asset_name());

                            egui::Frame {
                                fill: AMBER_SOFT,
                                stroke: egui::Stroke::new(1.0, AMBER),
                                corner_radius: egui::CornerRadius::same(7),
                                inner_margin: egui::Margin::symmetric(10, 8),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.spacing_mut().item_spacing.y = 5.0;
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Update available: {curr_disp}  →  {latest_tag}"
                                    ))
                                    .size(13.0)
                                    .color(AMBER)
                                    .strong(),
                                );
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Package: {asset_disp}  •  Extracts {} only & deletes ZIP",
                                        xray_bin_name()
                                    ))
                                    .size(11.5)
                                    .color(FG_SECONDARY),
                                );
                                ui.add_space(2.0);
                                ui.horizontal(|ui| {
                                    let confirm_btn = egui::Button::new(
                                        egui::RichText::new("Confirm & Install Update")
                                            .size(12.5)
                                            .color(BG_MAIN)
                                            .strong(),
                                    )
                                    .fill(EMERALD);
                                    if ui
                                        .add_enabled(
                                            !self.is_running && info.download_url.is_some(),
                                            confirm_btn,
                                        )
                                        .clicked()
                                    {
                                        req_install = Some(Some(info.clone()));
                                    }

                                    if ui.button("Cancel").clicked() {
                                        req_dismiss = true;
                                    }
                                });
                            });
                        }
                        XrayUpdateState::Installing { stage, progress } => {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(stage)
                                        .size(12.0)
                                        .color(SKY),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}%",
                                                (progress.clamp(0.0, 1.0) * 100.0).round() as u32
                                            ))
                                            .size(12.0)
                                            .color(EMERALD_HI)
                                            .strong(),
                                        );
                                    },
                                );
                            });
                            Self::draw_progress_bar(ui, *progress, EMERALD, 7.0);
                        }
                        XrayUpdateState::Installed(tag) => {
                            egui::Frame {
                                fill: EMERALD_SOFT,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(6),
                                inner_margin: egui::Margin::symmetric(10, 7),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Xray Core {tag} installed cleanly and ZIP removed!"
                                    ))
                                    .size(12.5)
                                    .color(EMERALD_HI)
                                    .strong(),
                                );
                            });
                        }
                        XrayUpdateState::Error(e) => {
                            egui::Frame {
                                fill: ROSE_SOFT,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(6),
                                inner_margin: egui::Margin::symmetric(10, 7),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(e)
                                            .size(12.0)
                                            .color(ROSE_HI),
                                    )
                                    .wrap(),
                                );
                            });
                        }
                    }
                });
            });

        self.show_xray_modal = open;

        if req_browse && let Some(p) = rfd::FileDialog::new().pick_file() {
            self.xray_path = p;
            self.xray_state = XrayUpdateState::Idle;
            self.trigger_xray_version_detect();
        }
        if req_refresh {
            self.trigger_xray_version_detect();
        }
        if req_check {
            self.trigger_xray_update_check();
        }
        if let Some(rel) = req_install {
            self.trigger_xray_install(rel);
        }
        if req_dismiss {
            self.xray_state = XrayUpdateState::Idle;
        }
    }

    // ================= About & App Self-Update Modal =================
    fn draw_about_window(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }
        let mut open = self.show_about;
        let mut req_check = false;
        let mut req_update_url: Option<String> = None;
        let mut req_dismiss = false;

        egui::Window::new("About & Updates")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size([520.0, 360.0])
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                let busy = matches!(
                    self.app_update_state,
                    AppUpdateState::Checking | AppUpdateState::Updating { .. }
                );

                // App header
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("CipherForge")
                            .size(21.0)
                            .color(FG_TEXT)
                            .strong(),
                    );
                    egui::Frame {
                        fill: INDIGO_SOFT,
                        stroke: egui::Stroke::new(1.0, INDIGO),
                        corner_radius: egui::CornerRadius::same(6),
                        inner_margin: egui::Margin::symmetric(7, 2),
                        ..Default::default()
                    }
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(format!("v{APP_VERSION}"))
                                .size(12.0)
                                .color(SKY)
                                .strong(),
                        );
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "TLS Cipher Suite Scanner & Evolutionary Optimizer for the F&F Method",
                    )
                    .size(12.5)
                    .color(FG_MUTED),
                );

                ui.add_space(8.0);

                // Links Card
                Self::modal_section_frame().show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 5.0;
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Project Repository:").color(FG_SECONDARY));
                        ui.hyperlink_to("github.com/NetForgeDev/CipherForge", GITHUB_REPO_URL);
                    });
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Releases & Downloads:").color(FG_SECONDARY));
                        ui.hyperlink_to("Latest Portable Releases", GITHUB_RELEASES_URL);
                    });
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Compatible Xray Core:").color(FG_SECONDARY));
                        ui.hyperlink_to("patterniha/Xray-core", XRAY_FORK_URL);
                    });
                });

                ui.add_space(8.0);

                // Self-Update Card
                Self::modal_section_frame().show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 8.0;

                    Self::draw_section_title(ui, "APPLICATION UPDATES", INDIGO);

                    if self.is_running {
                        egui::Frame {
                            fill: AMBER_SOFT,
                            stroke: egui::Stroke::new(1.0, AMBER),
                            corner_radius: egui::CornerRadius::same(6),
                            inner_margin: egui::Margin::symmetric(9, 6),
                            ..Default::default()
                        }
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.label(
                                egui::RichText::new(
                                    "Stop the active scan before installing an application update.",
                                )
                                .size(12.0)
                                .color(AMBER),
                            );
                        });
                    }

                    ui.horizontal(|ui| {
                        let chk_btn = egui::Button::new(
                            egui::RichText::new("Check for Updates")
                                .size(12.5)
                                .color(FG_TEXT)
                                .strong(),
                        )
                        .fill(INDIGO)
                        .min_size(egui::vec2(150.0, 30.0));
                        if ui.add_enabled(!busy, chk_btn).clicked() {
                            req_check = true;
                        }

                        if matches!(self.app_update_state, AppUpdateState::Idle) {
                            ui.label(
                                egui::RichText::new("Checks GitHub & supports 1-click auto-update.")
                                    .size(11.5)
                                    .color(FG_MUTED),
                            );
                        }
                    });

                    match &self.app_update_state {
                        AppUpdateState::Idle => {}
                        AppUpdateState::Checking => {
                            ui.label(
                                egui::RichText::new("Checking GitHub API for latest release...")
                                    .size(12.0)
                                    .color(SKY),
                            );
                        }
                        AppUpdateState::UpToDate(tag) => {
                            egui::Frame {
                                fill: EMERALD_SOFT,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(6),
                                inner_margin: egui::Margin::symmetric(10, 7),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.label(
                                    egui::RichText::new(format!(
                                        "CipherForge is up to date ({tag})."
                                    ))
                                    .size(12.5)
                                    .color(EMERALD_HI)
                                    .strong(),
                                );
                            });
                        }
                        AppUpdateState::Available(info) => {
                            let latest_tag = format_version_tag(&info.tag);
                            let asset_disp = info
                                .asset_name
                                .as_deref()
                                .unwrap_or("Release ZIP");

                            egui::Frame {
                                fill: AMBER_SOFT,
                                stroke: egui::Stroke::new(1.0, AMBER),
                                corner_radius: egui::CornerRadius::same(7),
                                inner_margin: egui::Margin::symmetric(10, 8),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.spacing_mut().item_spacing.y = 5.0;
                                ui.label(
                                    egui::RichText::new(format!(
                                        "New version available: v{APP_VERSION}  →  {latest_tag}"
                                    ))
                                    .size(13.0)
                                    .color(AMBER)
                                    .strong(),
                                );
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Package: {asset_disp}  •  Downloads, replaces binary & restarts automatically"
                                    ))
                                    .size(11.5)
                                    .color(FG_SECONDARY),
                                );
                                ui.add_space(2.0);
                                ui.horizontal(|ui| {
                                    if let Some(dl_url) = &info.download_url {
                                        let upd_btn = egui::Button::new(
                                            egui::RichText::new("Confirm & Update Now")
                                                .size(12.5)
                                                .color(BG_MAIN)
                                                .strong(),
                                        )
                                        .fill(EMERALD);
                                        if ui
                                            .add_enabled(!self.is_running, upd_btn)
                                            .clicked()
                                        {
                                            req_update_url = Some(dl_url.clone());
                                        }
                                    }
                                    if ui.button("Release Page").clicked() {
                                        ui.ctx().open_url(egui::OpenUrl::new_tab(&info.html_url));
                                    }
                                    if ui.button("Cancel").clicked() {
                                        req_dismiss = true;
                                    }
                                });
                            });
                        }
                        AppUpdateState::Updating { stage, progress } => {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(stage)
                                        .size(12.0)
                                        .color(SKY),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}%",
                                                (progress.clamp(0.0, 1.0) * 100.0).round() as u32
                                            ))
                                            .size(12.0)
                                            .color(EMERALD_HI)
                                            .strong(),
                                        );
                                    },
                                );
                            });
                            Self::draw_progress_bar(ui, *progress, INDIGO, 7.0);
                        }
                        AppUpdateState::Error(e) => {
                            egui::Frame {
                                fill: ROSE_SOFT,
                                stroke: egui::Stroke::NONE,
                                corner_radius: egui::CornerRadius::same(6),
                                inner_margin: egui::Margin::symmetric(10, 7),
                                ..Default::default()
                            }
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(e)
                                            .size(12.0)
                                            .color(ROSE_HI),
                                    )
                                    .wrap(),
                                );
                            });
                        }
                    }
                });
            });

        self.show_about = open;

        if req_check {
            self.trigger_app_update_check();
        }
        if let Some(url) = req_update_url {
            self.trigger_app_self_update(url);
        }
        if req_dismiss {
            self.app_update_state = AppUpdateState::Idle;
        }
    }
}

impl eframe::App for CipherStudioApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_background_tasks();
        if self.has_active_background_work() {
            ui.ctx().request_repaint_after(Duration::from_millis(80));
        }

        self.draw_xray_window(ui.ctx());
        self.draw_about_window(ui.ctx());

        egui::CentralPanel::default()
            .frame(egui::Frame {
                fill: BG_MAIN,
                inner_margin: egui::Margin::same(12),
                ..Default::default()
            })
            .show(ui, |ui| {
                // Top Header
                self.draw_header(ui);
                ui.add_space(10.0);

                // Main Responsive Two-Column Workspace
                let total_w = ui.available_width();
                let total_h = ui.available_height();

                if !self.hide_settings {
                    let gap = 12.0;
                    let left_w = (total_w * 0.39).clamp(405.0, 480.0);
                    let right_w = (total_w - left_w - gap).max(460.0);

                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = gap;

                        ui.allocate_ui_with_layout(
                            egui::vec2(left_w, total_h),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                self.draw_settings_sidebar(ui);
                            },
                        );

                        ui.allocate_ui_with_layout(
                            egui::vec2(right_w, total_h),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                self.draw_main_workspace(ui);
                            },
                        );
                    });
                } else {
                    self.draw_main_workspace(ui);
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    cleanup_old_self_update_binary();

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1260.0, 840.0])
        .with_min_inner_size([980.0, 680.0]);

    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")) {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "CipherForge",
        options,
        Box::new(|cc| Ok(Box::new(CipherStudioApp::new(cc)))),
    )
}