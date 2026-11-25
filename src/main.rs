#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::Engine as _;
use chrono::Local;
use eframe::egui;
use rand::seq::{IndexedRandom, SliceRandom};
use rand::{Rng, RngCore};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::PathBuf;
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
const GITHUB_API_LATEST: &str = "https://api.github.com/repos/NetForgeDev/CipherForge/releases/latest";
const XRAY_FORK_URL: &str = "https://github.com/patterniha/Xray-core/releases";

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

enum UpdateState {
    Idle,
    Checking,
    UpToDate(String),
    Available { tag: String, url: String },
    Error(String),
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

// ================= Path Discovery & Update Check =================
fn resolve_base_dir() -> PathBuf {
    let bin_name = if cfg!(windows) { "xray.exe" } else { "xray" };
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

fn parse_semver(s: &str) -> (u64, u64, u64) {
    let clean = s.trim().trim_start_matches(['v', 'V']);
    let mut parts = clean.split('.').map(|p| {
        p.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u64>()
            .unwrap_or(0)
    });
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

fn spawn_update_check(tx: Sender<Result<(String, String), String>>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let res = match rt {
            Ok(rt) => rt.block_on(async {
                let client = reqwest::Client::builder()
                    .user_agent(format!("CipherForge/{APP_VERSION}"))
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|e| e.to_string())?;
                let resp = client
                    .get(GITHUB_API_LATEST)
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
                let url = data
                    .get("html_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or(GITHUB_RELEASES_URL)
                    .to_string();
                Ok((tag, url))
            }),
            Err(e) => Err(e.to_string()),
        };
        let _ = tx.send(res);
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

    struct TempGuard(PathBuf);
    impl Drop for TempGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
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

    update_state: UpdateState,
    update_rx: Option<Receiver<Result<(String, String), String>>>,
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
        let bin_name = if cfg!(windows) { "xray.exe" } else { "xray" };
        let xray_path = base_dir.join(bin_name);

        let mut app = Self {
            base_dir: base_dir.clone(),
            xray_path: xray_path.clone(),
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
            update_state: UpdateState::Idle,
            update_rx: None,
        };
        app.push_log(
            format!("CipherForge v{APP_VERSION} ready. Xray: {}", xray_path.display()),
            LogLevel::Info,
        );
        app.push_log(
            "Paste a VLESS / Trojan / VMess link in the left panel and click 'Start Search'.",
            LogLevel::Info,
        );
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

    fn trigger_update_check(&mut self) {
        if matches!(self.update_state, UpdateState::Checking) {
            return;
        }
        self.update_state = UpdateState::Checking;
        let (tx, rx) = mpsc::channel();
        self.update_rx = Some(rx);
        spawn_update_check(tx);
    }

    fn poll_worker(&mut self) {
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

        if let Some(urx) = &self.update_rx
            && let Ok(res) = urx.try_recv()
        {
            self.update_rx = None;
            match res {
                Ok((tag, url)) => {
                    if parse_semver(&tag) > parse_semver(APP_VERSION) {
                        self.push_log(format!("Update available: {tag} -> {url}"), LogLevel::Warn);
                        self.update_state = UpdateState::Available { tag, url };
                    } else {
                        self.push_log(
                            format!("CipherForge is up to date (v{APP_VERSION})."),
                            LogLevel::Info,
                        );
                        self.update_state = UpdateState::UpToDate(tag);
                    }
                }
                Err(e) => {
                    self.push_log(format!("Update check failed: {e}"), LogLevel::Warn);
                    self.update_state = UpdateState::Error(e);
                }
            }
        }
    }

    fn start_scan(&mut self) {
        if !self.xray_path.exists() {
            self.push_log(
                format!("Xray binary not found at: {}", self.xray_path.display()),
                LogLevel::Fail,
            );
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

                    // Tight status pill (note: right_to_left places label first on right, dot on left => "● IDLE")
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

                    if ui.button("About").clicked() {
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

                    let xray_ok = self.xray_path.exists();
                    let (x_text, x_clr, x_fill) = if xray_ok {
                        ("Xray: Ready", EMERALD_HI, EMERALD_SOFT)
                    } else {
                        ("Pick xray.exe", ROSE_HI, ROSE_SOFT)
                    };
                    let x_btn = egui::Button::new(
                        egui::RichText::new(x_text)
                            .size(12.5)
                            .color(x_clr)
                            .strong(),
                    )
                    .fill(x_fill);
                    let x_resp = ui
                        .add(x_btn)
                        .on_hover_text(format!("Xray path: {}", self.xray_path.display()));
                    if x_resp.clicked()
                        && let Some(p) = rfd::FileDialog::new().pick_file()
                    {
                        self.xray_path = p;
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

            // Smooth rounded progress bar
            let bar_w = ui.available_width();
            let (bar_rect, _) =
                ui.allocate_exact_size(egui::vec2(bar_w, 7.0), egui::Sense::hover());
            ui.painter()
                .rect_filled(bar_rect, egui::CornerRadius::same(4), BG_INPUT);
            let pct = self.progress_pct.clamp(0.0, 1.0);
            if pct > 0.0 {
                let mut fill_rect = bar_rect;
                fill_rect.set_width((bar_rect.width() * pct).max(10.0));
                ui.painter()
                    .rect_filled(fill_rect, egui::CornerRadius::same(4), EMERALD);
            }
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

    fn draw_about_window(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }
        let mut open = self.show_about;
        egui::Window::new("About CipherForge")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size([470.0, 275.0])
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("CipherForge")
                            .size(21.0)
                            .color(FG_TEXT)
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new(format!("v{APP_VERSION}"))
                            .size(13.0)
                            .color(SKY)
                            .strong(),
                    );
                });
                ui.label(
                    egui::RichText::new(
                        "TLS Cipher Suite Scanner & Evolutionary Optimizer for the F&F Method",
                    )
                    .size(12.5)
                    .color(FG_MUTED),
                );
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(8.0);

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

                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    let checking = matches!(self.update_state, UpdateState::Checking);
                    if ui
                        .add_enabled(
                            !checking,
                            egui::Button::new(
                                egui::RichText::new("Check for Updates")
                                    .color(FG_TEXT)
                                    .strong(),
                            )
                            .fill(INDIGO),
                        )
                        .clicked()
                    {
                        self.trigger_update_check();
                    }

                    match &self.update_state {
                        UpdateState::Idle => {
                            ui.label(
                                egui::RichText::new("Click to check GitHub for updates.")
                                    .color(FG_MUTED)
                                    .size(12.0),
                            );
                        }
                        UpdateState::Checking => {
                            ui.label(
                                egui::RichText::new("Checking GitHub API...")
                                    .color(SKY)
                                    .size(12.0),
                            );
                        }
                        UpdateState::UpToDate(tag) => {
                            ui.label(
                                egui::RichText::new(format!("Up to date ({tag})"))
                                    .color(EMERALD_HI)
                                    .size(12.0)
                                    .strong(),
                            );
                        }
                        UpdateState::Available { tag, url } => {
                            ui.label(
                                egui::RichText::new(format!("New version: {tag}!"))
                                    .color(AMBER)
                                    .size(12.0)
                                    .strong(),
                            );
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("Download")
                                            .color(BG_MAIN)
                                            .strong(),
                                    )
                                    .fill(EMERALD),
                                )
                                .clicked()
                            {
                                ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                            }
                        }
                        UpdateState::Error(e) => {
                            ui.label(egui::RichText::new(e).color(ROSE_HI).size(12.0));
                        }
                    }
                });
            });
        self.show_about = open;
    }
}

impl eframe::App for CipherStudioApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.is_running || matches!(self.update_state, UpdateState::Checking) {
            ui.ctx().request_repaint_after(Duration::from_millis(80));
        }

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
