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

const DEFAULT_FINALMASK_STR: &str = r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["114","1"],"delays":["1"],"maxSplit":"11"}}]}"#;

const REFERENCE_CIPHER: &str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";

// ================= Palette =================
const BG_MAIN: egui::Color32 = egui::Color32::from_rgb(11, 15, 25);
const BG_CARD: egui::Color32 = egui::Color32::from_rgb(19, 26, 42);
const BG_CARD2: egui::Color32 = egui::Color32::from_rgb(24, 33, 53);
const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(10, 14, 23);
const BORDER_CLR: egui::Color32 = egui::Color32::from_rgb(42, 54, 82);
const FG_TEXT: egui::Color32 = egui::Color32::from_rgb(241, 245, 249);
const FG_MUTED: egui::Color32 = egui::Color32::from_rgb(148, 163, 184);

const INDIGO: egui::Color32 = egui::Color32::from_rgb(99, 102, 241);
const EMERALD: egui::Color32 = egui::Color32::from_rgb(16, 185, 129);
const EMERALD_HI: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);
const ROSE: egui::Color32 = egui::Color32::from_rgb(244, 63, 94);
const ROSE_HI: egui::Color32 = egui::Color32::from_rgb(251, 113, 133);
const SKY: egui::Color32 = egui::Color32::from_rgb(56, 189, 248);
const AMBER: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
const PURPLE: egui::Color32 = egui::Color32::from_rgb(192, 132, 252);

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
            Self::Custom => "Custom",
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

// ================= Path Discovery =================
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
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
                out.push(char::from_digit((b & 0x0F) as u32, 16).unwrap().to_ascii_uppercase());
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
        Some((serde_json::to_string(&parsed).map_err(|e| e.to_string())?, parsed))
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
                if let Some(stream) = out.get_mut("streamSettings").and_then(|s| s.as_object_mut())
                    && (stream.contains_key("tlsSettings") || stream.get("security").and_then(|v| v.as_str()) == Some("tls"))
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
            .map(|(k, v)| format!("{}={}", percent_encode_component(k), percent_encode_component(v)))
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
        let mut vm: Value = serde_json::from_slice(&decoded).map_err(|e| format!("Invalid VMess JSON: {e}"))?;
        if let Some(obj) = vm.as_object_mut() {
            obj.insert("fp".into(), json!("unsafe"));
            obj.insert("cs".into(), json!(cipher));
            if let Some((fm_compact, _)) = &fm_str {
                obj.insert("fm".into(), json!(fm_compact));
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&vm).map_err(|e| e.to_string())?);
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
            let key = if net == "xhttp" { "xhttpSettings" } else { "splithttpSettings" };
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
            let svc = if !service_name.is_empty() { service_name } else { path };
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
            return Err(if is_vless { "Missing UUID in VLESS link" } else { "Missing password in Trojan link" }.into());
        }

        let mut qs = std::collections::HashMap::<String, String>::new();
        for (k, v) in u.query_pairs() {
            qs.insert(k.into_owned(), v.into_owned());
        }

        let default_sec = if is_vless { "none" } else { "tls" };
        let security = qs.get("security").map(|s| s.as_str()).unwrap_or(default_sec);
        let network = qs.get("type").map(|s| s.as_str()).unwrap_or("tcp");
        let sni = qs.get("sni").map(|s| s.as_str()).unwrap_or("");
        let alpn = qs.get("alpn").map(|s| s.as_str()).unwrap_or("");
        let host_hdr = qs.get("host").map(|s| s.as_str()).unwrap_or("");
        let path = qs.get("path").map(|s| s.as_str()).unwrap_or("/");
        let insecure = matches!(
            qs.get("allowInsecure").or_else(|| qs.get("insecure")).map(|s| s.as_str()),
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
            "{proto_name}  •  {}  •  {}  •  SNI: {sni_disp}  ({remark})",
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
        let vm: Value = serde_json::from_slice(&decoded).map_err(|e| format!("Invalid VMess JSON: {e}"))?;

        let host = vm.get("add").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let port: u16 = match vm.get("port") {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(443) as u16,
            Some(Value::String(s)) => s.parse().unwrap_or(443),
            _ => 443,
        };
        let uuid = vm.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if host.is_empty() || uuid.is_empty() {
            return Err("Invalid VMess link (missing address or id).".into());
        }
        let aid: u64 = match vm.get("aid") {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
            Some(Value::String(s)) => s.parse().unwrap_or(0),
            _ => 0,
        };
        let scy = vm.get("scy").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("auto");
        let network = vm.get("net").and_then(|v| v.as_str()).unwrap_or("tcp");
        let security = if vm.get("tls").and_then(|v| v.as_str()).unwrap_or("").eq_ignore_ascii_case("tls") {
            "tls"
        } else {
            "none"
        };
        let sni = vm.get("sni").and_then(|v| v.as_str()).unwrap_or("");
        let alpn = vm.get("alpn").and_then(|v| v.as_str()).unwrap_or("");
        let host_hdr = vm.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let path = vm.get("path").and_then(|v| v.as_str()).unwrap_or("/");
        let mode = vm.get("type").and_then(|v| v.as_str()).unwrap_or("");

        let stream = build_stream_settings(network, security, sni, alpn, host_hdr, path, false, mode, "", "", "")?;
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
        let remark = vm.get("ps").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or(&host);
        let sni_disp = if sni.is_empty() { &host } else { sni };
        let summary = format!(
            "VMESS  •  {}  •  {}  •  SNI: {sni_disp}  ({remark})",
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
    ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
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
        "256" => ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        "128" => ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        _ => ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
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
    let bias = *[Bias::Aes256, Bias::Aes128, Bias::ChaCha].choose(rng).unwrap();
    let grouping = *[Grouping::CipherFirst, Grouping::AuthFirst, Grouping::RsaFirst].choose(rng).unwrap();
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
                let choices: Vec<Grouping> = [Grouping::CipherFirst, Grouping::AuthFirst, Grouping::RsaFirst]
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
                let k = (dna.tail_ecdhe_idx.len() as isize + delta).clamp(0, TAIL_ECDHE_CBC.len() as isize) as usize;
                let mut idx = sample_vec(&[0usize, 1, 2], k, rng);
                idx.sort_unstable();
                dna.tail_ecdhe_idx = idx;
            }
            3 => {
                let delta: isize = if rng.random_bool(0.5) { 1 } else { -1 };
                let k = (dna.tail_rsa_idx.len() as isize + delta).clamp(0, TAIL_STATIC_RSA.len() as isize) as usize;
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
    let mut t13: Vec<&str> = order[..dna.t13_count].iter().map(|f| tls13_suite(f)).collect();
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
    let tag = format!("{prefix}({}|{}|{}s)", dna.bias.tag(), dna.grouping.tag(), suite_count);
    (tag, joined)
}

fn gen_semi_python(rng: &mut impl Rng) -> (String, String) {
    let t13 = sample_vec(
        &["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"],
        3,
        rng,
    );
    let pairs = sample_vec(&[aead_pair("256"), aead_pair("128"), aead_pair("cha")], 3, rng);
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
    let mut t13 = vec!["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"];
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
    let mut t13 = vec!["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384"];
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
        &["TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        k13,
        rng,
    );
    let kp = rng.random_range(2..=3);
    for (e, r) in sample_vec(&[aead_pair("cha"), aead_pair("128"), aead_pair("256")], kp, rng) {
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
    let root = cfg.as_object_mut().ok_or("Config root must be a JSON object")?;

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
            let Some(out_obj) = out.as_object_mut() else { continue };
            let is_tls_out = out_obj
                .get("streamSettings")
                .and_then(|s| s.as_object())
                .map(|s| s.contains_key("tlsSettings") || s.get("security").and_then(|v| v.as_str()) == Some("tls"))
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

                if let Some(stream) = out_obj.get_mut("streamSettings").and_then(|s| s.as_object_mut()) {
                    if override_fm && let Some(fm) = fm_obj {
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

    let p_tag = proxy_tag.ok_or("No TLS outbound found. Make sure your proxy uses TLS (not Reality).")?;
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
    let cfg = prepare_temp_config(&params.base_cfg, Some(cipher), port, params.override_fm, &params.fm_obj)?;

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

    let mut child = cmd.spawn().map_err(|e| format!("Failed to launch xray: {e}"))?;

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
        let resp = client.get(&params.ping_url).send().await.map_err(|e| format!("Ping error: {e}"))?;
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
            return Err(format!("Ping OK ({ping_ms}ms) | DL HTTP {}", dl_resp.status()));
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
            return Err(format!("Ping OK ({ping_ms}ms), DL {dl_kbps}KB/s | UL HTTP {}", ul_resp.status()));
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

            let _ = tx.send(WorkerMsg::Log("--------------------------------------------------------------------".into(), LogLevel::Info));
            let _ = tx.send(WorkerMsg::Log(format!("Target: {}", params.summary), LogLevel::Info));
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
                            format!("[REF] [PASS] Ping: {ping}ms | DL: {dl} KB/s | UL: {ul} KB/s"),
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
                found_list.sort_by(|a, b| a.ping_ms.cmp(&b.ping_ms).then_with(|| b.ul_kbps.cmp(&a.ul_kbps)));
                let mut content = String::new();
                for r in &found_list {
                    content.push_str(&format!(
                        "[{}] Ping={}ms | DL={}KB/s | UL={}KB/s\n{}\n\n",
                        r.tag, r.ping_ms, r.dl_kbps, r.ul_kbps, r.cipher
                    ));
                }
                if let Err(e) = std::fs::write(&params.output_path, content) {
                    let _ = tx.send(WorkerMsg::Log(format!("Failed saving results: {e}"), LogLevel::Warn));
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
                let _ = tx.send(WorkerMsg::Log("Finished with 0 working ciphers found.".into(), LogLevel::Warn));
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
    parsed_summary: Result<String, String>,

    target_found: usize,
    max_attempts: usize,
    timeout_secs: u64,
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
    status_label: String,
    tried_count: usize,
    progress_pct: f32,

    logs: Vec<LogEntry>,
    results: Vec<WorkingResult>,

    rx: Option<Receiver<WorkerMsg>>,
    stop_tx: Option<watch::Sender<bool>>,
}

impl CipherStudioApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG_MAIN;
        visuals.extreme_bg_color = BG_INPUT;
        visuals.widgets.noninteractive.bg_fill = BG_CARD;
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER_CLR);
        visuals.widgets.inactive.bg_fill = BG_CARD2;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER_CLR);
        visuals.widgets.hovered.bg_fill = INDIGO;
        visuals.widgets.active.bg_fill = INDIGO;
        visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(6);
        visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(6);
        visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(6);
        cc.egui_ctx.set_visuals(visuals);

        let base_dir = resolve_base_dir();
        let bin_name = if cfg!(windows) { "xray.exe" } else { "xray" };
        let xray_path = base_dir.join(bin_name);

        let mut app = Self {
            base_dir: base_dir.clone(),
            xray_path: xray_path.clone(),
            proxy_input: String::new(),
            expand_link: false,
            parsed_summary: Err("Waiting for a proxy link (vless://, trojan://, vmess://)...".into()),
            target_found: 5,
            max_attempts: 40,
            timeout_secs: 15,
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
            status_label: "IDLE".into(),
            tried_count: 0,
            progress_pct: 0.0,
            logs: Vec::new(),
            results: Vec::new(),
            rx: None,
            stop_tx: None,
        };
        app.push_log(format!("Ready. Looking for Xray at: {}", xray_path.display()), LogLevel::Info);
        app.push_log("Paste a VLESS / Trojan / VMess link above and click 'Start Search'.", LogLevel::Info);
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
            self.parsed_summary = Err("Waiting for a proxy link (vless://, trojan://, vmess://)...".into());
            return;
        }
        self.parsed_summary = parse_proxy_input(&self.proxy_input).map(|(_, s)| s);
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
                    self.status_label = if stopped { "STOPPED".into() } else { "DONE".into() };
                    finished = true;
                }
            }
        }
        if finished {
            self.rx = None;
            self.stop_tx = None;
        }
    }

    fn start_scan(&mut self) {
        if !self.xray_path.exists() {
            self.push_log(format!("Xray binary not found at: {}", self.xray_path.display()), LogLevel::Fail);
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
            target_found: self.target_found,
            max_attempts: self.max_attempts.max(1),
            timeout_secs: self.timeout_secs.max(3),
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
            self.status_label = "STOPPING...".into();
            self.push_log("Stop requested. Terminating active test...", LogLevel::Warn);
        }
    }

    fn best_result(&self) -> Option<&WorkingResult> {
        self.results
            .iter()
            .min_by(|a, b| a.ping_ms.cmp(&b.ping_ms).then_with(|| b.ul_kbps.cmp(&a.ul_kbps)))
    }

    fn sorted_results(&self) -> Vec<&WorkingResult> {
        let mut list: Vec<&WorkingResult> = self.results.iter().collect();
        match self.result_sort {
            ResultSort::BestPing => {
                list.sort_by(|a, b| a.ping_ms.cmp(&b.ping_ms).then_with(|| b.ul_kbps.cmp(&a.ul_kbps)));
            }
            ResultSort::BestUpload => {
                list.sort_by(|a, b| b.ul_kbps.cmp(&a.ul_kbps).then_with(|| a.ping_ms.cmp(&b.ping_ms)));
            }
            ResultSort::BestDownload => {
                list.sort_by(|a, b| b.dl_kbps.cmp(&a.dl_kbps).then_with(|| a.ping_ms.cmp(&b.ping_ms)));
            }
            ResultSort::OrderFound => {
                list.sort_by_key(|r| r.index);
            }
        }
        list
    }

    fn card_frame() -> egui::Frame {
        egui::Frame {
            fill: BG_CARD,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(8),
            inner_margin: egui::Margin::same(12),
            ..Default::default()
        }
    }

    fn draw_kpi(ui: &mut egui::Ui, label: &str, value: &str, accent: egui::Color32) {
        egui::Frame {
            fill: BG_CARD2,
            stroke: egui::Stroke::new(1.0, BORDER_CLR),
            corner_radius: egui::CornerRadius::same(7),
            inner_margin: egui::Margin::symmetric(12, 8),
            ..Default::default()
        }
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 30.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, egui::CornerRadius::same(2), accent);
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(label).size(9.5).color(FG_MUTED).strong());
                    ui.label(egui::RichText::new(value).size(14.5).color(FG_TEXT).strong());
                });
            });
        });
    }
}

impl eframe::App for CipherStudioApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.is_running {
            ui.ctx().request_repaint_after(Duration::from_millis(80));
        }

        let best_ping = self
            .results
            .iter()
            .map(|r| r.ping_ms)
            .min()
            .map(|p| format!("{p} ms"))
            .unwrap_or_else(|| "--".into());
        let best_ul = self
            .results
            .iter()
            .map(|r| r.ul_kbps)
            .max()
            .map(|u| format!("{u} KB/s"))
            .unwrap_or_else(|| "--".into());
        let found_str = if self.target_found > 0 {
            format!("{} / {}", self.results.len(), self.target_found)
        } else {
            format!("{}", self.results.len())
        };

        egui::CentralPanel::default()
            .frame(egui::Frame {
                fill: BG_MAIN,
                inner_margin: egui::Margin::same(14),
                ..Default::default()
            })
            .show(ui, |ui| {
                // ---- Header Row ----
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("CipherForge")
                                .size(19.0)
                                .color(FG_TEXT)
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new("TLS Cipher Scanner & Evolutionary Optimizer for the F&F Method")
                                .size(11.0)
                                .color(FG_MUTED),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let status_bg = match self.status_label.as_str() {
                            "RUNNING" => EMERALD,
                            "STOPPING..." => AMBER,
                            _ => BG_CARD2,
                        };
                        let status_fg = if self.status_label == "RUNNING" || self.status_label == "STOPPING..." {
                            BG_MAIN
                        } else {
                            SKY
                        };
                        egui::Frame {
                            fill: status_bg,
                            stroke: egui::Stroke::new(1.0, BORDER_CLR),
                            corner_radius: egui::CornerRadius::same(7),
                            inner_margin: egui::Margin::symmetric(14, 8),
                            ..Default::default()
                        }
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(&self.status_label).size(11.5).color(status_fg).strong());
                        });
                    });
                });

                ui.add_space(8.0);

                // ---- 4 Equal-Width KPI Cards ----
                ui.columns(4, |cols| {
                    Self::draw_kpi(&mut cols[0], "FOUND", &found_str, EMERALD);
                    Self::draw_kpi(&mut cols[1], "TRIED", &self.tried_count.to_string(), SKY);
                    Self::draw_kpi(&mut cols[2], "BEST PING", &best_ping, AMBER);
                    Self::draw_kpi(&mut cols[3], "BEST UPLOAD", &best_ul, PURPLE);
                });

                ui.add_space(10.0);

                // ---- Proxy Link Card ----
                Self::card_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("PROXY LINK  (Paste VLESS / Trojan / VMess share link — or JSON)")
                                .size(11.0)
                                .color(SKY)
                                .strong(),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let xray_ok = self.xray_path.exists();
                            let x_clr = if xray_ok { EMERALD_HI } else { ROSE_HI };
                            if ui
                                .button(egui::RichText::new(if xray_ok { "Xray: Ready" } else { "Pick xray.exe" }).color(x_clr).size(11.0))
                                .clicked()
                                && let Some(p) = rfd::FileDialog::new().pick_file()
                            {
                                self.xray_path = p;
                            }

                            if ui.button(if self.expand_link { "Compact" } else { "Expand" }).clicked() {
                                self.expand_link = !self.expand_link;
                            }
                            if ui.button("Load .json").clicked()
                                && let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file()
                                && let Ok(content) = std::fs::read_to_string(&path)
                            {
                                if let Ok(obj) = serde_json::from_str::<Value>(&content)
                                    && let Some(outs) = obj.get("outbounds").and_then(|v| v.as_array())
                                {
                                    for o in outs {
                                        if let Some(s) = o.get("streamSettings")
                                            && let Some(fm) = s.get("finalmask").or_else(|| s.get("finalMask"))
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
                                .add(egui::Button::new(egui::RichText::new("Paste").color(FG_TEXT)).fill(INDIGO))
                                .clicked()
                                && let Ok(mut cb) = arboard::Clipboard::new()
                                && let Ok(txt) = cb.get_text()
                            {
                                self.proxy_input = txt.trim().to_string();
                                self.refresh_proxy_badge();
                            }
                        });
                    });

                    ui.add_space(4.0);
                    let mut changed = false;
                    if self.expand_link {
                        egui::ScrollArea::vertical()
                            .id_salt("proxy_expand_scroll")
                            .max_height(84.0)
                            .show(ui, |ui| {
                                if ui
                                    .add(
                                        egui::TextEdit::multiline(&mut self.proxy_input)
                                            .desired_rows(4)
                                            .desired_width(f32::INFINITY)
                                            .hint_text("vless://...  or  trojan://...  or  vmess://...")
                                            .font(egui::TextStyle::Monospace),
                                    )
                                    .changed()
                                {
                                    changed = true;
                                }
                            });
                    } else if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.proxy_input)
                                .desired_width(f32::INFINITY)
                                .hint_text("vless://...  or  trojan://...  or  vmess://...")
                                .font(egui::TextStyle::Monospace),
                        )
                        .changed()
                    {
                        changed = true;
                    }
                    if changed {
                        self.refresh_proxy_badge();
                    }

                    ui.add_space(4.0);
                    match &self.parsed_summary {
                        Ok(s) => ui.label(egui::RichText::new(format!("[OK]  {s}")).size(11.0).color(EMERALD_HI).strong()),
                        Err(e) => {
                            let clr = if self.proxy_input.trim().is_empty() { FG_MUTED } else { ROSE_HI };
                            ui.label(egui::RichText::new(format!("[!]  {e}")).size(11.0).color(clr))
                        }
                    };
                });

                ui.add_space(8.0);

                // ---- Middle 2 Columns: Strategy & Endpoints ----
                ui.columns(2, |cols| {
                    Self::card_frame().show(&mut cols[0], |ui| {
                        ui.label(egui::RichText::new("SCAN & GENERATION ENGINE").size(11.0).color(INDIGO).strong());
                        ui.add_space(6.0);
                        egui::Grid::new("scan_grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                            ui.label("Target working ciphers (0 = no limit):");
                            ui.add(egui::DragValue::new(&mut self.target_found).range(0..=500));
                            ui.end_row();

                            ui.label("Max attempts:");
                            ui.add(egui::DragValue::new(&mut self.max_attempts).range(1..=1000));
                            ui.end_row();

                            ui.label("HTTP timeout (sec):");
                            ui.add(egui::DragValue::new(&mut self.timeout_secs).range(3..=60));
                            ui.end_row();
                        });

                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Generation engine:").size(11.0).color(FG_MUTED));
                        egui::ComboBox::from_id_salt("strategy_cb")
                            .width(ui.available_width())
                            .selected_text(self.strategy.label())
                            .show_ui(ui, |ui| {
                                for s in Strategy::ALL {
                                    ui.selectable_value(&mut self.strategy, s, s.label());
                                }
                            });

                        ui.add_space(4.0);
                        ui.checkbox(&mut self.run_ref, "Run [REF] F&F baseline benchmark first");
                    });

                    Self::card_frame().show(&mut cols[1], |ui| {
                        ui.label(egui::RichText::new("TEST ENDPOINTS  (Worker-Safe vs Direct/VPS)").size(11.0).color(PURPLE).strong());
                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            ui.allocate_ui(egui::vec2(70.0, 20.0), |ui| {
                                ui.label("Preset:");
                            });
                            let prev = self.preset;
                            egui::ComboBox::from_id_salt("preset_cb")
                                .width(ui.available_width())
                                .selected_text(self.preset.label())
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.preset, EndpointPreset::WorkerSafe, EndpointPreset::WorkerSafe.label());
                                    ui.selectable_value(&mut self.preset, EndpointPreset::CloudflareDirect, EndpointPreset::CloudflareDirect.label());
                                    ui.selectable_value(&mut self.preset, EndpointPreset::Custom, EndpointPreset::Custom.label());
                                });
                            if self.preset != prev {
                                match self.preset {
                                    EndpointPreset::WorkerSafe => {
                                        self.ping_url = "https://www.gstatic.com/generate_204".into();
                                        self.dl_url = "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js".into();
                                        self.ul_url = "https://postman-echo.com/post".into();
                                    }
                                    EndpointPreset::CloudflareDirect => {
                                        self.ping_url = "https://cp.cloudflare.com/generate_204".into();
                                        self.dl_url = "https://speed.cloudflare.com/__down?bytes=100000".into();
                                        self.ul_url = "https://speed.cloudflare.com/__up".into();
                                    }
                                    EndpointPreset::Custom => {}
                                }
                            }
                        });

                        ui.add_space(4.0);
                        for (lbl, val) in [
                            ("Ping (204):", &mut self.ping_url),
                            ("Download:", &mut self.dl_url),
                            ("Upload:", &mut self.ul_url),
                        ] {
                            ui.horizontal(|ui| {
                                ui.allocate_ui(egui::vec2(70.0, 20.0), |ui| {
                                    ui.label(lbl);
                                });
                                if ui.add(
                                    egui::TextEdit::singleline(val)
                                        .desired_width(ui.available_width())
                                        .font(egui::TextStyle::Monospace),
                                ).changed() {
                                    self.preset = EndpointPreset::Custom;
                                }
                            });
                            ui.add_space(3.0);
                        }
                    });
                });

                ui.add_space(8.0);

                // ---- Final Mask Card ----
                Self::card_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("FINAL MASK (finalmask JSON)").size(11.0).color(AMBER).strong());
                        ui.checkbox(&mut self.override_fm, "Apply / Override finalmask");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Validate").clicked() {
                                match serde_json::from_str::<Value>(self.fm_input.trim()) {
                                    Ok(v) => {
                                        self.fm_input = v.to_string();
                                        self.push_log("Final Mask JSON is valid.", LogLevel::Info);
                                    }
                                    Err(e) => self.push_log(format!("Final Mask JSON error: {e}"), LogLevel::Fail),
                                }
                            }
                            if ui.button("F&F Default").clicked() {
                                self.fm_input = DEFAULT_FINALMASK_STR.into();
                            }
                        });
                    });
                    ui.add_space(4.0);
                    egui::ScrollArea::vertical()
                        .id_salt("fm_scroll")
                        .max_height(52.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.fm_input)
                                    .desired_rows(2)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                });

                ui.add_space(8.0);

                // ---- Action Bar + Progress ----
                ui.horizontal(|ui| {
                    let start_fg = if self.is_running { FG_MUTED } else { BG_MAIN };
                    let start_btn = egui::Button::new(egui::RichText::new("Start Search").color(start_fg).strong())
                        .fill(if self.is_running { BG_CARD2 } else { EMERALD });
                    if ui.add_enabled(!self.is_running, start_btn).clicked() {
                        self.start_scan();
                    }

                    let stop_fg = if self.is_running { FG_TEXT } else { FG_MUTED };
                    let stop_btn = egui::Button::new(egui::RichText::new("Stop").color(stop_fg).strong())
                        .fill(if self.is_running { ROSE } else { BG_CARD2 });
                    if ui.add_enabled(self.is_running, stop_btn).clicked() {
                        self.stop_scan();
                    }

                    if ui.add(egui::Button::new("Copy Best CS").fill(INDIGO)).clicked() {
                        if let Some(best) = self.best_result() {
                            let cs = best.cipher.clone();
                            let tag = best.tag.clone();
                            let ping = best.ping_ms;
                            let ul = best.ul_kbps;
                            ui.copy_text(cs);
                            self.push_log(
                                format!("Copied best cipher ({tag}, Ping={ping}ms, UL={ul}KB/s)."),
                                LogLevel::Info,
                            );
                        } else {
                            self.push_log("No working ciphers found yet.", LogLevel::Warn);
                        }
                    }

                    if ui.add(egui::Button::new("Copy Best Config").fill(PURPLE)).clicked() {
                        if let Some(best) = self.best_result() {
                            let cs = best.cipher.clone();
                            let tag = best.tag.clone();
                            let ping = best.ping_ms;
                            match build_exported_config(&self.proxy_input, &cs, self.override_fm, &self.fm_input) {
                                Ok(exported) => {
                                    ui.copy_text(exported);
                                    self.push_log(
                                        format!("Copied full F&F config ({tag}, Ping={ping}ms) to clipboard!"),
                                        LogLevel::Info,
                                    );
                                }
                                Err(e) => self.push_log(format!("Export error: {e}"), LogLevel::Fail),
                            }
                        } else {
                            self.push_log("No working ciphers found yet.", LogLevel::Warn);
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Clear Log").clicked() {
                            self.logs.clear();
                        }
                        if ui.selectable_label(self.active_tab == ActiveTab::Results, format!("Working Results ({})", self.results.len())).clicked() {
                            self.active_tab = ActiveTab::Results;
                        }
                        if ui.selectable_label(self.active_tab == ActiveTab::Console, "Live Console").clicked() {
                            self.active_tab = ActiveTab::Console;
                        }
                    });
                });

                ui.add_space(6.0);
                let bar_w = ui.available_width();
                let (bar_rect, _) = ui.allocate_exact_size(egui::vec2(bar_w, 8.0), egui::Sense::hover());
                ui.painter().rect_filled(bar_rect, egui::CornerRadius::same(4), BG_CARD2);
                let pct = self.progress_pct.clamp(0.0, 1.0);
                if pct > 0.0 {
                    let mut fill_rect = bar_rect;
                    fill_rect.set_width((bar_rect.width() * pct).max(8.0));
                    ui.painter().rect_filled(fill_rect, egui::CornerRadius::same(4), EMERALD);
                }
                ui.add_space(6.0);

                // ---- Output Area (Console / Results) ----
                egui::Frame {
                    fill: BG_INPUT,
                    stroke: egui::Stroke::new(1.0, BORDER_CLR),
                    corner_radius: egui::CornerRadius::same(8),
                    inner_margin: egui::Margin::same(10),
                    ..Default::default()
                }
                .show(ui, |ui| {
                    let avail = ui.available_size();
                    ui.set_min_size(avail);

                    match self.active_tab {
                        ActiveTab::Console => {
                            egui::ScrollArea::vertical()
                                .stick_to_bottom(true)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    for entry in &self.logs {
                                        let color = match entry.level {
                                            LogLevel::Info => SKY,
                                            LogLevel::Pass => EMERALD_HI,
                                            LogLevel::Fail => ROSE_HI,
                                            LogLevel::Warn => AMBER,
                                            LogLevel::Cipher => PURPLE,
                                        };
                                        ui.label(
                                            egui::RichText::new(format!("[{}] {}", entry.time, entry.text))
                                                .monospace()
                                                .size(11.5)
                                                .color(color),
                                        );
                                    }
                                });
                        }
                        ActiveTab::Results => {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Sort by:").color(FG_MUTED).size(11.0));
                                ui.selectable_value(&mut self.result_sort, ResultSort::BestPing, "Best Ping");
                                ui.selectable_value(&mut self.result_sort, ResultSort::BestUpload, "Best Upload");
                                ui.selectable_value(&mut self.result_sort, ResultSort::BestDownload, "Best Download");
                                ui.selectable_value(&mut self.result_sort, ResultSort::OrderFound, "Order Found");
                            });
                            ui.add_space(6.0);

                            let sorted = self.sorted_results();
                            let mut copy_cs_msg: Option<(String, String)> = None;
                            let mut copy_cfg_msg: Option<(String, String)> = None;

                            egui::ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    if sorted.is_empty() {
                                        ui.label(egui::RichText::new("No working cipher suites found yet.").color(FG_MUTED));
                                    } else {
                                        for r in sorted {
                                            egui::Frame {
                                                fill: BG_CARD,
                                                stroke: egui::Stroke::new(1.0, BORDER_CLR),
                                                corner_radius: egui::CornerRadius::same(6),
                                                inner_margin: egui::Margin::same(8),
                                                ..Default::default()
                                            }
                                            .show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    ui.label(egui::RichText::new(format!("#{}", r.index)).color(FG_MUTED).strong());
                                                    ui.label(egui::RichText::new(&r.tag).color(SKY).strong());
                                                    ui.label(egui::RichText::new(format!("Ping: {}ms", r.ping_ms)).color(AMBER));
                                                    ui.label(egui::RichText::new(format!("DL: {} KB/s", r.dl_kbps)).color(EMERALD_HI));
                                                    ui.label(egui::RichText::new(format!("UL: {} KB/s", r.ul_kbps)).color(PURPLE));
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if ui.add(egui::Button::new("Copy Config").fill(INDIGO)).clicked() {
                                                            copy_cfg_msg = Some((r.cipher.clone(), r.tag.clone()));
                                                        }
                                                        if ui.button("Copy CS").clicked() {
                                                            copy_cs_msg = Some((r.cipher.clone(), r.tag.clone()));
                                                        }
                                                    });
                                                });
                                                ui.label(egui::RichText::new(&r.cipher).monospace().size(10.5).color(FG_TEXT));
                                            });
                                            ui.add_space(4.0);
                                        }
                                    }
                                });

                            if let Some((cs, tag)) = copy_cs_msg {
                                ui.copy_text(cs);
                                self.push_log(format!("Copied CS ({tag}) to clipboard."), LogLevel::Info);
                            }
                            if let Some((cs, tag)) = copy_cfg_msg {
                                match build_exported_config(&self.proxy_input, &cs, self.override_fm, &self.fm_input) {
                                    Ok(exported) => {
                                        ui.copy_text(exported);
                                        self.push_log(format!("Copied full F&F config ({tag}) to clipboard!"), LogLevel::Info);
                                    }
                                    Err(e) => self.push_log(format!("Export error: {e}"), LogLevel::Fail),
                                }
                            }
                        }
                    }
                });
            });
    }
}

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1040.0, 760.0])
        .with_min_inner_size([880.0, 640.0]);

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