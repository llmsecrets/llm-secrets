// scrt4/src/cli.rs — CLI client for the scrt4 daemon
//!
//! Connects to the scrt4-daemon via Unix socket and sends JSON commands.
//! Usage:
//!   scrt4 setup                     Register WebAuthn credential
//!   scrt4 unlock [--ttl SECS]       Unlock vault via WebAuthn
//!   scrt4 status                    Check session status
//!   scrt4 list                      List secret names
//!   scrt4 run 'command'             Run command with $env[NAME] substitution
//!   scrt4 add KEY=VALUE [...]       Add secrets to active session
//!   scrt4 clear                     Clear session
//!   scrt4 extend [--ttl SECS]       Extend session timer
//!   scrt4 daemon                    Start the daemon (foreground)

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("scrt4.sock")
    } else {
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/scrt4-{}.sock", uid))
    }
}

fn send_request(request_json: &str) -> Result<serde_json::Value, String> {
    let socket_path = get_socket_path();

    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("Cannot connect to daemon at {:?}: {}. Is scrt4 daemon running? Start with: scrt4 daemon", socket_path, e))?;

    // Send request as a single JSON line
    stream.write_all(format!("{}\n", request_json).as_bytes())
        .map_err(|e| format!("Failed to send request: {}", e))?;
    stream.flush()
        .map_err(|e| format!("Failed to flush: {}", e))?;

    // Read response line
    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    serde_json::from_str(&response_line)
        .map_err(|e| format!("Invalid response: {}", e))
}

fn print_result(response: &serde_json::Value) {
    let success = response.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = response.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }

    // Handle different response data types
    if let Some(data) = response.get("data") {
        // Status response
        if let Some(active) = data.get("active") {
            let active = active.as_bool().unwrap_or(false);
            let remaining = data.get("remaining").and_then(|v| v.as_i64()).unwrap_or(0);
            if active {
                if remaining < 0 {
                    println!("Session active (no expiry)");
                } else {
                    let hours = remaining / 3600;
                    let mins = (remaining % 3600) / 60;
                    println!("Session active ({:02}h {:02}m remaining)", hours, mins);
                }
            } else {
                println!("No active session");
            }
            return;
        }

        // List response
        if let Some(names) = data.get("names").and_then(|v| v.as_array()) {
            println!("{} secret(s):", names.len());
            for name in names {
                if let Some(n) = name.as_str() {
                    println!("  {}", n);
                }
            }
            return;
        }

        // Run response
        if let Some(output) = data.get("output").and_then(|v| v.as_str()) {
            let exit_code = data.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1);
            print!("{}", output);
            if exit_code != 0 {
                std::process::exit(exit_code as i32);
            }
            return;
        }

        // Unlocked response
        if let Some(count) = data.get("count").and_then(|v| v.as_u64()) {
            println!("Unlocked ({} secrets)", count);
            return;
        }

        // Extended response
        if let Some(remaining) = data.get("remaining").and_then(|v| v.as_i64()) {
            let hours = remaining / 3600;
            let mins = (remaining % 3600) / 60;
            println!("Session extended ({:02}h {:02}m remaining)", hours, mins);
            return;
        }

        // WaState response
        if let Some(configured) = data.get("configured").and_then(|v| v.as_bool()) {
            let enabled = data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let unlock_enabled = data.get("unlock_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("WebAuthn configured: {}", configured);
            println!("WebAuthn 2FA (reveal): {}", if enabled { "enabled" } else { "disabled" });
            println!("WebAuthn 2FA (unlock): {}", if unlock_enabled { "enabled" } else { "disabled" });
            return;
        }

        // Reveal response
        if let Some(value) = data.get("value").and_then(|v| v.as_str()) {
            println!("{}", value);
            return;
        }

        // Generic data
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    } else {
        println!("OK");
    }
}

fn usage() {
    eprintln!("scrt4 — WebAuthn PRF secret manager");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  scrt4 daemon                     Start the daemon (foreground)");
    eprintln!("  scrt4 setup                      Register WebAuthn credential via browser");
    eprintln!("  scrt4 unlock [--ttl SECS]         Unlock vault via WebAuthn (default: 2h)");
    eprintln!("  scrt4 status                     Check session status");
    eprintln!("  scrt4 list                       List secret names");
    eprintln!("  scrt4 run 'command'              Run command with $env[NAME] substitution");
    eprintln!("  scrt4 add KEY=VALUE [...]         Add secrets to active session");
    eprintln!("  scrt4 clear                      Clear session");
    eprintln!("  scrt4 extend [--ttl SECS]         Extend session timer");
    eprintln!("  scrt4 wa-state                   Check WebAuthn 2FA state");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        usage();
    }

    let command = args[1].as_str();

    match command {
        "daemon" => {
            // Exec the daemon binary
            let err = exec_daemon();
            eprintln!("Failed to exec daemon: {}", err);
            std::process::exit(1);
        }

        "setup" => {
            run_setup_flow();
        }

        "unlock" => {
            let ttl = parse_ttl_arg(&args[2..]);
            run_unlock_flow(ttl);
        }

        "status" => {
            let resp = send_request(r#"{"method":"status"}"#).unwrap_or_else(|e| {
                eprintln!("{}", e);
                std::process::exit(1);
            });
            print_result(&resp);
        }

        "list" => {
            let resp = send_request(r#"{"method":"list"}"#).unwrap_or_else(|e| {
                eprintln!("{}", e);
                std::process::exit(1);
            });
            print_result(&resp);
        }

        "run" => {
            if args.len() < 3 {
                eprintln!("Usage: scrt4 run 'command with $env[NAME]'");
                std::process::exit(1);
            }
            let command = args[2..].join(" ");
            let request = serde_json::json!({
                "method": "run",
                "params": {
                    "command": command
                }
            });
            let resp = send_request(&request.to_string()).unwrap_or_else(|e| {
                eprintln!("{}", e);
                std::process::exit(1);
            });
            print_result(&resp);
        }

        "add" => {
            if args.len() < 3 {
                eprintln!("Usage: scrt4 add KEY=VALUE [KEY2=VALUE2 ...]");
                std::process::exit(1);
            }
            let mut secrets = serde_json::Map::new();
            for arg in &args[2..] {
                if let Some(eq_pos) = arg.find('=') {
                    let key = &arg[..eq_pos];
                    let value = &arg[eq_pos + 1..];
                    secrets.insert(key.to_string(), serde_json::Value::String(value.to_string()));
                } else {
                    eprintln!("Invalid format: '{}'. Use KEY=VALUE", arg);
                    std::process::exit(1);
                }
            }
            let request = serde_json::json!({
                "method": "add_secrets",
                "params": {
                    "secrets": secrets
                }
            });
            let resp = send_request(&request.to_string()).unwrap_or_else(|e| {
                eprintln!("{}", e);
                std::process::exit(1);
            });
            print_result(&resp);
        }

        "clear" => {
            let resp = send_request(r#"{"method":"clear"}"#).unwrap_or_else(|e| {
                eprintln!("{}", e);
                std::process::exit(1);
            });
            print_result(&resp);
        }

        "extend" => {
            let ttl = parse_ttl_arg(&args[2..]);
            let request = if let Some(ttl) = ttl {
                format!(r#"{{"method":"extend","params":{{"ttl":{}}}}}"#, ttl)
            } else {
                r#"{"method":"extend"}"#.to_string()
            };
            let resp = send_request(&request).unwrap_or_else(|e| {
                eprintln!("{}", e);
                std::process::exit(1);
            });
            print_result(&resp);
        }

        "wa-state" => {
            let resp = send_request(r#"{"method":"check_wa_state"}"#).unwrap_or_else(|e| {
                eprintln!("{}", e);
                std::process::exit(1);
            });
            print_result(&resp);
        }

        "--help" | "-h" | "help" => {
            usage();
        }

        _ => {
            eprintln!("Unknown command: {}", command);
            usage();
        }
    }
}

fn parse_ttl_arg(args: &[String]) -> Option<u64> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--ttl" && i + 1 < args.len() {
            return args[i + 1].parse().ok();
        }
        i += 1;
    }
    None
}

fn exec_daemon() -> String {
    // Find the daemon binary next to the CLI binary
    let current_exe = std::env::current_exe().unwrap_or_default();
    let daemon_path = current_exe.parent()
        .map(|p| p.join("scrt4-daemon"))
        .unwrap_or_else(|| PathBuf::from("scrt4-daemon"));

    if daemon_path.exists() {
        let err = std::process::Command::new(&daemon_path)
            .exec_not_available();
        return format!("{}", err);
    }

    // Try PATH
    match std::process::Command::new("scrt4-daemon")
        .status()
    {
        Ok(status) => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => format!("{}", e),
    }
}

trait ExecNotAvailable {
    fn exec_not_available(&mut self) -> String;
}

impl ExecNotAvailable for std::process::Command {
    fn exec_not_available(&mut self) -> String {
        // On Unix, use exec to replace the process
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = self.exec();
            return format!("{}", err);
        }
        #[cfg(not(unix))]
        {
            match self.status() {
                Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                Err(e) => format!("{}", e),
            }
        }
    }
}

// ── QR code rendering ──────────────────────────────────────────────

fn print_qr(url: &str) {
    use qrcode::QrCode;

    let code = match QrCode::new(url.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Open this URL on your phone: {}", url);
            return;
        }
    };

    let width = code.width();
    let data = code.into_colors();
    let quiet = 2;
    let total_w = width + quiet * 2;
    let total_h = width + quiet * 2;

    println!();
    let mut row = 0;
    while row < total_h {
        print!("  ");
        for col in 0..total_w {
            let top_dark = if row >= quiet && row < quiet + width && col >= quiet && col < quiet + width {
                data[(row - quiet) * width + (col - quiet)] == qrcode::Color::Dark
            } else {
                false
            };
            let bot_dark = if row + 1 >= quiet && row + 1 < quiet + width && col >= quiet && col < quiet + width {
                data[(row + 1 - quiet) * width + (col - quiet)] == qrcode::Color::Dark
            } else {
                false
            };
            match (top_dark, bot_dark) {
                (true, true)   => print!("\u{2588}"),
                (true, false)  => print!("\u{2580}"),
                (false, true)  => print!("\u{2584}"),
                (false, false) => print!(" "),
            }
        }
        println!();
        row += 2;
    }
    println!();
}

// ── Relay polling ──────────────────────────────────────────────────

fn poll_relay(session_id: &str) -> String {
    let url = format!("https://auth.llmsecrets.com/api/relay/{}", session_id);

    loop {
        let output = std::process::Command::new("curl")
            .args(&["-sf", &url])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let body = String::from_utf8_lossy(&o.stdout).to_string();
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                if let Some(payload) = parsed.get("payload").and_then(|v| v.as_str()) {
                    return payload.to_string();
                }
                eprintln!("Invalid relay response");
                std::process::exit(1);
            }
            _ => {
                // Not ready yet
                std::thread::sleep(std::time::Duration::from_millis(1500));
            }
        }
    }
}

// ── Two-phase setup flow ──────────────────────────────────────────

fn run_setup_flow() {
    // Phase 1: Get relay URL from daemon
    let resp = send_request(r#"{"method":"setup_webauthn"}"#).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });

    if !resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        let error = resp.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }

    let data = resp.get("data").unwrap();
    let url = data.get("url").and_then(|v| v.as_str()).unwrap();
    let session_id = data.get("session_id").and_then(|v| v.as_str()).unwrap();
    let wrapping_key = data.get("wrapping_key").and_then(|v| v.as_str()).unwrap();
    let prf_salt_b64 = data.get("prf_salt_b64").and_then(|v| v.as_str()).unwrap();

    // Phase 2: Display QR code and poll relay
    print_qr(url);
    println!("  Scan the QR code with your phone camera.");
    println!("  Then tap 'Register with Bitwarden' on the page.\n");
    eprintln!("  Waiting for phone...");

    let payload = poll_relay(session_id);

    // Phase 3: Send to daemon for completion
    let complete_req = serde_json::json!({
        "method": "setup_webauthn_complete",
        "params": {
            "encrypted_payload": payload,
            "wrapping_key": wrapping_key,
            "prf_salt_b64": prf_salt_b64
        }
    });
    let resp = send_request(&complete_req.to_string()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });

    if resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        println!("Credential registered successfully!");
    } else {
        let error = resp.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }
}

fn run_unlock_flow(ttl: Option<u64>) {
    // Phase 1: Get relay URL from daemon
    let request = serde_json::json!({
        "method": "unlock_webauthn",
        "params": { "ttl": ttl.unwrap_or(7200) }
    });
    let resp = send_request(&request.to_string()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });

    if !resp.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        let error = resp.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }

    let data = match resp.get("data") {
        Some(d) => d,
        None => { println!("OK"); return; }
    };

    // Check if it's a relay response or direct response
    if let Some(url) = data.get("url").and_then(|v| v.as_str()) {
        let session_id = data.get("session_id").and_then(|v| v.as_str()).unwrap();
        let wrapping_key = data.get("wrapping_key").and_then(|v| v.as_str()).unwrap();

        print_qr(url);
        println!("  Scan the QR code with your phone camera.");
        println!("  Then tap 'Unlock with Passkey' on the page.\n");
        eprintln!("  Waiting for phone...");

        let payload = poll_relay(session_id);

        let complete_req = serde_json::json!({
            "method": "unlock_webauthn_complete",
            "params": {
                "encrypted_payload": payload,
                "wrapping_key": wrapping_key,
                "ttl": ttl.unwrap_or(7200)
            }
        });
        let resp = send_request(&complete_req.to_string()).unwrap_or_else(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        });
        print_result(&resp);
    } else {
        // Direct response (already unlocked or error)
        print_result(&resp);
    }
}
