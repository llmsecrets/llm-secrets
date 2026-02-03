// wsl2-helper/tests/integration.rs
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use base64::Engine;

fn start_daemon() -> Child {
    Command::new("cargo")
        .args(["run", "--release"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start daemon")
}

fn get_socket_path() -> String {
    std::env::var("XDG_RUNTIME_DIR")
        .map(|d| format!("{}/scrt.sock", d))
        .unwrap_or_else(|_| format!("/tmp/scrt-{}.sock", unsafe { libc::getuid() }))
}

fn send_request(request: &serde_json::Value) -> serde_json::Value {
    let socket_path = get_socket_path();

    let mut stream = UnixStream::connect(&socket_path).expect("Connect failed");
    writeln!(stream, "{}", serde_json::to_string(request).unwrap()).unwrap();

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();

    serde_json::from_str(&response).unwrap()
}

#[test]
#[ignore] // Run with: cargo test --test integration -- --ignored
fn test_full_workflow() {
    // Start daemon
    let mut daemon = start_daemon();
    thread::sleep(Duration::from_millis(1000));

    // Store session
    let token = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let mut secrets = HashMap::new();
    secrets.insert("API_KEY".to_string(), "sk_test_123".to_string());
    secrets.insert("DB_PASS".to_string(), "secret_password".to_string());

    let store_resp = send_request(&serde_json::json!({
        "method": "store",
        "params": {
            "token": token,
            "secrets": secrets,
            "ttl": 3600
        }
    }));
    assert!(store_resp["success"].as_bool().unwrap(), "Store failed: {:?}", store_resp);

    // Check status
    let status_resp = send_request(&serde_json::json!({"method": "status"}));
    assert!(status_resp["data"]["active"].as_bool().unwrap(), "Session not active");

    // List secrets
    let list_resp = send_request(&serde_json::json!({"method": "list"}));
    let names = list_resp["data"]["names"].as_array().unwrap();
    assert!(names.iter().any(|n| n == "API_KEY"), "API_KEY not in list");
    assert!(names.iter().any(|n| n == "DB_PASS"), "DB_PASS not in list");

    // Run with substitution
    let run_resp = send_request(&serde_json::json!({
        "method": "run",
        "params": {
            "command": "echo $env[API_KEY]",
            "working_dir": null
        }
    }));
    assert!(run_resp["success"].as_bool().unwrap(), "Run failed: {:?}", run_resp);
    // Output should be sanitized
    let output = run_resp["data"]["output"].as_str().unwrap();
    assert!(output.contains("[REDACTED:API_KEY]"), "Output not sanitized: {}", output);

    // Clear session
    let clear_resp = send_request(&serde_json::json!({"method": "clear"}));
    assert!(clear_resp["success"].as_bool().unwrap(), "Clear failed");

    // Verify cleared
    let status2_resp = send_request(&serde_json::json!({"method": "status"}));
    assert!(!status2_resp["data"]["active"].as_bool().unwrap(), "Session should be inactive");

    // Cleanup
    daemon.kill().unwrap();
}

#[test]
#[ignore]
fn test_missing_secret() {
    let mut daemon = start_daemon();
    thread::sleep(Duration::from_millis(1000));

    // Store session
    let token = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let mut secrets = HashMap::new();
    secrets.insert("ONLY_KEY".to_string(), "value".to_string());

    send_request(&serde_json::json!({
        "method": "store",
        "params": {
            "token": token,
            "secrets": secrets,
            "ttl": 3600
        }
    }));

    // Try to use non-existent secret
    let run_resp = send_request(&serde_json::json!({
        "method": "run",
        "params": {
            "command": "echo $env[MISSING_SECRET]",
            "working_dir": null
        }
    }));

    assert!(!run_resp["success"].as_bool().unwrap_or(true), "Should fail for missing secret");
    assert!(run_resp["error"].as_str().unwrap().contains("not found"), "Should mention secret not found");

    daemon.kill().unwrap();
}

#[test]
#[ignore]
fn test_no_session() {
    let mut daemon = start_daemon();
    thread::sleep(Duration::from_millis(1000));

    // Try to run without session
    let run_resp = send_request(&serde_json::json!({
        "method": "run",
        "params": {
            "command": "echo hello",
            "working_dir": null
        }
    }));

    assert!(!run_resp["success"].as_bool().unwrap_or(true), "Should fail without session");

    daemon.kill().unwrap();
}
