// wsl2-helper/scrt-client/src/main.rs
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("scrt.sock")
    } else {
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/scrt-{}.sock", uid))
    }
}

fn send_request(request: &serde_json::Value) -> Result<serde_json::Value, String> {
    let socket_path = get_socket_path();

    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("Connection failed: {}. Is the daemon running?", e))?;

    let json = serde_json::to_string(request).unwrap();
    writeln!(stream, "{}", json).map_err(|e| format!("Write failed: {}", e))?;

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response).map_err(|e| format!("Read failed: {}", e))?;

    serde_json::from_str(&response).map_err(|e| format!("Parse failed: {}", e))
}

fn print_usage() {
    eprintln!("Usage: scrt-client <command> [args...]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  store <ttl>      - Read JSON {{token, secrets}} from stdin");
    eprintln!("  clear            - Clear session");
    eprintln!("  status           - Check session status");
    eprintln!("  list             - List secret names");
    eprintln!("  run '<command>'  - Run with $env[NAME] substitution");
    eprintln!("  reveal <name>    - Get secret value (GUI only)");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let command = &args[1];

    let result = match command.as_str() {
        "store" => {
            if args.len() < 3 {
                eprintln!("ERROR: TTL required");
                std::process::exit(1);
            }
            let ttl: u64 = args[2].parse().unwrap_or(0);

            // Read JSON from stdin
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).expect("Failed to read stdin");

            let input_json: serde_json::Value = serde_json::from_str(&input)
                .expect("Invalid JSON input");

            send_request(&serde_json::json!({
                "method": "store",
                "params": {
                    "token": input_json["token"],
                    "secrets": input_json["secrets"],
                    "ttl": ttl
                }
            }))
        }

        "clear" => send_request(&serde_json::json!({"method": "clear"})),

        "status" => send_request(&serde_json::json!({"method": "status"})),

        "list" => send_request(&serde_json::json!({"method": "list"})),

        "run" => {
            if args.len() < 3 {
                eprintln!("ERROR: Command required");
                std::process::exit(1);
            }
            let cmd = args[2..].join(" ");
            let working_dir = env::current_dir().ok().map(|p| p.to_string_lossy().to_string());

            send_request(&serde_json::json!({
                "method": "run",
                "params": {
                    "command": cmd,
                    "working_dir": working_dir
                }
            }))
        }

        "reveal" => {
            if args.len() < 3 {
                eprintln!("ERROR: Secret name required");
                std::process::exit(1);
            }
            send_request(&serde_json::json!({
                "method": "reveal",
                "params": {"name": &args[2]}
            }))
        }

        _ => {
            eprintln!("ERROR: Unknown command '{}'", command);
            print_usage();
            std::process::exit(1);
        }
    };

    match result {
        Ok(response) => {
            if response["success"] == true {
                if let Some(data) = response.get("data") {
                    // Format output based on command
                    match command.as_str() {
                        "status" => {
                            let active = data["active"].as_bool().unwrap_or(false);
                            let remaining = data["remaining"].as_i64().unwrap_or(0);
                            if active {
                                if remaining < 0 {
                                    println!("ACTIVE:no_expiry");
                                } else {
                                    println!("ACTIVE:{}", remaining);
                                }
                            } else {
                                println!("INACTIVE");
                            }
                        }
                        "list" => {
                            if let Some(names) = data["names"].as_array() {
                                for name in names {
                                    println!("{}", name.as_str().unwrap_or(""));
                                }
                            }
                        }
                        "run" => {
                            let output = data["output"].as_str().unwrap_or("");
                            let exit_code = data["exit_code"].as_i64().unwrap_or(0);
                            print!("{}", output);
                            std::process::exit(exit_code as i32);
                        }
                        "reveal" => {
                            println!("{}", data["value"].as_str().unwrap_or(""));
                        }
                        _ => println!("OK"),
                    }
                } else {
                    println!("OK");
                }
            } else {
                eprintln!("ERROR: {}", response["error"].as_str().unwrap_or("Unknown error"));
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    }
}
