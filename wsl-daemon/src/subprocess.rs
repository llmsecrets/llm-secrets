// wsl2-helper/src/subprocess.rs
use regex::Regex;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;

use crate::sanitize::sanitize_output;

/// Result of running a command
pub struct RunResult {
    pub exit_code: i32,
    pub output: String,  // Sanitized
}

/// Substitute $env[NAME] patterns with actual secret values
fn substitute_secrets(command: &str, secrets: &HashMap<String, String>) -> Result<(String, HashMap<String, String>), String> {
    let re = Regex::new(r"\$env\[([^\]]+)\]").unwrap();
    let mut result = command.to_string();
    let mut used_secrets = HashMap::new();

    // Find all matches first
    let matches: Vec<_> = re.captures_iter(command).collect();

    // Process in reverse to preserve indices
    for cap in matches.into_iter().rev() {
        let full_match = cap.get(0).unwrap();
        let secret_name = cap.get(1).unwrap().as_str();

        match secrets.get(secret_name) {
            Some(value) => {
                used_secrets.insert(secret_name.to_string(), value.clone());
                result.replace_range(full_match.range(), value);
            }
            None => {
                return Err(format!("Secret not found: {}", secret_name));
            }
        }
    }

    Ok((result, used_secrets))
}

/// Run a command with secret substitution and output sanitization
pub async fn run_with_secrets(
    command: &str,
    working_dir: Option<&str>,
    all_secrets: &HashMap<String, String>,
) -> Result<RunResult, String> {
    // Substitute $env[NAME] patterns
    let (substituted_cmd, _used_secrets) = substitute_secrets(command, all_secrets)?;

    tracing::info!("Running command (secrets substituted)");

    // Run via shell
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(&substituted_cmd);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = cmd.output().await
        .map_err(|e| format!("Failed to run command: {}", e))?;

    let exit_code = output.status.code().unwrap_or(-1);

    // Combine stdout and stderr
    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        combined.push_str("\n[stderr]\n");
        combined.push_str(&stderr);
    }

    // Sanitize ALL secrets (not just used ones) from output
    let sanitized = sanitize_output(&combined, all_secrets);

    Ok(RunResult {
        exit_code,
        output: sanitized,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_single() {
        let mut secrets = HashMap::new();
        secrets.insert("KEY".to_string(), "value123".to_string());

        let (result, used) = substitute_secrets("echo $env[KEY]", &secrets).unwrap();

        assert_eq!(result, "echo value123");
        assert_eq!(used.get("KEY"), Some(&"value123".to_string()));
    }

    #[test]
    fn test_substitute_multiple() {
        let mut secrets = HashMap::new();
        secrets.insert("A".to_string(), "aaa".to_string());
        secrets.insert("B".to_string(), "bbb".to_string());

        let (result, _) = substitute_secrets("$env[A] and $env[B]", &secrets).unwrap();

        assert_eq!(result, "aaa and bbb");
    }

    #[test]
    fn test_substitute_missing() {
        let secrets = HashMap::new();

        let result = substitute_secrets("$env[MISSING]", &secrets);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Secret not found: MISSING"));
    }

    #[test]
    fn test_substitute_no_secrets() {
        let secrets = HashMap::new();

        let (result, used) = substitute_secrets("echo hello", &secrets).unwrap();

        assert_eq!(result, "echo hello");
        assert!(used.is_empty());
    }

    #[test]
    fn test_substitute_adjacent() {
        let mut secrets = HashMap::new();
        secrets.insert("USER".to_string(), "admin".to_string());
        secrets.insert("PASS".to_string(), "secret".to_string());

        let (result, _) = substitute_secrets("$env[USER]:$env[PASS]", &secrets).unwrap();

        assert_eq!(result, "admin:secret");
    }
}
