// scrt4/src/subprocess.rs
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

// NOTE: `shell_quote` used to live here, in two cfg-gated forms. Its only
// purpose was making a secret value survive as a literal inside the command
// string — which is the defect itself, because that string becomes the child's
// argv. Removed rather than left unused, so it cannot quietly come back, and
// the whole class of quoting bugs goes with it.

/// Environment-variable name a secret is exposed under inside the child.
///
/// Namespaced rather than using the bare secret name, so that a secret called
/// `PATH`, `HOME` or `IFS` cannot clobber the child's real environment. The
/// `$env[NAME]` syntax remains the user-facing contract.
fn env_var_name(secret_name: &str) -> String {
    format!("SCRT4_ENV_{}", secret_name)
}

/// Shell reference that expands to the secret at runtime, inside the child.
///
/// Double-quoted so whitespace and newlines in the value survive expansion,
/// which is also what lets multi-line secrets (SSH keys, PEM) work here.
#[cfg(unix)]
fn env_ref(secret_name: &str) -> String {
    format!("\"${}\"", env_var_name(secret_name))
}

#[cfg(not(unix))]
fn env_ref(secret_name: &str) -> String {
    format!("\"%{}%\"", env_var_name(secret_name))
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
                result.replace_range(full_match.range(), &env_ref(secret_name));
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
    let (substituted_cmd, used_secrets) = substitute_secrets(command, all_secrets)?;

    tracing::info!("Running command (secrets substituted)");

    // Run via platform shell
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(&substituted_cmd);
        c
    };
    #[cfg(not(unix))]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("cmd");
        c.arg("/c");
        // raw_arg, not arg: `arg` applies MSVC argv escaping, which cmd.exe does
        // not use. The command string now carries only %SCRT4_ENV_*% references
        // and never a secret value, so the escaping hazard that used to matter
        // here — including cmd expanding a %NAME% that appeared inside a secret —
        // is gone along with the splicing.
        c.as_std_mut().raw_arg(&substituted_cmd);
        c
    };

    // The values reach the child ONLY through its environment, and only the
    // secrets this command actually references — never the whole vault.
    // /proc/<pid>/environ is mode 0400 and owner-only; /proc/<pid>/cmdline is
    // world-readable, which is precisely why the value is no longer in the
    // command string.
    for (name, value) in &used_secrets {
        cmd.env(env_var_name(name), value);
    }

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

    // Sanitize ALL secrets (not just used ones) from output.
    // Dev mode (SCRT4_DEV_MODE=1) skips sanitization so contributors can
    // see the actual command output during testing — the dev distribution
    // is already documented "do not store real secrets". See issue #59.
    let dev_mode = std::env::var("SCRT4_DEV_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let output_str = if dev_mode {
        combined
    } else {
        sanitize_output(&combined, all_secrets)
    };

    Ok(RunResult {
        exit_code,
        output: output_str,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rewritten test asserts the same property: the command REFERENCES
    /// the secret, and never CONTAINS it. These tests previously asserted the
    /// spliced value, i.e. they encoded the defect - so they are inverted
    /// rather than deleted, keeping the behaviour covered.
    fn assert_no_plaintext(cmd: &str, values: &[&str]) {
        for v in values {
            assert!(
                !cmd.contains(v),
                "value {:?} appears in the command string, which becomes the                  child's argv and is world-readable via /proc/<pid>/cmdline:
  {}",
                v, cmd
            );
        }
    }

    #[test]
    fn test_substitute_single() {
        let mut secrets = HashMap::new();
        secrets.insert("KEY".to_string(), "value123".to_string());

        let (result, used) = substitute_secrets("echo $env[KEY]", &secrets).unwrap();

        assert_no_plaintext(&result, &["value123"]);
        assert!(result.contains("SCRT4_ENV_KEY"), "must reference the env var: {}", result);
        assert_eq!(used.get("KEY"), Some(&"value123".to_string()));
    }

    #[test]
    fn test_substitute_multiple() {
        let mut secrets = HashMap::new();
        secrets.insert("A".to_string(), "aaa".to_string());
        secrets.insert("B".to_string(), "bbb".to_string());

        let (result, used) = substitute_secrets("$env[A] and $env[B]", &secrets).unwrap();

        assert_no_plaintext(&result, &["aaa", "bbb"]);
        assert!(result.contains("SCRT4_ENV_A") && result.contains("SCRT4_ENV_B"));
        assert_eq!(used.len(), 2);
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

        assert_no_plaintext(&result, &["admin", "secret"]);
        assert!(result.contains("SCRT4_ENV_USER") && result.contains("SCRT4_ENV_PASS"));
        assert!(result.contains(':'), "the literal separator must survive: {}", result);
    }

    #[test]
    fn test_substitute_shell_metacharacters() {
        // The old code had to shell-quote these. A reference cannot carry them
        // at all, so the whole class of quoting bugs disappears with the value.
        let mut secrets = HashMap::new();
        secrets.insert("PASS".to_string(), "h3llo W*rld!".to_string());

        let (result, _) = substitute_secrets("VAR=$env[PASS] cmd", &secrets).unwrap();

        assert_no_plaintext(&result, &["h3llo W*rld!", "W*rld"]);
        assert!(result.starts_with("VAR="), "surrounding text preserved: {}", result);
        assert!(result.ends_with(" cmd"));
    }

    #[test]
    fn test_substitute_embedded_double_quote() {
        // Previously asserted the exact escaping of embedded quotes. There is
        // nothing left to escape.
        let mut secrets = HashMap::new();
        secrets.insert("SQ".to_string(), "it's here".to_string());
        secrets.insert("DQ".to_string(), "say \"hi\" now".to_string());

        let (r1, _) = substitute_secrets("echo $env[SQ]", &secrets).unwrap();
        let (r2, _) = substitute_secrets("echo $env[DQ]", &secrets).unwrap();

        assert_no_plaintext(&r1, &["it's here"]);
        assert_no_plaintext(&r2, &["say \"hi\" now", "hi"]);
    }

    #[test]
    fn no_secret_value_reaches_the_command_string() {
        // The command string becomes the argument to `sh -c` / `cmd /c`, i.e.
        // the child's argv. On Linux /proc/<pid>/cmdline is world-readable, so a
        // value here is disclosed to every local user for the lifetime of the
        // command - not merely to the same user.
        let mut secrets = HashMap::new();
        let sensitive = [
            ("API", "sk_live_deadbeefcafe"),
            ("MULTI", "-----BEGIN KEY-----
line2
-----END KEY-----"),
            ("WEIRD", "va'lue\"with$pecials"),
        ];
        for (k, v) in sensitive {
            secrets.insert(k.to_string(), v.to_string());
        }

        let (cmd, used) =
            substitute_secrets("run $env[API] $env[MULTI] $env[WEIRD]", &secrets).unwrap();

        for (_, v) in sensitive {
            assert!(!cmd.contains(v), "value {:?} leaked into:
  {}", v, cmd);
        }
        assert_eq!(used.len(), 3);
        assert_eq!(used.get("API").map(String::as_str), Some("sk_live_deadbeefcafe"));
    }

    #[test]
    fn env_var_is_namespaced_so_it_cannot_clobber_the_child() {
        // A secret named PATH must not become $PATH in the child.
        assert_eq!(env_var_name("PATH"), "SCRT4_ENV_PATH");
        assert_ne!(env_var_name("PATH"), "PATH");
        let mut secrets = HashMap::new();
        secrets.insert("PATH".to_string(), "/evil".to_string());
        let (cmd, _) = substitute_secrets("echo $env[PATH]", &secrets).unwrap();
        assert!(cmd.contains("SCRT4_ENV_PATH"));
        assert!(!cmd.contains("/evil"));
    }

    #[test]
    fn multiline_secret_reference_is_double_quoted() {
        // Double quoting preserves newlines when the shell expands the variable;
        // an unquoted $VAR would word-split an SSH key.
        let mut secrets = HashMap::new();
        secrets.insert("K".to_string(), "a
b".to_string());
        let (cmd, _) = substitute_secrets("cat $env[K]", &secrets).unwrap();
        assert!(cmd.contains('"'), "reference must be double-quoted: {}", cmd);
        assert!(!cmd.contains("a
b"));
    }
}
