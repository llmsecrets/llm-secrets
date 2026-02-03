// wsl2-helper/src/sanitize.rs
use std::collections::HashMap;

/// Sanitize output by replacing secret values with [REDACTED:NAME]
pub fn sanitize_output(output: &str, secrets: &HashMap<String, String>) -> String {
    let mut result = output.to_string();

    for (name, value) in secrets {
        if !value.is_empty() {
            result = result.replace(value, &format!("[REDACTED:{}]", name));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_single_secret() {
        let mut secrets = HashMap::new();
        secrets.insert("API_KEY".to_string(), "sk_live_123".to_string());

        let output = "Using key: sk_live_123";
        let sanitized = sanitize_output(output, &secrets);

        assert_eq!(sanitized, "Using key: [REDACTED:API_KEY]");
    }

    #[test]
    fn test_sanitize_multiple_secrets() {
        let mut secrets = HashMap::new();
        secrets.insert("KEY1".to_string(), "value1".to_string());
        secrets.insert("KEY2".to_string(), "value2".to_string());

        let output = "First: value1, Second: value2";
        let sanitized = sanitize_output(output, &secrets);

        assert_eq!(sanitized, "First: [REDACTED:KEY1], Second: [REDACTED:KEY2]");
    }

    #[test]
    fn test_sanitize_empty_value() {
        let mut secrets = HashMap::new();
        secrets.insert("EMPTY".to_string(), "".to_string());

        let output = "No change here";
        let sanitized = sanitize_output(output, &secrets);

        assert_eq!(sanitized, "No change here");
    }

    #[test]
    fn test_sanitize_multiple_occurrences() {
        let mut secrets = HashMap::new();
        secrets.insert("TOKEN".to_string(), "abc123".to_string());

        let output = "Token: abc123, again: abc123";
        let sanitized = sanitize_output(output, &secrets);

        assert_eq!(sanitized, "Token: [REDACTED:TOKEN], again: [REDACTED:TOKEN]");
    }
}
