//! **LLM Secrets** — hardware-bound secrets for AI coding agents.
//!
//! This crate is the project's namespace on crates.io. It carries no
//! implementation: the tool you want is [`scrt4`](https://crates.io/crates/scrt4).
//!
//! ```sh
//! cargo install scrt4
//! ```
//!
//! # What the project does
//!
//! When an agent with shell access reads a `.env` file, the values land in
//! its context window, the prompt cache, and every error pasted afterwards.
//! scrt4 keeps them in an encrypted vault instead. The agent writes a command
//! containing a placeholder; the daemon substitutes the real value into that
//! one subprocess and scrubs it back out of the output.
//!
//! ```text
//! scrt4 add STRIPE_SECRET_KEY=sk_live_...
//! scrt4 run 'stripe --api-key $env[STRIPE_SECRET_KEY] charges list'
//! ```
//!
//! The agent sees the command. It never sees the value.
//!
//! The vault key is derived from a FIDO2 authenticator via the WebAuthn PRF
//! extension and is never written to disk — so unlike an encrypted `.env`,
//! there is no key file for an agent to read.
//!
//! # Not to be confused with
//!
//! The `llm-secrets` crate (with a hyphen) is an unrelated project by a
//! different author. This one is <https://llmsecrets.com>.

/// Where releases are published. Binaries are checksum-verified by the
/// installer, and `scrt4 verify-self` re-checks a running binary against the
/// same manifest.
pub const DOWNLOADS: &str = "https://llmsecrets.com/downloads";

/// Source and issue tracker.
pub const REPOSITORY: &str = "https://github.com/llmsecrets/llm-secrets";

/// Documentation.
pub const DOCS: &str = "https://docs.llmsecrets.com";

/// The crate that actually installs the tool.
pub const CLI_CRATE: &str = "scrt4";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_https_and_point_at_the_project() {
        for url in [DOWNLOADS, REPOSITORY, DOCS] {
            assert!(url.starts_with("https://"), "{url} is not https");
        }
        assert!(DOWNLOADS.contains("llmsecrets.com"));
        assert!(DOCS.contains("llmsecrets.com"));
        assert!(REPOSITORY.contains("llmsecrets/llm-secrets"));
    }

    #[test]
    fn points_at_the_unhyphenated_cli_crate() {
        // `llm-secrets` is someone else's crate; naming it here by accident
        // would send people to the wrong project.
        assert_eq!(CLI_CRATE, "scrt4");
    }
}
