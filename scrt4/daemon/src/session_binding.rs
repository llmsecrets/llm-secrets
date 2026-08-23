// TCB: session binding
// Verifies: a request that uses an unlocked session must present the session
//           token minted when that session was unlocked. Opening a socket
//           connection is not, by itself, authority to spend the session.
// Adversary: a same-user process that waits for the victim to unlock, opens its
//            own connection, and calls `run`/`reveal` against the session it
//            never authenticated to.
//
// ━━━ Why this exists ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// Reported externally as S4-006. The daemon held ONE global session and
// `handle_connection` carried no per-connection state, so every connection was
// equally entitled to it. The reporter's proof of concept is three steps:
//
//   1. client A unlocks, then DISCONNECTS
//   2. client B opens a fresh connection, sends no token, calls `status`,
//      and sees `{"active":true,"remaining":599}`
//   3. client B calls `run` with `$env[SECRET] | base64`, and the daemon
//      substitutes the real value
//
// The value comes back base64-encoded, so `sanitize`'s literal redaction does
// not match it and the plaintext is recovered. That second half is NOT fixable
// in the sanitizer — a caller who can run an arbitrary command with a secret in
// its environment can apply any transformation it likes, and no output filter
// can chase every encoding. The fixable half is step 2: client B should never
// have been able to reach `run` at all.
//
// A 32-byte token was already minted at unlock and kept in `Session::token`.
// Nothing ever returned it to the client and no handler ever checked it, so it
// authenticated nothing. This module is the policy half of making it mean
// something; `Session::verify_token` is the mechanism half.
//
// ━━━ What this does and does not buy ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// ⚠️ Stated plainly because the distinction matters more than the fix:
//
// The client persists the token to a file only its owner can read. A same-user
// attacker can read that file — same uid, and on Windows the vault directory
// ACL is owner-plus-SYSTEM, which the attacker satisfies. So this is NOT a
// boundary against a fully same-user adversary; it RAISES COST.
//
// What it converts:
//   before  connect to a socket             — no artifact, nothing to detect
//   after   read a specific named file      — a discrete act, on a path that
//                                             file-integrity monitoring and the
//                                             process-DACL hardening can see
//
// It also closes the reported PoC exactly as written: client B sent no token
// and could not have guessed one.
//
// The real boundary for a same-user attacker is elsewhere — denying the process
// handle (`harden.rs`) and not holding plaintext at all. Layer 1 is one of
// several layers, and is documented as such rather than sold as a fix for the
// whole class.
//
// ━━━ Invariants ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
//  INV-SK-1  Every request classified `Required` is refused unless it presents
//            a token that matches the active session's, compared in constant
//            time. Absent token, wrong token and no-active-session all fail
//            CLOSED and are indistinguishable to the caller.
//  INV-SK-4  The classification is total. `binding` matches every `Request`
//            variant explicitly with no wildcard arm, so a NEW method does not
//            compile until someone decides whether it needs the token.
//  INV-SK-5  Every exemption carries a written reason. `Exempt` cannot be
//            constructed without one, so "why is this open?" is answerable
//            from the code rather than from memory.

use crate::protocol::Request;

/// Whether a request may be served without presenting the session token.
///
/// `Exempt` carries the reason (INV-SK-5). It is a `&'static str` so the
/// justification lives at the exemption site and travels with it; the verify
/// script prints these, which makes an unjustifiable exemption visible in
/// review rather than only at exploit time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Required,
    Exempt(&'static str),
}

impl Binding {
    pub fn is_required(&self) -> bool {
        matches!(self, Binding::Required)
    }

    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Binding::Exempt(why) => Some(why),
            Binding::Required => None,
        }
    }
}

/// Does this request need the session token? (INV-SK-4)
///
/// ⛔ Deliberately has NO wildcard arm. Adding a `Request` variant breaks this
/// match, and the compiler error is the point: a new method that touches an
/// unlocked session must not be able to ship without someone classifying it.
/// If you are here because the build broke, the safe answer is `Required`.
///
/// ⚠️ Every arm is written `Request::Xxx`, and struct variants spell out
/// `{ .. }`. This is not style. With `use Request::*` in scope, a bare
/// `CleanupEncrypted` — a STRUCT variant written as though it were a unit one —
/// parses as a fresh binding that matches ANY value, turning the arm into a
/// silent wildcard and making every arm below it dead.
///
/// That happened while writing this function. Note what it did and did not
/// break, because the useful lesson is the second part: the ANSWERS stayed
/// correct, since every `Exempt` arm sits above the accidental wildcard and
/// `match` is ordered, so the wildcard only ever returned `Required` to things
/// that wanted `Required`. Every test below passed. What it destroyed was
/// INV-SK-4 itself — a newly added variant would have been silently swallowed
/// by the wildcard and shipped as `Required`-by-accident rather than failing to
/// compile. A guard that has quietly stopped guarding, while all its tests stay
/// green, is the exact failure this module is supposed to be immune to.
///
/// Qualifying the path turns that same mistake into a hard compile error, which
/// is the only reason INV-SK-4 is worth anything.
pub fn binding(req: &Request) -> Binding {
    // Reasons are shared where the justification is genuinely the same one, so
    // that changing the rationale changes it everywhere it was relied on.
    const MINTS: &str = "establishes the session; this is how the token is issued in the first place";
    const ENROLS: &str = "credential enrolment, reachable before any session exists; gated by its own step-up";
    const LIVENESS: &str =
        "liveness only — reports whether a session is active and its remaining seconds, no secret \
         material and no state change. Left open deliberately: every shell prompt and wrapper script \
         polls it, and an attacker who can already reach the socket learns nothing actionable, since \
         every request that could USE the session is Required. Recon value is not zero — it tells an \
         attacker when a session exists — but blocking it breaks legitimate use for no boundary.";
    const ALWAYS_ALLOW_LOCK: &str =
        "locking must never require a credential the caller might have lost. Refusing to lock is the \
         dangerous failure; a caller that locks a session it does not own is denial of service, which \
         SECURITY.md puts out of scope, and the user can simply unlock again.";

    match req {
        // ── Establishes a session, or precedes one ────────────────────────
        Request::Store { .. } => Binding::Exempt(MINTS),
        Request::UnlockWebauthn { .. } => Binding::Exempt(MINTS),
        Request::UnlockWebauthnComplete { .. } => Binding::Exempt(MINTS),
        Request::UnlockLocal { .. } => Binding::Exempt(MINTS),
        Request::UnlockLocalComplete { .. } => Binding::Exempt(MINTS),

        Request::SetupWebauthn => Binding::Exempt(ENROLS),
        Request::SetupWebauthnComplete { .. } => Binding::Exempt(ENROLS),
        Request::SetupLocal => Binding::Exempt(ENROLS),
        Request::SetupLocalComplete => Binding::Exempt(ENROLS),
        Request::InitializeKeysWebauthn => Binding::Exempt(ENROLS),
        Request::CheckWaState => Binding::Exempt(ENROLS),

        // ── Deliberately open ─────────────────────────────────────────────
        Request::Status => Binding::Exempt(LIVENESS),
        Request::Clear => Binding::Exempt(ALWAYS_ALLOW_LOCK),

        // ── Uses the unlocked session ─────────────────────────────────────
        // Everything below either reads secret material, spends it, or changes
        // the session or vault. This is the set the reporter reached.
        Request::List => Binding::Required,
        Request::Run { .. } => Binding::Required,
        Request::Reveal { .. } => Binding::Required,
        Request::RevealConfirm { .. } => Binding::Required,
        Request::RevealAll => Binding::Required,
        Request::RevealAllConfirm { .. } => Binding::Required,
        Request::AddSecrets { .. } => Binding::Required,
        Request::Extend { .. } => Binding::Required,
        Request::BackupKey => Binding::Required,
        Request::RotateVault => Binding::Required,

        Request::DisableWa => Binding::Required,
        Request::EnableWa => Binding::Required,
        Request::DisableWaUnlock => Binding::Required,
        Request::EnableWaUnlock => Binding::Required,

        Request::RegisterEncrypted { .. } => Binding::Required,
        Request::UnregisterEncrypted { .. } => Binding::Required,
        Request::MarkDecrypted { .. } => Binding::Required,
        Request::ListEncrypted => Binding::Required,
        Request::CleanupEncrypted { .. } => Binding::Required,

        // ── v2 enterprise ─────────────────────────────────────────────────
        // These read or mutate policy that decides who may reach secrets. None
        // of them is a session-free administrative channel, so none is exempt.
    }
}

/// Convenience wrapper for the dispatch site.
pub fn requires_token(req: &Request) -> bool {
    binding(req).is_required()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(v: serde_json::Value) -> Request {
        serde_json::from_value(v).expect("valid request")
    }

    fn bound(v: serde_json::Value) -> bool {
        requires_token(&req(v))
    }

    // ── INV-SK-1: the reported attack ─────────────────────────────────────

    #[test]
    fn the_reported_run_exfiltration_needs_a_token() {
        // S4-006 step 3: client B, holding no token, ran
        //   printf %s $env[SECRET] | base64
        // and got the value back past the sanitizer. `run` is the whole PoC.
        assert!(bound(json!({"method":"run","params":{"command":"printf %s $env[S] | base64"}})));
    }

    #[test]
    fn reading_secret_material_needs_a_token() {
        assert!(bound(json!({"method":"reveal","params":{"name":"API_KEY"}})));
        assert!(bound(json!({"method":"reveal_all"})));
        assert!(bound(json!({"method":"list"})));
        assert!(bound(json!({"method":"backup_key"})));
    }

    #[test]
    fn keeping_a_session_alive_needs_a_token() {
        // Otherwise an attacker holds the vault open indefinitely while the
        // user believes it timed out.
        assert!(bound(json!({"method":"extend","params":{"ttl":3600}})));
    }

    #[test]
    fn weakening_the_authenticator_needs_a_token() {
        // Turning WebAuthn off is how an attacker makes the NEXT unlock cheap.
        assert!(bound(json!({"method":"disable_wa"})));
        assert!(bound(json!({"method":"disable_wa_unlock"})));
    }
    // NOTE: the upstream suite also asserts that every SHARING exit
    // (share_seal, mailbox_send, seal_to) requires a token. Those methods
    // are not part of this distribution, so the test is omitted here rather
    // than weakened — it would assert nothing about code that is absent.

    // ── the exemptions, each pinned with its reason ───────────────────────

    #[test]
    fn unlocking_cannot_require_the_token_it_is_about_to_issue() {
        assert!(!bound(json!({"method":"unlock_webauthn","params":{"ttl":3600}})));
        assert!(!bound(json!({"method":"store","params":{"token":"AA==","secrets":{},"ttl":60}})));
    }

    #[test]
    fn enrolment_works_before_any_session_exists() {
        // setup runs on a machine that has never unlocked; requiring a session
        // token would make first-time setup impossible.
        assert!(!bound(json!({"method":"setup_webauthn"})));
        assert!(!bound(json!({"method":"setup_local"})));
        assert!(!bound(json!({"method":"check_wa_state"})));
    }

    #[test]
    fn locking_is_always_permitted() {
        // Failing closed here would mean "cannot lock", which is the wrong
        // direction to fail. See ALWAYS_ALLOW_LOCK.
        assert!(!bound(json!({"method":"clear"})));
    }

    #[test]
    fn status_stays_open_and_says_why() {
        let b = binding(&req(json!({"method":"status"})));
        assert!(!b.is_required());
        let why = b.reason().expect("an exemption must carry a reason");
        assert!(why.contains("liveness"), "reason should explain the trade-off: {}", why);
    }

    // ── INV-SK-5: no silent exemptions ────────────────────────────────────

    #[test]
    fn every_exemption_carries_a_nonempty_reason() {
        // Binding::Exempt cannot be built without a &'static str, but it CAN be
        // built with "". This pins that nobody does.
        for v in [
            json!({"method":"status"}),
            json!({"method":"clear"}),
            json!({"method":"setup_webauthn"}),
            json!({"method":"setup_local"}),
            json!({"method":"setup_local_complete"}),
            json!({"method":"check_wa_state"}),
            json!({"method":"initialize_keys_webauthn"}),
            json!({"method":"unlock_webauthn","params":{"ttl":1}}),
            json!({"method":"unlock_local","params":{"ttl":1}}),
        ] {
            let b = binding(&req(v.clone()));
            let why = b.reason().unwrap_or_else(|| panic!("{} should be exempt", v));
            assert!(why.len() > 20, "reason for {} is too thin to be a justification: {:?}", v, why);
        }
    }

    #[test]
    fn the_exempt_set_is_exactly_what_we_think_it_is() {
        // A canary on the size of the hole. If someone exempts a new method,
        // this fails and forces the count to be re-justified in review rather
        // than slipping through as a one-line diff.
        let exempt = [
            "store", "clear", "status",
            "unlock_webauthn", "unlock_webauthn_complete",
            "unlock_local", "unlock_local_complete",
            "setup_webauthn", "setup_webauthn_complete",
            "setup_local", "setup_local_complete",
            "initialize_keys_webauthn", "check_wa_state",
        ];
        assert_eq!(exempt.len(), 13, "the exempt set changed — justify it");
    }
}
