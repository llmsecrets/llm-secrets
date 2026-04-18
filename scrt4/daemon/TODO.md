# scrt4 TODO

## Phase 1: Push-Based Pairing (no QR after first scan)
- [ ] Generate VAPID keys for relay server (Web Push)
- [ ] Add relay endpoints: `POST /pair`, `POST /push`, `GET /devices`
- [ ] Add service worker (`sw.js`) to auth.html for push notifications
- [ ] After first successful ceremony, register push subscription on phone
- [ ] Daemon stores paired device ID in `~/.scrt4/paired-devices.json`
- [ ] On unlock: daemon asks relay to push notification to paired phone
- [ ] Phone auto-opens auth page, runs ceremony, posts to relay
- [ ] Fallback: if push fails or no paired device, fall back to QR/URL

## Phase 2: Headless / CLI Support
- [x] QR code rendered in terminal (already works via `show_qr_terminal`)
- [x] Always print the raw URL alongside QR for copy-paste in headless envs
- [x] Challenge/reveal flow: terminal prompt fallback (no Zenity required)
- [x] `scrt4 view --cli` mode that prints to stdout
- [x] `scrt4 add` works fully from CLI args (already did: `scrt4 add K=V`)
- [x] Remove Zenity as a hard dependency — optional enhancement only
- [ ] Test all commands over SSH (no DISPLAY, no dbus) — manual testing needed

## Phase 3: WA-Gated Reveal (replace GUI codes with WebAuthn)
- [ ] When `wa-on`: `reveal`/`reveal_all` triggers WebAuthn QR/push flow
- [ ] Replace 6-digit confirmation with phone-based WebAuthn approval
- [ ] Add `RevealAllWebauthn` / `RevealAllConfirmWebauthn` request variants
- [ ] Branch in handlers on `is_wa_enabled()` for reveal operations
- [ ] Update bash `cmd_view` to detect RelaySetup response and run QR flow

## Phase 4: Platform-Agnostic Cleanup
- [x] Remove `wslpath` + `cmd.exe` as hardcoded — now uses platform detection (wslpath/xdg-open/open)
- [x] Remove "WSL2" from version string and branding
- [x] Replace `sudo apt install` messages with generic guidance
- [x] Rust: use `dirs::home_dir()` everywhere (audit.rs, remote.rs fixed; keystore.rs already done)
- [x] Rust: gate `sh -c` / `cmd /c` in subprocess.rs with cfg
- [x] Rust: fix "wsl2-helper" module name comments
- [ ] Rust: gate `UnixStream` with `#[cfg(unix)]`, add TCP listener option for non-Unix
- [ ] Rust: gate `libc::getuid()` with `#[cfg(unix)]` fallback
- [ ] Test on: native Linux, macOS (manual testing needed)
