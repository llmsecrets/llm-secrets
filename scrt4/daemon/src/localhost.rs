//! Localhost WebAuthn server for scrt4.
//!
//! Starts a temporary HTTP server on 127.0.0.1:9474 that serves a self-contained
//! WebAuthn authentication page. The browser handles BLE/hybrid transport natively,
//! so no internet connection is needed.
//!
//! Flow:
//!   1. Daemon starts HTTP server, returns URL to CLI
//!   2. CLI opens browser with URL
//!   3. Browser does WebAuthn ceremony (with phone via BLE hybrid)
//!   4. Browser POSTs encrypted PRF output to localhost:9474/callback
//!   5. Daemon receives callback, decrypts, unlocks vault

use std::sync::Arc;
use axum::{Router, Json, response::Html, extract::State as AxumState};
use tokio::sync::{mpsc, oneshot, Mutex};

const PORT: u16 = 9474;

// ── Server state ─────────────────────────────────────────────────────

struct ServerState {
    html: String,
    sender: Mutex<Option<mpsc::Sender<String>>>,
}

/// A running localhost WebAuthn server.
pub struct LocalServer {
    pub url: String,
    receiver: mpsc::Receiver<String>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl LocalServer {
    /// Wait for the browser callback, with timeout.
    pub async fn wait_for_callback(&mut self, timeout_secs: u64) -> Result<String, String> {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            self.receiver.recv(),
        ).await {
            Ok(Some(payload)) => Ok(payload),
            Ok(None) => Err("Server channel closed unexpectedly".into()),
            Err(_) => Err(format!(
                "Timed out after {}s waiting for browser authentication",
                timeout_secs
            )),
        }
    }

    /// Shut down the HTTP server.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ── Pending state (shared between handler calls) ────────────────────

pub struct PendingLocalAuth {
    pub server: LocalServer,
    pub wrapping_key: String,
    pub prf_salt_b64: String,
}

static PENDING: std::sync::OnceLock<Mutex<Option<PendingLocalAuth>>> = std::sync::OnceLock::new();

fn pending() -> &'static Mutex<Option<PendingLocalAuth>> {
    PENDING.get_or_init(|| Mutex::new(None))
}

/// Store a pending local auth (replaces any existing one).
pub async fn set_pending(auth: PendingLocalAuth) {
    let mut guard = pending().lock().await;
    if let Some(mut old) = guard.take() {
        old.server.shutdown();
    }
    *guard = Some(auth);
}

/// Take the pending local auth (removes it from storage).
pub async fn take_pending() -> Option<PendingLocalAuth> {
    pending().lock().await.take()
}

// ── HTTP server ─────────────────────────────────────────────────────

/// Start the localhost WebAuthn server.
pub async fn start(
    mode: &str,
    challenge_b64: &str,
    salt_b64: &str,
    wrapping_key_hex: &str,
    credential_id_b64: Option<&str>,
) -> Result<LocalServer, String> {
    let (tx, rx) = mpsc::channel::<String>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let state = Arc::new(ServerState {
        html: build_html(mode, challenge_b64, salt_b64, wrapping_key_hex, credential_id_b64),
        sender: Mutex::new(Some(tx)),
    });

    let app = Router::new()
        .route("/", axum::routing::get(serve_html))
        .route("/callback", axum::routing::post(handle_callback))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", PORT);
    let listener = tokio::net::TcpListener::bind(&addr).await
        .map_err(|e| format!(
            "Failed to bind {} — is another scrt4 unlock running? ({})",
            addr, e
        ))?;

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async { let _ = shutdown_rx.await; })
            .await
            .ok();
    });

    tracing::info!("Localhost WebAuthn server started on {}", addr);

    Ok(LocalServer {
        url: format!("http://localhost:{}", PORT),
        receiver: rx,
        shutdown_tx: Some(shutdown_tx),
    })
}

async fn serve_html(
    AxumState(state): AxumState<Arc<ServerState>>,
) -> Html<String> {
    Html(state.html.clone())
}

async fn handle_callback(
    AxumState(state): AxumState<Arc<ServerState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let payload = body.get("payload")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if !payload.is_empty() {
        let mut sender = state.sender.lock().await;
        if let Some(tx) = sender.take() {
            let _ = tx.send(payload).await;
            tracing::info!("Received WebAuthn callback from browser");
        }
    }

    Json(serde_json::json!({"ok": true}))
}

// ── HTML template ────────────────────────────────────────────────────

fn build_html(
    mode: &str,
    challenge_b64: &str,
    salt_b64: &str,
    wrapping_key_hex: &str,
    credential_id_b64: Option<&str>,
) -> String {
    HTML_TEMPLATE
        .replace("__MODE__", mode)
        .replace("__MODE_LABEL__", if mode == "register" { "Register New Credential" } else { "Authenticate" })
        .replace("__BTN_LABEL__", if mode == "register" { "Register Passkey" } else { "Unlock with Passkey" })
        .replace("__CHALLENGE__", challenge_b64)
        .replace("__SALT__", salt_b64)
        .replace("__WRAPPING_KEY__", wrapping_key_hex)
        .replace("__CRED_ID__", &match credential_id_b64 {
            Some(id) => format!("'{}'", id),
            None => "null".to_string(),
        })
}

const HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LLM Secrets — Authenticate</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#0a0a0a;color:#e5e5e5;padding:20px}
    .container{background:#1a1a1a;padding:32px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.4);text-align:center;max-width:380px;width:100%;border:1px solid #333}
    .logo{font-size:28px;font-weight:700;margin-bottom:4px;color:#fff}
    .subtitle{color:#888;font-size:14px;margin-bottom:24px}
    #status{color:#888;margin:16px 0;font-size:14px;min-height:20px}
    .success{color:#22c55e!important}
    .error{color:#ef4444!important}
    .spinner{display:none;width:28px;height:28px;border:3px solid #333;border-top:3px solid #3b82f6;border-radius:50%;animation:spin .8s linear infinite;margin:20px auto}
    @keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
    #startBtn{background:#3b82f6;color:#fff;border:none;padding:16px 32px;border-radius:12px;font-size:17px;font-weight:600;cursor:pointer;width:100%;transition:background .2s}
    #startBtn:hover{background:#2563eb}
    #startBtn:active{background:#1d4ed8;transform:scale(.98)}
    #startBtn:disabled{background:#374151;cursor:not-allowed;color:#9ca3af}
    .lock-icon{font-size:48px;margin-bottom:16px}
    .footer{margin-top:24px;font-size:12px;color:#555}
    #debugLog{margin-top:16px;text-align:left;font-size:11px;color:#555;font-family:monospace;max-height:150px;overflow-y:auto;border-top:1px solid #222;padding-top:8px;word-break:break-all}
    #debugLog div{margin-bottom:2px}
  </style>
</head>
<body>
  <div class="container">
    <div class="lock-icon" id="lockIcon">&#x1f512;</div>
    <div class="logo">LLM Secrets</div>
    <div class="subtitle" id="modeLabel">__MODE_LABEL__</div>
    <button id="startBtn">__BTN_LABEL__</button>
    <div class="spinner" id="spinner"></div>
    <p id="status"></p>
    <div id="debugLog"></div>
    <div class="footer">Local authentication &middot; No internet required</div>
  </div>
  <script>
    const MODE = '__MODE__';
    const CHALLENGE_B64 = '__CHALLENGE__';
    const SALT_B64 = '__SALT__';
    const WRAPPING_KEY_HEX = '__WRAPPING_KEY__';
    const CRED_ID_B64 = __CRED_ID__;
    const RP_ID = 'localhost';

    const logEl = document.getElementById('debugLog');
    function log(msg) {
      const d = document.createElement('div');
      d.textContent = new Date().toLocaleTimeString() + ' ' + msg;
      logEl.appendChild(d);
      logEl.scrollTop = logEl.scrollHeight;
    }
    window.onerror = (msg, src, line) => { log('UNCAUGHT: ' + msg); showError('Error: ' + msg); };
    window.onunhandledrejection = (e) => { log('REJECTION: ' + (e.reason?.message || e.reason)); showError('Error: ' + (e.reason?.message || e.reason)); };

    const status = document.getElementById('status');
    const btn = document.getElementById('startBtn');

    function showError(msg) {
      document.getElementById('spinner').style.display = 'none';
      status.className = 'error';
      status.textContent = msg;
      btn.style.display = 'block';
      btn.disabled = false;
    }

    function b64ToBytes(b64) {
      let f = b64.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
      while (f.length % 4) f += '=';
      return Uint8Array.from(atob(f), c => c.charCodeAt(0));
    }
    function bytesToB64(bytes) { return btoa(String.fromCharCode(...bytes)); }
    function hexToBytes(hex) {
      const b = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) b[i/2] = parseInt(hex.substr(i, 2), 16);
      return b;
    }

    async function encryptPayload(data, keyHex) {
      const keyBytes = hexToBytes(keyHex);
      const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const pt = new TextEncoder().encode(JSON.stringify(data));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
      const combined = new Uint8Array(iv.length + ct.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(ct), iv.length);
      return bytesToB64(combined);
    }

    async function sendCallback(encrypted) {
      log('Sending to localhost...');
      const resp = await fetch('/callback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encrypted })
      });
      log('Callback: ' + resp.status);
      if (!resp.ok) throw new Error('Callback failed: ' + resp.status);
    }

    log('Ready. mode=' + MODE + ' rpId=' + RP_ID);

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.style.display = 'none';
      document.getElementById('spinner').style.display = 'block';

      try {
        if (!window.PublicKeyCredential) throw new Error('WebAuthn not supported');

        const challenge = b64ToBytes(CHALLENGE_B64);
        const salt = b64ToBytes(SALT_B64);
        log('Challenge: ' + challenge.length + 'B, Salt: ' + salt.length + 'B');

        if (MODE === 'register') {
          status.textContent = 'Creating passkey...';
          log('Creating credential with PRF...');

          const credential = await navigator.credentials.create({
            publicKey: {
              challenge,
              rp: { id: RP_ID, name: 'LLM Secrets' },
              user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: 'llmsecrets-user',
                displayName: 'LLM Secrets User'
              },
              pubKeyCredParams: [
                { type: 'public-key', alg: -7 },
                { type: 'public-key', alg: -257 }
              ],
              authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'required'
              },
              extensions: { prf: { eval: { first: salt } } }
            }
          });

          log('Credential created! rawId: ' + credential.rawId.byteLength + 'B');
          const ext = credential.getClientExtensionResults();
          log('Extensions: ' + JSON.stringify(ext));
          let prfOutput;

          if (ext.prf && ext.prf.results && ext.prf.results.first) {
            prfOutput = new Uint8Array(ext.prf.results.first);
          } else if (ext.prf && ext.prf.enabled) {
            status.textContent = 'PRF needs a second tap...';
            log('PRF enabled but no output — doing get()...');
            const credId = new Uint8Array(credential.rawId);
            const assertion = await navigator.credentials.get({
              publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                rpId: RP_ID,
                allowCredentials: [{ type: 'public-key', id: credId }],
                userVerification: 'required',
                extensions: { prf: { eval: { first: salt } } }
              }
            });
            const prf2 = assertion.getClientExtensionResults().prf;
            if (!prf2 || !prf2.results || !prf2.results.first) throw new Error('PRF failed on second attempt');
            prfOutput = new Uint8Array(prf2.results.first);
          } else {
            throw new Error('PRF not supported. Extensions: ' + JSON.stringify(ext));
          }

          log('PRF output: ' + prfOutput.length + 'B');
          status.textContent = 'Encrypting...';

          const credId = new Uint8Array(credential.rawId);
          const pubKey = new Uint8Array(credential.response.getPublicKey());
          const authData = new Uint8Array(credential.response.getAuthenticatorData());
          const aaguid = Array.from(authData.slice(37, 53)).map(b => b.toString(16).padStart(2, '0')).join('');

          const encrypted = await encryptPayload({
            type: 'register',
            credential_id: bytesToB64(credId),
            public_key: bytesToB64(pubKey),
            prf_output: bytesToB64(prfOutput),
            aaguid,
            authenticator_name: 'WebAuthn'
          }, WRAPPING_KEY_HEX);

          status.textContent = 'Completing...';
          await sendCallback(encrypted);

        } else {
          status.textContent = 'Authenticating...';
          log('Getting assertion with PRF...');
          const credentialId = b64ToBytes(CRED_ID_B64);

          const assertion = await navigator.credentials.get({
            publicKey: {
              challenge,
              rpId: RP_ID,
              allowCredentials: [{ type: 'public-key', id: credentialId }],
              userVerification: 'required',
              extensions: { prf: { eval: { first: salt } } }
            }
          });

          log('Assertion received');
          const ext = assertion.getClientExtensionResults();
          log('Extensions: ' + JSON.stringify(ext));
          if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
            throw new Error('PRF not supported. Extensions: ' + JSON.stringify(ext));
          }

          const prfOutput = new Uint8Array(ext.prf.results.first);
          log('PRF output: ' + prfOutput.length + 'B');

          status.textContent = 'Encrypting...';
          const encrypted = await encryptPayload({
            type: 'auth',
            prf_output: bytesToB64(prfOutput)
          }, WRAPPING_KEY_HEX);

          status.textContent = 'Completing...';
          await sendCallback(encrypted);
        }

        log('SUCCESS');
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('lockIcon').textContent = '\u{1f513}';
        status.className = 'success';
        status.textContent = MODE === 'register'
          ? 'Registered! You can close this tab.'
          : 'Authenticated! You can close this tab.';

      } catch (e) {
        log('ERROR: ' + (e.name ? '[' + e.name + '] ' : '') + e.message);
        showError((e.name ? '[' + e.name + '] ' : '') + e.message);
      }
    });
  </script>
</body>
</html>"#;
