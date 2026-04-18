# SECRETS.md — How to generate every secret a module needs

> **This document is the module author's onboarding checklist.** For every
> secret referenced in any module's `reveals:` header, this file tells you
> exactly how to generate it, what scopes to pick, and how to rotate it.
>
> **If your module adds a new secret name, you must also add its generation
> steps here.** A PR that adds a secret without updating this file will be
> held at review.

## How this document is organized

- One top-level section per module, named after the module (§`github`, §`gcp`, …).
- Inside each section, one subsection per secret name.
- Each secret entry is a short fixed schema:

  1. **What it is** — one sentence on what the secret authorizes.
  2. **Scopes / permissions** — the least-privilege set to pick during generation.
  3. **Generate** — numbered steps (UI clicks or CLI commands).
  4. **Install** — the exact `scrt4 add` line.
  5. **Rotate** — how to replace it when it leaks or expires.

- At the end there is a **§Rotation checklist** and a **§Troubleshooting** section
  common to all secrets.

---

## How to install a secret once you have it

Every secret in this document is installed the same way:

```bash
scrt4 unlock                              # if not already in a session
scrt4 add NAME=VALUE                      # single value
scrt4 add 'NAME=val with spaces or :'     # single-quote anything with shell metacharacters
scrt4 view                                # inspect/edit in the Zenity GUI
```

`scrt4 add` overwrites an existing secret of the same name. There is no
confirmation. If you want a safety net, run `scrt4 list` first to see if the
name already exists.

**Never** paste a secret value into a file, a chat message, a git-tracked
config, or the URL / query-string of any HTTP request. Secrets belong in the
vault and only in the vault.

---

## github

Module file: `daemon/bin/scrt4-modules/github.sh`
Required: `GITHUB_PAT`, `GITHUB_USERNAME`

### `GITHUB_PAT`

**What it is.** A GitHub Personal Access Token. The `github` module uses it as
`Authorization: Bearer <pat>` for all REST calls — issues, PRs, repos.

**Scopes (classic PAT).** The minimum set depends on what subcommands you use:

| Subcommand family | Scopes |
|---|---|
| Read repos / issues / PRs (public only) | *(no scopes — the token is just for rate limit)* |
| Read repos / issues / PRs (private) | `repo` (gives read + write; GitHub does not split these) |
| Create / close / comment on issues | `repo` |
| Merge PRs | `repo` |
| Manage labels / milestones | `repo` |

**Fine-grained PAT (preferred for new tokens).**
- Resource owner: your account (or the org that owns the repos).
- Repository access: *Only select repositories* and pick the exact repos you
  want the module to touch. Never choose *All repositories*.
- Repository permissions:
  - Contents → *Read-only* (or *Read and write* if you'll use write subcommands).
  - Issues → *Read and write* (if you'll issue-create/close/comment).
  - Pull requests → *Read and write* (if you'll merge PRs).

**Generate.**
1. Open <https://github.com/settings/personal-access-tokens/new> (fine-grained)
   or <https://github.com/settings/tokens/new> (classic).
2. Name it `scrt4 github module — <hostname>` so it's clear where it lives.
3. Expiration: **90 days** (force yourself to rotate).
4. Pick the repository access and permission set from the table above.
5. *Generate token*. Copy the value **once** — GitHub never shows it again.

**Install.**
```bash
scrt4 add GITHUB_PAT=github_pat_...   # fine-grained
# or
scrt4 add GITHUB_PAT=ghp_...          # classic
```

**Rotate.** Re-run *Generate*, `scrt4 add GITHUB_PAT=<new>` (overwrites), then
delete the old token from the GitHub UI so it cannot be reused.

### `GITHUB_USERNAME`

**What it is.** Your GitHub login (e.g. `joshgottlieb`). The module uses it to
scope list queries ("my PRs", "my issues") and to populate the `author` field
in API calls that need it.

**Scopes.** None — it's public.

**Generate.** Look at your GitHub profile URL: the slug after `github.com/` is
your username.

**Install.**
```bash
scrt4 add GITHUB_USERNAME=joshgottlieb
```

**Rotate.** Only needed if you rename your GitHub account. Overwrite.

---

## gcp

Module file: `daemon/bin/scrt4-modules/gcp.sh`
Required: `GCP_INSTANCE_NAME`, `GCP_ZONE`, `GCP_EXTERNAL_IP`

The `gcp` module shells out to `gcloud`. It does **not** store any credentials
itself — it relies on the host's `gcloud` having been logged in separately
(`gcloud auth login`). The three secrets are all non-secret identifiers, but
live in the vault so every module (and every script) picks up the same values.

### `GCP_INSTANCE_NAME`

**What it is.** The name of your primary Compute Engine VM (e.g.
`prod-repo-app-instance-v001`). Used as the target of `gcloud compute ssh`.

**Generate.**
```bash
gcloud compute instances list
# Copy the NAME column for the instance you want.
```

**Install.**
```bash
scrt4 add GCP_INSTANCE_NAME=prod-repo-app-instance-v001
```

**Rotate.** Update if you rebuild the VM with a new name.

### `GCP_ZONE`

**What it is.** The Compute Engine zone the instance is in (e.g. `us-east4-c`).

**Generate.** Same `gcloud compute instances list` output — the ZONE column.

**Install.**
```bash
scrt4 add GCP_ZONE=us-east4-c
```

### `GCP_EXTERNAL_IP`

**What it is.** The public IPv4 of the instance. Used for non-gcloud paths
(e.g. a one-off `ssh -i key ...` if gcloud is unavailable).

**Generate.**
```bash
gcloud compute instances describe "${INSTANCE}" --zone="${ZONE}" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

**Install.**
```bash
scrt4 add GCP_EXTERNAL_IP=34.48.219.138
```

**Rotate.** The IP changes if you detach and re-attach the ephemeral address
(or reserve a static one). Re-run the describe command and overwrite.

---

## stripe

Module file: `daemon/bin/scrt4-modules/stripe.sh`
Required: `STRIPE_SECRET_KEY`

### `STRIPE_SECRET_KEY`

**What it is.** Stripe's server-side API key. The module uses it as the
`-u "${key}:"` basic-auth username for every REST call (balance, charges,
customers, refunds).

**Scopes.** Stripe secret keys do not have scopes by default — they are
all-powerful for the account. Two ways to reduce blast radius:

1. **Use a restricted key (recommended).** In the Stripe Dashboard →
   Developers → API keys → *Create restricted key*. Grant only what you need:
   - Reads (balance, charges, customers, subs): `Read` on each resource.
   - Refunds: `Write` on `refunds` and `charges`.
2. **Use a test-mode key** for any environment that isn't production. Test-mode
   keys start with `sk_test_...`; production keys start with `sk_live_...`.
   The module treats them identically — the difference is which side of the
   production/test divide your API calls hit.

**Generate.**
1. <https://dashboard.stripe.com/apikeys> (live) or
   <https://dashboard.stripe.com/test/apikeys> (test).
2. *Create restricted key*.
3. Name it `scrt4 stripe module — <hostname>`.
4. Select the resource permissions per the table above.
5. *Create key*. Copy the value **once**.

**Install.**
```bash
scrt4 add STRIPE_SECRET_KEY=sk_live_...   # or sk_test_...  or rk_live_...
```

**Rotate.**
1. Generate a new restricted key.
2. `scrt4 add STRIPE_SECRET_KEY=<new>` (overwrites).
3. In the Stripe Dashboard, revoke the old key. (Stripe's revoke is instant —
   the old key stops working the moment you click it.)

---

## domain

Module file: `daemon/bin/scrt4-modules/domain.sh`
Required: varies by provider — any subset of the below is fine; the module
detects which providers you have configured and offers only those.

### `CLOUDFLARE_API_TOKEN`

**What it is.** A scoped Cloudflare API token. The module uses it for DNS
zone + record list / read / edit / delete across all Cloudflare zones it can
see.

**Scopes.**
- *Zone → DNS → Edit* (includes read). Add this for every zone you want to
  manage.
- *Zone → Zone → Read* (so list commands work).

Don't use the "Global API Key" — that's the all-powerful legacy token. Always
use a scoped token.

**Generate.**
1. <https://dash.cloudflare.com/profile/api-tokens> → *Create Token*.
2. Use the *Edit zone DNS* template, or *Custom token* with the scopes above.
3. *Zone Resources*: *Include → Specific zone → <yourdomain>* — or *All zones*
   if the module will manage many.
4. *Client IP Address Filtering* — optional. If your workstation has a stable
   IP, use it; otherwise skip.
5. *TTL*: 90 days.
6. *Continue to summary → Create Token*. Copy the value **once**.

**Install.**
```bash
scrt4 add CLOUDFLARE_API_TOKEN=...
```

**Rotate.** Re-run *Create Token*, `scrt4 add` overwrite, then *Roll* (Cloudflare
term for revoke) the old one from the API-tokens page.

### `VERCEL_TOKEN`

**What it is.** A Vercel API token. The module uses it to list projects,
domains, and deployments; trigger redeploys if requested.

**Scopes.** Vercel tokens are scoped to either your *Personal Account* or a
specific *Team*. There's no per-resource scoping — the token has full access to
the account/team it's bound to. For a production Vercel team, prefer scoping to
the team so the token can't see unrelated personal projects.

**Generate.**
1. <https://vercel.com/account/tokens>.
2. *Create Token*.
3. Name: `scrt4 domain module — <hostname>`.
4. Scope: *Your personal account* **or** the specific team (recommended).
5. Expiration: *90 days*.
6. *Create*. Copy the value **once**.

**Install.**
```bash
scrt4 add VERCEL_TOKEN=...
```

**Rotate.** Same as Cloudflare — regenerate, overwrite, revoke the old one from
the tokens page.

### `GODADDY_API_KEY` and `GODADDY_API_SECRET`

**What they are.** A paired API-key + API-secret for GoDaddy. The module uses
them together (HTTP header `Authorization: sso-key ${key}:${secret}`) for
domain-search, registration-status, and DNS-record reads against GoDaddy.

**Scopes.** GoDaddy tokens are all-or-nothing — no scopes. Pick the
*Production* environment (not *OTE*/sandbox) for real use.

**Generate.**
1. <https://developer.godaddy.com/keys>.
2. *Create New API Key*.
3. Name: `scrt4 domain — <hostname>`.
4. Environment: *Production*.
5. *Next*. GoDaddy shows the Key and Secret **once**. Copy both.

**Install.**
```bash
scrt4 add GODADDY_API_KEY=...
scrt4 add GODADDY_API_SECRET=...
```

**Rotate.** GoDaddy does not let you rotate in place — you have to *Revoke* the
old key and *Create New* to get a new pair. Install both new values; the old
pair is dead the moment you click *Revoke*.

### `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`

**What they are.** An AWS access-key pair for the `aws` CLI, used by the
Route 53 subcommands of the `domain` module. `AWS_REGION` is optional and
defaults to `us-east-1`.

**Scopes (IAM policy).** Create a dedicated IAM user (never use root) with
only the Route 53 actions needed:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "route53:ListHostedZones",
      "route53:GetHostedZone",
      "route53:ListResourceRecordSets",
      "route53:ChangeResourceRecordSets"
    ],
    "Resource": "*"
  }]
}
```

If you only need reads, drop `ChangeResourceRecordSets`.

**Generate.**
1. <https://console.aws.amazon.com/iam/home#/users> → *Add users*.
2. User name: `scrt4-domain-<hostname>`.
3. Access type: *Programmatic access*.
4. Attach the inline policy above (or one you've previously saved).
5. Create the user. On the final screen AWS shows the *Access key ID* and
   *Secret access key* — copy both **now**; the secret is never shown again.

**Install.**
```bash
scrt4 add AWS_ACCESS_KEY_ID=AKIA...
scrt4 add AWS_SECRET_ACCESS_KEY=...
scrt4 add AWS_REGION=us-east-1         # optional; module defaults to this
```

**Rotate.** IAM → your user → *Security credentials* → *Create access key*
(you're allowed up to two active at once). Install the new pair. Deactivate
the old pair. After 24 hours of clean logs, *Delete* the old pair.

---

## wallet

Module file: `daemon/bin/scrt4-modules/wallet.sh`
Secrets: the module scans the vault for names matching `PUBLIC_KEY*`,
`*_PUBLIC_KEY`, `*ADDRESS*`, plus RPC URLs (`ALCHEMY_*_URL`, `*RPC_URL`, etc.)
and `ETHERSCAN_API_KEY`. None of these are strictly "declared" in the header
— the module operates on whatever is present.

**`PUBLIC_KEY` (and variants like `PUBLIC_KEY_PHANTOM_WALLET`).**
Wallet addresses are **not secrets** — they are public by definition. They
live in the vault so the `wallet` module has a stable list of addresses to
query. Generate one by creating the wallet in your wallet app (MetaMask,
Phantom, etc.) and copying the public address. Install:
```bash
scrt4 add PUBLIC_KEY=0x...
scrt4 add PUBLIC_KEY_PHANTOM_WALLET=...
```
Don't bother rotating — it's the wallet's identity.

**`PRIVATE_KEY` (if you keep one).**
The `wallet` module does **not** read private keys — it only displays
balances. If you store a private key in the vault for other scripts
(deploy scripts, etc.), it comes from wherever you generated the wallet.
**Never regenerate a private key you've used on-chain without migrating
funds first.** The ONLY way to rotate is: create a new wallet → transfer
funds → update `scrt4 add PRIVATE_KEY=...` → retire the old wallet.

**`ALCHEMY_API_KEY`, `ALCHEMY_RPC_URL`, `ALCHEMY_SEPOLIA_RPC_URL`,
`ALCHEMY_ARBITRUM_RPC_URL`.**
Alchemy RPC endpoints.

**Generate.**
1. <https://dashboard.alchemy.com/>.
2. *Create new app* (one per chain — Mainnet, Sepolia, Arbitrum).
3. Pick *Chain* and *Network*. Name and Description don't matter.
4. *Create app*. Click into it → *API key*.
5. `HTTP` URL is the RPC URL. `KEY` is the raw API key.

**Install.**
```bash
scrt4 add ALCHEMY_API_KEY=...
scrt4 add ALCHEMY_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/...
scrt4 add ALCHEMY_SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/...
scrt4 add ALCHEMY_ARBITRUM_RPC_URL=https://arb-mainnet.g.alchemy.com/v2/...
```

**Rotate.** Alchemy *View key* → *Roll key*. Install the new URLs (the key
portion changes). Old URL stops serving within seconds.

**`ETHERSCAN_API_KEY`.**
Used by wallet display for read-only token balance / tx lookups on Ethereum.

**Generate.**
1. <https://etherscan.io/myapikey> (requires a free Etherscan account).
2. *Add*.
3. Label: `scrt4 wallet`.
4. Copy the key.

**Install.**
```bash
scrt4 add ETHERSCAN_API_KEY=...
```

**Rotate.** Delete the old key from the *My API Keys* page. Generate a new one.

---

## messages

Module file: `daemon/bin/scrt4-modules/messages.sh`
Required: `personal_google_workspace` (optional — if absent, Gmail source is
skipped cleanly). No secret is needed for the WhatsApp or Telegram sources:
those read local archive JSONLs written by your existing archivers.

### `personal_google_workspace`

**What it is.** An OAuth refresh-token blob for your *personal* Gmail. The
messages module uses it to exchange for a short-lived `access_token`, then
hits the Gmail REST API to pull action-item candidates from whitelisted
senders / labels.

**Why not a service account?** The Google-service-account + domain-wide
delegation path exists for *workspace admin* operations (Drive, Docs,
impersonation). For reading *your own* mail, the personal OAuth refresh-token
flow is simpler, uses no crypto libraries, and avoids handing the module
admin-level reach.

**Scopes.** The OAuth consent must grant **only**:

```
https://www.googleapis.com/auth/gmail.readonly
```

Nothing else. If you want the module to be able to move / label / archive
later, add those scopes then — not preemptively.

**Generate.** This is a three-phase dance. Do it once, then you have a
refresh token that is good until you revoke it.

#### Phase 1 — Create OAuth client credentials

1. <https://console.cloud.google.com/apis/credentials> → pick the project.
2. *+ Create credentials* → *OAuth client ID*.
3. Application type: *Desktop app*.
4. Name: `scrt4 messages — <hostname>`.
5. *Create*. Google shows a `client_id` and `client_secret`. Download the
   JSON or copy both values.

If you also haven't enabled the Gmail API in this project:
`APIs & Services → Library → Gmail API → Enable`.

#### Phase 2 — Get your refresh token

The OAuth refresh-token dance needs a browser redirect. There is no way
around this — Google does not allow purely-headless consent for personal
accounts. The easiest method is the Google OAuth Playground proxy:

1. <https://developers.google.com/oauthplayground/>.
2. Click the gear icon (top-right) → *OAuth 2.0 configuration*.
   - Tick *Use your own OAuth credentials*.
   - Paste your `client_id` and `client_secret` from Phase 1.
   - *Close*.
3. In the left panel, under *Step 1 Select & authorize APIs*, paste into
   the manual-input box: `https://www.googleapis.com/auth/gmail.readonly`.
4. *Authorize APIs*. Consent in the popup — pick the correct Google
   account (**your personal one**, not a workspace admin).
5. You land on *Step 2*. Click *Exchange authorization code for tokens*.
6. The right panel now shows `access_token`, `expires_in`, `refresh_token`,
   `token_type`. **Copy the `refresh_token`** — this is the long-lived one.

#### Phase 3 — Assemble the opaque blob and install

The module expects one single-line secret value in this exact shape — key
names and the `:` / `,` / space separators are regex-parsed by the module:

```
{client_id:YOUR_CLIENT_ID, client_secret:YOUR_CLIENT_SECRET, refresh_token:YOUR_REFRESH_TOKEN, token_uri:https://oauth2.googleapis.com/token}
```

No quotes around the values, no JSON escaping — just the braces, the four
keys, their values, and `, ` between them.

**Install.**
```bash
scrt4 add 'personal_google_workspace={client_id:1234-abcd.apps.googleusercontent.com, client_secret:GOCSPX-..., refresh_token:1//0g..., token_uri:https://oauth2.googleapis.com/token}'
```

Single-quote the whole argument so the shell doesn't try to expand or split
on `:` or spaces.

**Verify.**
```bash
scrt4 messages whitelist add "gmail:sender:josh@klevel.one"
scrt4 messages scan
```
`gmail=N` where N is the action-items extracted from your inbox means the
refresh-token flow is working end-to-end. If you see `gmail=0` with
no error, either your whitelist has no matching senders or your inbox has
no action-items among them.

**Rotate.**
1. Google Account → Security → Third-party access → find the OAuth client
   → *Remove access*. This invalidates the refresh token.
2. Re-run Phase 2 to get a new refresh token.
3. `scrt4 add 'personal_google_workspace={...new refresh_token...}'`
   (overwrites).

---

## website

The `website` module deploys to an existing user-owned domain. It does
**not** register domains — buy/transfer separately at a registrar.
No new secret types are introduced; the module reuses:

| Secret | Where it's documented | Used for |
|---|---|---|
| `VERCEL_TOKEN` | [`## domain → VERCEL_TOKEN`](#vercel_token) | static-mode deploy + project list + alias |
| `GCP_INSTANCE_NAME` | [`## gcp → GCP_INSTANCE_NAME`](#gcp_instance_name) | app-mode target VM |
| `GCP_ZONE` | [`## gcp → GCP_ZONE`](#gcp_zone) | app-mode target zone |
| `GCP_EXTERNAL_IP` | [`## gcp → GCP_EXTERNAL_IP`](#gcp_external_ip) | status display only |
| `GODADDY_API_KEY` | [`## domain → GODADDY_API_KEY`](#godaddy_api_key-and-godaddy_api_secret) | DNS helpers (optional) |
| `GODADDY_API_SECRET` | same entry | DNS helpers (optional) |

Before first use, run `scrt4 website init` — it prints a checklist of
which of the above are in your vault and which CLIs (`vercel`, `gcloud`)
are on your `PATH`, so you know exactly what to install/add before
touching a `deploy`.

Static (Vercel) mode needs only `VERCEL_TOKEN` + a CNAME you add at your
registrar (the `deploy` output prints the exact CNAME target). App mode
needs `GCP_INSTANCE_NAME` + `GCP_ZONE` + `gcloud` authed; the module
rsyncs your directory, installs a `systemd` unit, and appends a Caddy
snippet for `https://<domain> → reverse_proxy localhost:<port>`.

---

## Rotation checklist

A secret is only as safe as the *rotation workflow* around it. For any
new module you add:

1. **Rotate at least every 90 days** (set the expiration when you generate).
2. **Rotate immediately** if any of:
   - The secret ever appears in a log, a terminal recording, a screenshot,
     a pasted error message, or a commit.
   - Someone other than you gains access to the machine the vault lives on.
   - The provider emails you about a suspicious API call.
3. **Rotate by generating the new value first, installing it via
   `scrt4 add` (overwrites), then revoking the old one** — never the other
   way around, or you'll lock yourself out for the window between revoke
   and install.
4. **Confirm the rotation worked** by running a read-only subcommand of
   the module (`github gh-list`, `stripe balance`, `domain check`, etc.).
   If the call fails, the new secret didn't take — roll back and
   investigate before revoking the old one.

---

## Troubleshooting

**"reveal_denied" on module startup.**
The daemon refused to reveal the secret. Run `scrt4 status` — if no
session, `scrt4 unlock`. If the session is fine, the secret probably
isn't in the vault at all — `scrt4 list | grep -i <name>` to check.

**"secret not found" but I just added it.**
`scrt4 add` is case-sensitive and the module's `reveals:` list is the
source of truth. Compare `scrt4 list` output to the module's header
line-for-line.

**Value is right but calls fail with 401 / 403.**
The token is stale or scoped wrong. Regenerate with the scopes from this
doc's §per-secret entry. Don't "just add more scopes" — revoke the old
one first so you're not accumulating overly-privileged credentials.

**`personal_google_workspace` always returns `gmail=0`.**
- Whitelist has no `gmail:sender:*` or `gmail:label:*` entry for any sender /
  label that actually exists in your mailbox. `scrt4 messages whitelist list`
  to inspect.
- Refresh token was generated against a different Google account than the
  one whose mail you're trying to read. Re-do Phase 2, picking the correct
  account.

**"invalid_grant" from Google's token endpoint.**
Refresh token was revoked (manually, or Google's 6-month inactivity policy,
or a password reset invalidated it). Re-do Phase 2.

**AWS calls fail with `SignatureDoesNotMatch`.**
Almost always a trailing whitespace or newline in the secret value. `scrt4
view`, select the secret, retype carefully, Save.

---

## For module authors: when to add an entry here

You must add a new section / subsection to this document if:

- Your module's `reveals:` header names a secret that isn't already documented.
- Your module uses a `reveals_pattern:` that could match a named secret not
  already covered — document each concrete example name that pattern is
  expected to match.
- Your module talks to an external API through a pre-installed CLI that
  itself reads credentials — even if you don't `reveal` the credential
  directly, document where the CLI expects it to live so the user knows how
  to set it up (e.g. `gcloud auth login`, `aws configure`).

A new secret entry must include all five fields: *What it is*, *Scopes*,
*Generate*, *Install*, *Rotate*. If any of them are "N/A" (e.g. scopes for a
public address), say so explicitly — don't leave the field out.
