# shellcheck shell=bash
# scrt4-module: wallet
# version: 1
# api: 1
# tcb: false
# deps: jq python3
# commands: wallet
# requires:
#
# Wallet dashboard — read-only EVM balance/token/tx view.
#
#   scrt4 wallet setup     Detect wallet/RPC/etherscan secrets, write config
#   scrt4 wallet           Display dashboard (balances, tokens, recent tx)
#
# Ported from daemon/bin/scrt4 (v0.1.0 monolith) cmd_wallet / _wallet_setup /
# _wallet_display / _wallet_detect_secrets. The v0.1.0 zenity UI is dropped
# in favor of CLI-only interaction; the rest of the flow (detection regex,
# Uniswap V3 on-chain pricing, CoinGecko fallback, Alchemy token balances,
# Etherscan tx history) is preserved byte-for-byte.
#
# Only PUBLIC address secrets are ever read from the vault — the detection
# regex explicitly excludes PRIVATE/MNEMONIC/SECRET/TOKEN/API/RPC/URL from
# the "wallets" list. The module never writes transactions and never
# accesses private key material.

scrt4_module_wallet_register() {
    _register_command wallet scrt4_module_wallet_dispatch
}

_scrt4_module_wallet_config() {
    echo "${CONFIG_DIR}/wallet.json"
}

scrt4_module_wallet_dispatch() {
    case "${1:-}" in
        setup)  shift; _scrt4_module_wallet_setup "$@" ;;
        help|-h|--help) _scrt4_module_wallet_help ;;
        *)      _scrt4_module_wallet_display "$@" ;;
    esac
}

_scrt4_module_wallet_help() {
    cat <<'EOF'
scrt4 wallet — EVM wallet dashboard (read-only)

USAGE:
    scrt4 wallet              Show dashboard (runs setup on first use)
    scrt4 wallet setup        (Re)select wallets, RPC, and Etherscan key

DETECTION:
    The module scans vault names for PUBLIC_KEY/ADDRESS patterns
    (excluding PRIVATE/MNEMONIC/SECRET). It never reads private keys.

CONFIG:
    Stored at $CONFIG_DIR/wallet.json. Safe to delete to force re-setup.
EOF
}

# Categorize secret names by pattern. Input: newline-separated names on stdin.
# Output: JSON {"wallets":[...], "rpcs":[...], "etherscan":[...]}.
_scrt4_module_wallet_detect_secrets() {
    python3 -c '
import sys, json, re
names = [n.strip() for n in sys.stdin.read().splitlines() if n.strip()]
wallets = [n for n in names
    if re.search(r"PUBLIC.?KEY|ADDRESS", n, re.I)
    and not re.search(r"PRIVATE|MNEMONIC|SECRET|TOKEN|API|RPC|URL", n, re.I)]
rpcs = [n for n in names if re.search(r"RPC|ALCHEMY.*URL|INFURA", n, re.I)]
etherscan = [n for n in names if re.search(r"ETHERSCAN", n, re.I)]
print(json.dumps({"wallets": wallets, "rpcs": rpcs, "etherscan": etherscan}))
'
}

_scrt4_module_wallet_setup() {
    ensure_unlocked || return 1

    local list_response all_names
    list_response=$(send_request '{"method":"list"}')
    local list_ok
    list_ok=$(echo "$list_response" | jq -r '.success // false')
    if [ "$list_ok" != "true" ]; then
        echo -e "${RED}Cannot list secrets. Is vault initialized?${NC}" >&2
        return 1
    fi
    all_names=$(echo "$list_response" | jq -r '.data.names[]' 2>/dev/null)
    if [ -z "$all_names" ]; then
        echo -e "${YELLOW}No secrets in vault. Add secrets first, then run wallet setup.${NC}"
        return 1
    fi

    local detected
    detected=$(echo "$all_names" | _scrt4_module_wallet_detect_secrets)

    local -a det_wallets=() det_rpcs=() det_etherscan=()
    while IFS= read -r w; do [ -n "$w" ] && det_wallets+=("$w"); done < <(echo "$detected" | jq -r '.wallets[]' 2>/dev/null)
    while IFS= read -r r; do [ -n "$r" ] && det_rpcs+=("$r"); done < <(echo "$detected" | jq -r '.rpcs[]' 2>/dev/null)
    while IFS= read -r e; do [ -n "$e" ] && det_etherscan+=("$e"); done < <(echo "$detected" | jq -r '.etherscan[]' 2>/dev/null)

    if [ ${#det_wallets[@]} -eq 0 ]; then
        echo -e "${YELLOW}No wallet-like secrets detected (looking for PUBLIC_KEY, ADDRESS).${NC}"
        echo -e "${YELLOW}Add wallet address secrets, then re-run: scrt4 wallet setup${NC}"
        return 1
    fi

    if [ ${#det_rpcs[@]} -eq 0 ]; then
        echo -e "${YELLOW}No RPC URL secrets detected. Add one (e.g., ALCHEMY_RPC_URL) and try again.${NC}"
        return 1
    fi

    local -a selected_wallets=()
    local selected_rpc=""
    local selected_etherscan=""

    echo ""
    echo -e "${CYAN}Wallet Setup${NC}"
    echo ""

    # Wallets
    echo -e "${CYAN}Detected wallet secrets:${NC}"
    local i=1
    for w in "${det_wallets[@]}"; do
        printf "  %2d. %s\n" "$i" "$w"
        i=$((i + 1))
    done
    echo ""
    echo -e "Select wallets (numbers, comma-separated, or ${CYAN}all${NC}):"
    echo -n "> "
    local wsel
    read -r wsel
    if [ "$wsel" = "all" ] || [ -z "$wsel" ]; then
        selected_wallets=("${det_wallets[@]}")
    else
        for num in $(echo "$wsel" | tr ',; ' ' '); do
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le ${#det_wallets[@]} ]; then
                selected_wallets+=("${det_wallets[$((num - 1))]}")
            fi
        done
    fi

    if [ ${#selected_wallets[@]} -eq 0 ]; then
        echo -e "${YELLOW}No wallets selected.${NC}"
        return 0
    fi

    # RPC
    echo ""
    echo -e "${CYAN}Detected RPC secrets:${NC}"
    i=1
    for r in "${det_rpcs[@]}"; do
        printf "  %2d. %s\n" "$i" "$r"
        i=$((i + 1))
    done
    echo -n "Select RPC [1]: "
    local rsel
    read -r rsel
    rsel="${rsel:-1}"
    if [[ "$rsel" =~ ^[0-9]+$ ]] && [ "$rsel" -ge 1 ] && [ "$rsel" -le ${#det_rpcs[@]} ]; then
        selected_rpc="${det_rpcs[$((rsel - 1))]}"
    else
        selected_rpc="${det_rpcs[0]}"
    fi

    # Etherscan (optional)
    if [ ${#det_etherscan[@]} -gt 0 ]; then
        echo ""
        echo -e "${CYAN}Detected Etherscan API keys:${NC}"
        i=1
        for e in "${det_etherscan[@]}"; do
            printf "  %2d. %s\n" "$i" "$e"
            i=$((i + 1))
        done
        echo -n "Select Etherscan key (enter to skip) [1]: "
        local esel
        read -r esel
        if [ -n "$esel" ] && [[ "$esel" =~ ^[0-9]+$ ]] && [ "$esel" -ge 1 ] && [ "$esel" -le ${#det_etherscan[@]} ]; then
            selected_etherscan="${det_etherscan[$((esel - 1))]}"
        elif [ -z "$esel" ]; then
            selected_etherscan="${det_etherscan[0]}"
        fi
    fi

    # Build config
    local wallets_json="["
    local first=true
    for w in "${selected_wallets[@]}"; do
        if [ "$first" = true ]; then first=false; else wallets_json+=","; fi
        local label
        label=$(echo "$w" | sed 's/_/ /g; s/PUBLIC KEY/Wallet/i; s/PHANTOM WALLET/Phantom/i')
        wallets_json+="{\"label\":$(printf '%s' "$label" | jq -Rs .),\"secret\":$(printf '%s' "$w" | jq -Rs .)}"
    done
    wallets_json+="]"

    local config_json
    config_json=$(jq -cn \
        --arg rpc "$selected_rpc" \
        --arg etherscan "$selected_etherscan" \
        --argjson wallets "$wallets_json" \
        '{rpc: $rpc, etherscan: $etherscan, wallets: $wallets}')

    mkdir -p "$CONFIG_DIR"
    local wallet_cfg
    wallet_cfg=$(_scrt4_module_wallet_config)
    printf '%s' "$config_json" | jq . > "$wallet_cfg"

    echo -e "${GREEN}Wallet config saved to ${wallet_cfg}${NC}"
    echo -e "  RPC: ${selected_rpc}"
    [ -n "$selected_etherscan" ] && echo -e "  Etherscan: ${selected_etherscan}"
    echo -e "  Wallets: ${#selected_wallets[@]}"
    echo -e "${CYAN}Run 'scrt4 wallet' to view dashboard.${NC}"
}

_scrt4_module_wallet_display() {
    ensure_unlocked || return 1

    local wallet_cfg
    wallet_cfg=$(_scrt4_module_wallet_config)

    if [ ! -f "$wallet_cfg" ]; then
        echo -e "${YELLOW}Wallet not configured. Running setup...${NC}"
        _scrt4_module_wallet_setup "$@" || return 1
        [ ! -f "$wallet_cfg" ] && return 1
    fi

    local config
    config=$(cat "$wallet_cfg")

    # Auto-sync: append any newly-added wallet secrets to config
    local all_names
    all_names=$(send_request '{"method":"list"}' | jq -r '.data.names[]' 2>/dev/null)
    if [ -n "$all_names" ]; then
        local detected sync_result
        detected=$(echo "$all_names" | _scrt4_module_wallet_detect_secrets)
        sync_result=$(python3 -c '
import json, sys
config = json.loads(sys.argv[1])
detected = json.loads(sys.argv[2])
existing = {w["secret"] for w in config.get("wallets", [])}
new_wallets = [w for w in detected.get("wallets", []) if w not in existing]
if not new_wallets:
    print(json.dumps({"changed": False}))
else:
    for w in new_wallets:
        label = w.replace("_PUBLIC_KEY", "").replace("PUBLIC_KEY", "Main Wallet").replace("_", " ").title()
        if not label.strip():
            label = w
        config["wallets"].append({"label": label, "secret": w})
    print(json.dumps({"changed": True, "config": config, "added": new_wallets}))
' "$config" "$detected" 2>/dev/null)
        local changed
        changed=$(echo "$sync_result" | jq -r '.changed' 2>/dev/null)
        if [ "$changed" = "true" ]; then
            echo "$sync_result" | jq -r '.config' > "$wallet_cfg"
            config=$(cat "$wallet_cfg")
            local added
            added=$(echo "$sync_result" | jq -r '.added | join(", ")' 2>/dev/null)
            echo -e "${GREEN}Auto-added new wallet(s): ${added}${NC}"
        fi
    fi

    # Two-phase reveal_all flow.
    _wa_gate || return 1

    local resp1
    resp1=$(send_request '{"method":"reveal_all"}')
    local ok1
    ok1=$(echo "$resp1" | jq -r '.success // false')
    if [ "$ok1" != "true" ]; then
        echo -e "${RED}wallet reveal failed: $(echo "$resp1" | jq -r '.error // "unknown"')${NC}" >&2
        return 1
    fi
    local challenge user_code
    challenge=$(echo "$resp1" | jq -r '.data.challenge')
    user_code=$(echo "$resp1" | jq -r '.data.code')

    echo -e "${CYAN}Fetching wallet data...${NC}"

    local wallet_result_file="${XDG_RUNTIME_DIR:-/tmp}/scrt4-wallet-$$.json"

    python3 -c '
import json, sys, os, socket, urllib.request, urllib.parse, time, datetime

challenge = sys.argv[1]
user_code = sys.argv[2]
sock_path = sys.argv[3]
config = json.loads(sys.argv[4])
result_file = sys.argv[5]

def write_result(obj):
    with open(result_file, "w") as f:
        json.dump(obj, f)
    sys.exit(0)

def send_daemon(req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall(json.dumps(req).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            chunks.append(d)
        except: break
    s.close()
    return json.loads(b"".join(chunks))

def rpc_call(url, method, params):
    data = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
        return resp.get("result")
    except Exception:
        return None

def etherscan_get(base_url, params, api_key):
    if not api_key:
        return []
    params["apikey"] = api_key
    url = base_url + "?" + urllib.parse.urlencode(params)
    try:
        resp = json.loads(urllib.request.urlopen(url, timeout=15).read())
        r = resp.get("result", [])
        return r if isinstance(r, list) else []
    except Exception:
        return []

def coingecko_prices(ids):
    url = "https://api.coingecko.com/api/v3/simple/price?ids=" + ",".join(ids) + "&vs_currencies=usd"
    try:
        return json.loads(urllib.request.urlopen(url, timeout=10).read())
    except Exception:
        return {}

def coingecko_token_price(platform, contract):
    url = f"https://api.coingecko.com/api/v3/simple/token_price/{platform}?contract_addresses={contract}&vs_currencies=usd"
    try:
        resp = json.loads(urllib.request.urlopen(url, timeout=8).read())
        return resp.get(contract.lower(), {}).get("usd", 0)
    except Exception:
        return 0

KNOWN_TOKENS = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", 18, None, None),
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": ("wstETH", 18, "0x109830a1AAaD605BbF02a9dFA7B0B92EC2FB7dAa", True),
    "0x514910771af9ca656af840dff83e8264ecf986ca": ("LINK", 18, "0xa6Cc3C2531FdaA6Ae1A3CA84c2855806728693e8", True),
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6, None, None),
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6, None, None),
    "0x6b175474e89094c44da98b954eedeac495271d0f": ("DAI", 18, None, None),
}
STABLECOINS = {"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "0xdac17f958d2ee523a2206206994597c13d831ec7", "0x6b175474e89094c44da98b954eedeac495271d0f"}
WETH_CONTRACT = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"

def uniswap_v3_price(rpc_url, pool_address, is_token0, token_decimals, pair_decimals=18):
    result = rpc_call(rpc_url, "eth_call", [{"to": pool_address, "data": "0x3850c7bd"}, "latest"])
    if not result or result == "0x":
        return 0
    try:
        sqrt_price_x96 = int(result[:66], 16)
        price_raw = (sqrt_price_x96 ** 2) / (2 ** 192)
        decimal_adj = 10 ** (token_decimals - pair_decimals)
        if is_token0:
            return price_raw / decimal_adj
        else:
            if price_raw == 0:
                return 0
            return (1 / price_raw) * decimal_adj
    except Exception:
        return 0

def get_token_usd_price(rpc_url, contract, eth_price, price_cache):
    c = contract.lower()
    if c in price_cache:
        return price_cache[c]
    price = 0
    if c in KNOWN_TOKENS:
        symbol, decimals, pool, is_token0 = KNOWN_TOKENS[c]
        if c == WETH_CONTRACT:
            price = eth_price
        elif c in STABLECOINS:
            price = 1.0
        elif pool:
            price_in_weth = uniswap_v3_price(rpc_url, pool, is_token0, decimals, 18)
            price = price_in_weth * eth_price
    else:
        price = coingecko_token_price("ethereum", contract)
    price_cache[c] = price
    return price

def main():
    resp = send_daemon({
        "method": "reveal_all_confirm",
        "params": {"challenge": challenge, "code": user_code}
    })
    if not resp.get("success"):
        write_result({"error": resp.get("error", "Unknown error")})

    secrets = resp.get("data", {}).get("secrets", {})

    rpc_url = secrets.get(config.get("rpc", ""), "")
    etherscan_key = secrets.get(config.get("etherscan", ""), "")
    wallets = config.get("wallets", [])

    if not rpc_url:
        for k in list(secrets.keys()): secrets[k] = "[CLEARED]"
        write_result({"error": "RPC secret is empty or missing. Run: scrt4 wallet setup"})

    prices = coingecko_prices(["ethereum"])
    eth_price = prices.get("ethereum", {}).get("usd", 0)

    lines = []
    lines.append("=" * 63)
    lines.append("             scrt4  -  Wallet Dashboard")
    lines.append("=" * 63)
    lines.append("")
    ts_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines.append(f"  ETH Price: ${eth_price:,.2f}     ({ts_now})")
    lines.append("")

    total_usd = 0.0
    token_price_cache = {}
    seen_addresses = {}

    for w in wallets:
        label = w.get("label", w["secret"])
        address = secrets.get(w["secret"], "").strip()

        if not address:
            lines.append(f"  -- {label} --")
            lines.append("    Secret is empty for this wallet")
            lines.append("")
            continue

        addr_lower = address.lower()
        if addr_lower in seen_addresses:
            lines.append(f"  -- {label} -- (same as {seen_addresses[addr_lower]}, skipped)")
            lines.append("")
            continue
        seen_addresses[addr_lower] = label

        is_evm = address.startswith("0x") and len(address) == 42
        short = f"{address[:6]}...{address[-4:]}" if len(address) > 12 else address
        lines.append(f"  -- {label} ({short}) --")
        lines.append(f"    Address: {address}")

        if not is_evm:
            lines.append("    Non-EVM address (Solana/other) - balance check not yet supported")
            lines.append("")
            continue

        eth_bal = 0.0
        bal_result = rpc_call(rpc_url, "eth_getBalance", [address, "latest"])
        if bal_result:
            try:
                eth_bal = int(bal_result, 16) / 1e18
            except Exception:
                pass
        eth_usd = eth_bal * eth_price
        total_usd += eth_usd
        lines.append(f"    ETH     {eth_bal:>14.6f}    ${eth_usd:>12,.2f}")

        token_result = rpc_call(rpc_url, "alchemy_getTokenBalances", [address, "erc20"])
        token_lines = []
        seen_contracts = set()

        if token_result and "tokenBalances" in token_result:
            non_zero = []
            for t in token_result["tokenBalances"]:
                try:
                    raw = int(t["tokenBalance"], 16)
                    if raw > 0:
                        non_zero.append((t["contractAddress"], raw))
                except Exception:
                    pass
            for contract, raw_balance in non_zero[:50]:
                meta = rpc_call(rpc_url, "alchemy_getTokenMetadata", [contract])
                if not meta:
                    continue
                symbol = meta.get("symbol", "???")
                decimals = meta.get("decimals", 18) or 18
                balance = raw_balance / (10 ** decimals)
                seen_contracts.add(contract.lower())
                if balance < 0.0001:
                    continue
                token_usd_price = get_token_usd_price(rpc_url, contract, eth_price, token_price_cache)
                token_usd = balance * token_usd_price
                total_usd += token_usd
                if token_usd > 0.01:
                    token_lines.append((token_usd, f"    {symbol:<8}{balance:>14,.4f}    ${token_usd:>12,.2f}"))
                else:
                    token_lines.append((0, f"    {symbol:<8}{balance:>14,.4f}"))

        if etherscan_key:
            etk = etherscan_get("https://api.etherscan.io/api", {
                "module": "account", "action": "tokentx",
                "address": address, "startblock": 0, "endblock": 99999999,
                "page": 1, "offset": 100, "sort": "desc"
            }, etherscan_key)
            extra_contracts = set()
            for tx in etk:
                ca = tx.get("contractAddress", "").lower()
                if ca and ca not in seen_contracts:
                    extra_contracts.add(ca)
            for ca in list(extra_contracts)[:20]:
                bal_hex = rpc_call(rpc_url, "eth_call", [
                    {"to": ca, "data": "0x70a08231" + address[2:].lower().zfill(64)}, "latest"
                ])
                if not bal_hex:
                    continue
                try:
                    raw_balance = int(bal_hex, 16)
                except Exception:
                    continue
                if raw_balance == 0:
                    continue
                meta = rpc_call(rpc_url, "alchemy_getTokenMetadata", [ca])
                if not meta:
                    continue
                symbol = meta.get("symbol", "???")
                decimals = meta.get("decimals", 18) or 18
                balance = raw_balance / (10 ** decimals)
                if balance < 0.0001:
                    continue
                seen_contracts.add(ca)
                token_usd_price = get_token_usd_price(rpc_url, ca, eth_price, token_price_cache)
                token_usd = balance * token_usd_price
                total_usd += token_usd
                if token_usd > 0.01:
                    token_lines.append((token_usd, f"    {symbol:<8}{balance:>14,.4f}    ${token_usd:>12,.2f}"))
                else:
                    token_lines.append((0, f"    {symbol:<8}{balance:>14,.4f}"))

        token_lines.sort(key=lambda x: -x[0])
        for _, tl in token_lines:
            lines.append(tl)

        if etherscan_key:
            txs = etherscan_get("https://api.etherscan.io/api", {
                "module": "account", "action": "txlist",
                "address": address, "startblock": 0, "endblock": 99999999,
                "page": 1, "offset": 5, "sort": "desc"
            }, etherscan_key)
            if txs:
                lines.append("")
                lines.append("    Recent transactions:")
                for tx in txs[:5]:
                    try:
                        value_eth = int(tx.get("value", "0")) / 1e18
                        from_addr = tx.get("from", "")
                        to_addr = tx.get("to", "")
                        is_out = from_addr.lower() == address.lower()
                        direction = "SENT" if is_out else "RECV"
                        other = to_addr if is_out else from_addr
                        other_short = f"{other[:6]}...{other[-4:]}" if other else "contract"
                        ts = int(tx.get("timeStamp", "0"))
                        date = datetime.datetime.fromtimestamp(ts).strftime("%m/%d %H:%M")
                        status = "+" if tx.get("isError") == "0" else "x"
                        lines.append(f"      {status} {date}  {direction}  {value_eth:.4f} ETH  {other_short}")
                    except Exception:
                        pass

        lines.append("")

    lines.append("  " + "=" * 59)
    lines.append(f"  TOTAL PORTFOLIO VALUE:  ${total_usd:>12,.2f}")
    lines.append("  " + "=" * 59)

    for k in list(secrets.keys()):
        secrets[k] = "[CLEARED]"
    del secrets

    write_result({"success": True, "output": "\n".join(lines), "total_usd": total_usd})

try:
    main()
except Exception as e:
    import traceback
    write_result({"error": str(e) + "\n" + traceback.format_exc()})
' "$challenge" "$user_code" "$SOCKET" "$config" "$wallet_result_file" 2>/dev/null

    local py_rc=$?

    if [ ! -f "$wallet_result_file" ]; then
        echo -e "${RED}Wallet fetch failed (Python produced no result).${NC}" >&2
        [ $py_rc -ne 0 ] && echo -e "${YELLOW}Python exited with code ${py_rc}.${NC}" >&2
        return 1
    fi

    local py_json py_err output
    py_json=$(cat "$wallet_result_file")
    rm -f "$wallet_result_file"

    py_err=$(echo "$py_json" | jq -r '.error // empty')
    if [ -n "$py_err" ]; then
        echo -e "${RED}${py_err}${NC}" >&2
        return 1
    fi

    output=$(echo "$py_json" | jq -r '.output')
    echo ""
    echo "$output"
    echo ""
}
