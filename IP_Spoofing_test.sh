#!/usr/bin/env bash

set -u

DEBUG=0
DEBUG_LOG="/tmp/spoof-debug-$$.log"

enable_debug() {
    if [ "$DEBUG" -eq 1 ]; then
        return 0
    fi
    DEBUG=1
    touch "$DEBUG_LOG" 2>/dev/null || true
    exec > >(tee -a "$DEBUG_LOG") 2>&1
    echo "=== DEBUG MODE ON, full output logging to $DEBUG_LOG ==="
}

dbg_log() {
    if [ "${DEBUG:-0}" -eq 1 ]; then
        echo "--- DBG: $*" >>"$DEBUG_LOG" 2>/dev/null || true
    fi
}

for arg in "$@"; do
    case "$arg" in
        --debug|-x|-d) enable_debug ;;
    esac
done

RULE_ADDED=0
REMOTE_RULE_ADDED=0
DST_IP=""
SPOOF_IP=""
FOREIGN_IP=""
FOREIGN_PORT="22"
FOREIGN_USER="root"
FOREIGN_PASS=""
LOCAL_IP=""

# ---- CSV + per-IP tracking ----
CIDR_SAMPLE_MAX=3
# Fast full-range mode: above this many sample IPs we switch to single-SSH
# batched scapy (1-2 pkts/IP, inter~0) + nping proof on rep IP only.
# This keeps full-range scans feasible: 254 IPs in seconds, /16 in minutes
# instead of hours with the old per-IP SSH loop.
CIDR_FAST_THRESHOLD=20
RAW_PKTS_PER_IP=5
direct_res="NOT_RUN"
reverse_res="NOT_RUN"
direct_spoof_cnt=0
reverse_spoof_cnt=0
direct_new_real=0
reverse_new_real=0
direct_nping_proven=0
reverse_nping_proven=0
direct_raw_ran=0
reverse_raw_ran=0
DIRECT_RX_LOG=""
REVERSE_RX_LOG=""
DIRECT_NPING_LOG=""
REVERSE_NPING_LOG=""
CSV_SUMMARY_FILE=""
CSV_FULL_FILE=""

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

# ---- CIDR support for spoof IP ----
# SPOOF_IP   : original user input (single IP or CIDR, e.g. 1.1.1.1 or 1.1.1.0/24)
# SPOOF_CIDR : network in CIDR form if input was CIDR, else empty
# SPOOF_REP_IP : single representative IP for SNAT/scapy/nping (== SPOOF_IP if single)
# SPOOF_FILTER : tcpdump fragment, e.g. "src host 1.1.1.1" or "src net 1.1.1.0/24"
SPOOF_CIDR=""
SPOOF_REP_IP=""
SPOOF_FILTER=""

is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local -a o
    read -r -a o <<< "$ip"
    for n in "${o[@]}"; do
        [ "$n" -ge 0 ] 2>/dev/null && [ "$n" -le 255 ] 2>/dev/null || return 1
    done
    return 0
}

# Echo first usable host of a CIDR, or network address as fallback. Empty on failure.
cidr_first_host() {
    local cidr="$1"
    python3 - "$cidr" <<'PYEOF' 2>/dev/null
import sys, ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    if net.version != 4:
        sys.exit(1)
    hosts = list(net.hosts())
    if hosts:
        print(str(hosts[0]))
    else:
        # /31 and /32 have no usable hosts() - use network address
        print(str(net.network_address))
except Exception:
    sys.exit(1)
PYEOF
}

# Validate CIDR (v4). Returns 0 if valid.
is_valid_cidr() {
    local cidr="$1"
    [[ "$cidr" == *"/"* ]] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$cidr" <<'PYEOF' 2>/dev/null
import sys, ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    sys.exit(0 if net.version == 4 else 1)
except Exception:
    sys.exit(1)
PYEOF
        return $?
    fi
    # Fallback without python3: basic A.B.C.D/N check
    local base="${cidr%/*}" mask="${cidr#*/}"
    is_valid_ipv4 "$base" || return 1
    [[ "$mask" =~ ^[0-9]{1,2}$ ]] && [ "$mask" -ge 0 ] && [ "$mask" -le 32 ] || return 1
    return 0
}

# Normalize user spoof input. Sets SPOOF_IP/SPOOF_CIDR/SPOOF_REP_IP/SPOOF_FILTER.
# Returns 1 + prints error if invalid.
normalize_spoof_input() {
    local input="$1"
    input="$(echo "$input" | tr -d '[:space:]')"
    if [[ "$input" == *"/"* ]]; then
        if ! is_valid_cidr "$input"; then
            echo -e "${RED}[!] Invalid CIDR: $input (expected e.g. 1.1.1.0/24)${NC}" >&2
            return 1
        fi
        local rep
        rep="$(cidr_first_host "$input")"
        if [ -z "$rep" ]; then
            echo -e "${RED}[!] Could not derive host IP from CIDR: $input${NC}" >&2
            return 1
        fi
        SPOOF_IP="$input"
        SPOOF_CIDR="$input"
        SPOOF_REP_IP="$rep"
        SPOOF_FILTER="src net $input"
    else
        if ! is_valid_ipv4 "$input"; then
            echo -e "${RED}[!] Invalid IPv4: $input${NC}" >&2
            return 1
        fi
        SPOOF_IP="$input"
        SPOOF_CIDR=""
        SPOOF_REP_IP="$input"
        SPOOF_FILTER="src host $input"
    fi
    return 0
}

# Single IP to use for SNAT --to-source / scapy / nping --source-ip
spoof_rule_ip() {
    echo "${SPOOF_REP_IP:-${SPOOF_IP:-}}"
}

# tcpdump filter fragment for current spoof setting
spoof_filter_expr() {
    if [ -n "${SPOOF_CIDR:-}" ]; then
        echo "src net $SPOOF_CIDR"
    else
        echo "src host ${SPOOF_IP:-}"
    fi
}

# Print up to $2 (default 3) sample spoof IPs, one per line.
# Single IP -> prints it once. CIDR -> first N usable hosts.
# Fast arithmetic version: O(N), never materializes the full host list,
# so even /16 'all' (65k) prints in <1s and /8 won't OOM.
expand_spoof_ips() {
    local input="${1:-${SPOOF_IP:-}}"
    local max="${2:-3}"
    if [[ "$input" != *"/"* ]]; then
        echo "$input"
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        if python3 - "$input" "$max" <<'PYEOF' 2>/dev/null
import sys, ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    n = int(sys.argv[2])
    if net.version != 4:
        sys.exit(1)
    total = net.num_addresses
    if total <= 2:
        # /31 and /32 have no usable hosts() - use network address
        print(str(net.network_address))
        sys.exit(0)
    usable = total - 2
    base = int(net.network_address)
    # clamp n to usable so 'all' (=usable) doesn't overshoot
    if n > usable:
        n = usable
    if n < 1:
        n = 1
    # first N usable hosts: base+1 .. base+N (no big list built)
    out = []
    for i in range(1, n + 1):
        out.append(str(ipaddress.ip_address(base + i)))
    sys.stdout.write("\n".join(out) + "\n")
except Exception:
    sys.exit(1)
PYEOF
        then
            return 0
        fi
    fi
    # Fallback when python3 missing/failed: use known rep IP if it belongs to this input
    if [ -n "${SPOOF_REP_IP:-}" ] && [ "$input" = "${SPOOF_IP:-}" ]; then
        echo "$SPOOF_REP_IP"
        return 0
    fi
    local _rep
    _rep="$(cidr_first_host "$input" 2>/dev/null || true)"
    if [ -n "$_rep" ]; then
        echo "$_rep"
    else
        echo "$input"
    fi
}

# CIDR-aware counter: count tcpdump lines whose SRC IP is the spoof IP (or inside spoof CIDR).
# Usage: count_spoof_packets <logfile>
count_spoof_packets() {
    local logfile="$1"
    [ -f "$logfile" ] || { echo 0; return 0; }
    if [ -n "${SPOOF_CIDR:-}" ]; then
        if command -v python3 >/dev/null 2>&1; then
            local _cnt
            _cnt="$(SPOOF_NET="$SPOOF_CIDR" LOG="$logfile" python3 <<'PYEOF' 2>/dev/null
import os, re, ipaddress
log = os.environ.get("LOG", "")
net_s = os.environ.get("SPOOF_NET", "")
try:
    net = ipaddress.ip_network(net_s, strict=False)
except Exception:
    print(0)
    raise SystemExit
pat = re.compile(r'IP\s+(\d+\.\d+\.\d+\.\d+)\s*>')
cnt = 0
try:
    with open(log, errors="ignore") as f:
        for line in f:
            m = pat.search(line)
            if not m:
                continue
            try:
                if ipaddress.ip_address(m.group(1)) in net:
                    cnt += 1
            except Exception:
                continue
except FileNotFoundError:
    pass
print(cnt)
PYEOF
)"
            if [ -n "$_cnt" ]; then
                echo "$_cnt"
                return 0
            fi
        fi
        # Fallback without python3: count rep-IP hits (subset of true CIDR hits)
        grep -c -F "${SPOOF_REP_IP:-${SPOOF_IP:-}} >" "$logfile" 2>/dev/null || echo 0
    else
        grep -c -F "${SPOOF_IP:-} >" "$logfile" 2>/dev/null || echo 0
    fi
}

# Build a tcpdump filter for an arbitrary expected-spoof value (supports CIDR).
# Usage: spoof_filter_for <ip-or-cidr>
spoof_filter_for() {
    local v="$1"
    if [[ "$v" == *"/"* ]]; then
        echo "src net $v"
    else
        echo "src host $v"
    fi
}

# ---- Spoof-list-from-file helpers ----
# File format: one IP or CIDR per line. Blank lines, leading/trailing spaces,
# and '#' comments (full-line or trailing) are ignored.
# Usage: load_spoof_list_file <path>  -> prints cleaned entries, one per line
load_spoof_list_file() {
    local f="$1"
    [ -f "$f" ] || return 1
    local line cleaned
    while IFS= read -r line || [ -n "$line" ]; do
        # strip CR (Windows file), strip trailing '#...' comment, trim spaces
        line="${line%$'\r'}"
        line="${line%%#*}"
        # trim leading/trailing whitespace (spaces/tabs)
        cleaned="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [ -z "$cleaned" ] && continue
        # strip surrounding single/double quotes (drag-drop paths / quoted entries)
        if [[ "$cleaned" == \"*\" && "$cleaned" == *\" ]]; then
            cleaned="${cleaned#\"}"; cleaned="${cleaned%\"}"
        elif [[ "$cleaned" == \'*\' && "$cleaned" == *\' ]]; then
            cleaned="${cleaned#\'}"; cleaned="${cleaned%\'}"
        fi
        cleaned="$(echo "$cleaned" | tr -d '[:space:]')"
        [ -z "$cleaned" ] && continue
        echo "$cleaned"
    done < "$f"
    return 0
}

# Strip surrounding quotes + all whitespace from a single prompt input.
strip_spoof_arg() {
    local s="${1:-}"
    s="$(echo "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [[ "$s" == \"*\" && "$s" == *\" && ${#s} -ge 2 ]]; then
        s="${s#\"}"; s="${s%\"}"
    elif [[ "$s" == \'*\' && "$s" == *\' && ${#s} -ge 2 ]]; then
        s="${s#\'}"; s="${s%\'}"
    fi
    # '@path' means explicit file; keep the @ for caller to detect, just clean the rest
    if [[ "$s" == @* ]]; then
        local p="${s#@}"
        p="$(echo "$p" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        if [[ "$p" == \"*\" && "$p" == *\" && ${#p} -ge 2 ]]; then
            p="${p#\"}"; p="${p%\"}"
        elif [[ "$p" == \'*\' && "$p" == *\' && ${#p} -ge 2 ]]; then
            p="${p#\'}"; p="${p%\'}"
        fi
        echo "@$p"
    else
        echo "$s" | tr -d '[:space:]'
    fi
}

# CSV sink: reads full CSV (with header) on stdin, writes to $1.
# If $2==1 and dest already exists, header line is stripped and rows appended;
# otherwise dest is overwritten (fresh run). Keeps batch mode to 2 fixed files.
csv_sink() {
    local dest="$1"
    local app="${2:-0}"
    local tmp
    tmp="$(mktemp 2>/dev/null || echo "/tmp/spoof_csv_$$.tmp")"
    cat > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    if [ "$app" -eq 1 ] && [ -s "$dest" ]; then
        tail -n +2 "$tmp" >> "$dest" 2>/dev/null || { rm -f "$tmp"; return 1; }
    else
        cat "$tmp" > "$dest" 2>/dev/null || { rm -f "$tmp"; return 1; }
    fi
    rm -f "$tmp"
    return 0
}

# ---- CSV helpers ----
# Number of usable hosts in a CIDR (0 on failure).
cidr_host_count() {
    local cidr="$1"
    python3 - "$cidr" <<'PYEOF' 2>/dev/null
import sys, ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    n = net.num_addresses
    if n <= 2:
        print(n)
    else:
        print(n - 2)
except Exception:
    print(0)
PYEOF
}

# Adaptive packets-per-IP so full-range scans stay fast but small samples stay proof-grade.
# <=5 IPs  -> 5 pkts (old behavior, max proof)
# 6..20    -> 3 pkts
# >20      -> 2 pkts (fast mode: scapy+nping = 4 pkts/IP, single-SSH batched)
# >200     -> 1 pkt  (very large ranges: 2 pkts/IP total, avoids hours of sending)
raw_pkts_for_n() {
    local n="${1:-1}"
    if ! [[ "$n" =~ ^[0-9]+$ ]]; then n=1; fi
    if [ "$n" -gt 200 ]; then echo 1
    elif [ "$n" -gt 20 ]; then echo 2
    elif [ "$n" -gt 5 ]; then echo 3
    else echo 5
    fi
}

# Capture window so full-range scans don't outrun the fixed 240s tcpdump timeout.
# Small samples keep 240s; large/full ranges get more (capped at 1500s).
capture_timeout_for_n() {
    local n="${1:-1}"
    if ! [[ "$n" =~ ^[0-9]+$ ]]; then n=1; fi
    if [ "$n" -gt 5000 ]; then echo 1500
    elif [ "$n" -gt 1000 ]; then echo 900
    elif [ "$n" -gt 20 ]; then echo 600
    else echo 240
    fi
}

# Strip commas/quotes/newlines so a value is safe inside CSV.
csv_safe() {
    local s="${1:-}"
    s="${s//,/;}"
    s="${s//\"/}"
    s="$(echo "$s" | tr -d '\r\n')"
    echo "$s"
}

# Map full result string to short status: WORKED / NOT_WORKED / SKIPPED / ERROR
result_to_status() {
    local r="${1:-}"
    case "$r" in
        SUCCESS*) echo "WORKED" ;;
        SKIPPED) echo "SKIPPED" ;;
        ERROR*) echo "ERROR" ;;
        *) echo "NOT_WORKED" ;;
    esac
}

# Per-IP received counts from a tcpdump log.
# Usage: per_ip_counts <logfile> <cidr-or-single-ip>
# Outputs lines: "<ip>,<count>" (only ips with count>0, sorted). Empty on failure.
per_ip_counts() {
    local logfile="$1"
    local net="$2"
    [ -f "$logfile" ] || return 0
    [ -n "$net" ] || return 0
    if ! command -v python3 >/dev/null 2>&1; then
        return 0
    fi
    LOG="$logfile" NET="$net" python3 <<'PYEOF' 2>/dev/null
import os, re, ipaddress, collections
log = os.environ.get("LOG", "")
net_s = os.environ.get("NET", "")
try:
    if "/" in net_s:
        net = ipaddress.ip_network(net_s, strict=False)
        is_net = True
    else:
        addr = ipaddress.ip_address(net_s)
        net = None
        is_net = False
except Exception:
    raise SystemExit
pat = re.compile(r'IP\s+(\d+\.\d+\.\d+\.\d+)\s*>')
cnt = collections.Counter()
try:
    with open(log, errors="ignore") as f:
        for line in f:
            m = pat.search(line)
            if not m:
                continue
            ip_s = m.group(1)
            try:
                ip = ipaddress.ip_address(ip_s)
            except Exception:
                continue
            if is_net:
                if ip in net:
                    cnt[ip_s] += 1
            else:
                if ip_s == net_s:
                    cnt[ip_s] += 1
except FileNotFoundError:
    pass
for ip_s in sorted(cnt, key=lambda x: tuple(int(p) for p in x.split("."))):
    print("%s,%d" % (ip_s, cnt[ip_s]))
PYEOF
}

# Write CSV result file(s). Called once at end of auto_test.
# ALWAYS writes 2 fixed files (overwritten each run):
#   ./spoof_summary.csv (very summarized, per-direction rows)
#   ./spoof_full.csv    (full per-IP detail)
write_csv_results() {
    local ts
    ts="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "run$$")"
    local outdir
    outdir="$(pwd)"
    local spoof_label="${SPOOF_IP:-unknown}"
    # Fixed filenames: each run replaces the old files (no timestamp pile-up).
    local summary="$outdir/spoof_summary.csv"
    local full="$outdir/spoof_full.csv"
    local ts_iso
    ts_iso="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$ts")"

    local d_status r_status
    d_status="$(result_to_status "${direct_res:-NOT_RUN}")"
    r_status="$(result_to_status "${reverse_res:-NOT_RUN}")"
    local d_res_s r_res_s
    d_res_s="$(csv_safe "${direct_res:-NOT_RUN}")"
    r_res_s="$(csv_safe "${reverse_res:-NOT_RUN}")"
    # Batch mode: first target overwrites (fresh headers), rest append rows.
    local _append="${CSV_APPEND:-0}"
    local _mode_word="overwritten"
    [ "$_append" -eq 1 ] && _mode_word="appended"

    if [ -z "${SPOOF_CIDR:-}" ]; then
        # ---------- SINGLE IP: summary + full (same 2 fixed files) ----------
        {
            echo "timestamp,spoof_ip,iran_ip,foreign_ip,direction,result,status,spoofed_pkts,real_leaked,nping_proof,raw_used"
            if [ "${direct_res:-SKIPPED}" != "SKIPPED" ]; then
                echo "$ts_iso,$spoof_label,${LOCAL_IP:-},${FOREIGN_IP:-},direct,$d_res_s,$d_status,${direct_spoof_cnt:-0},${direct_new_real:-0},${direct_nping_proven:-0},${direct_raw_ran:-0}"
            else
                echo "$ts_iso,$spoof_label,${LOCAL_IP:-},${FOREIGN_IP:-},direct,SKIPPED,SKIPPED,0,0,0,0"
            fi
            if [ "${reverse_res:-SKIPPED}" != "SKIPPED" ]; then
                echo "$ts_iso,$spoof_label,${LOCAL_IP:-},${FOREIGN_IP:-},reverse,$r_res_s,$r_status,${reverse_spoof_cnt:-0},${reverse_new_real:-0},${reverse_nping_proven:-0},${reverse_raw_ran:-0}"
            else
                echo "$ts_iso,$spoof_label,${LOCAL_IP:-},${FOREIGN_IP:-},reverse,SKIPPED,SKIPPED,0,0,0,0"
            fi
        } | csv_sink "$summary" "$_append" || {
            echo -e "${RED}[!] Could not write CSV: $summary${NC}"
            return 1
        }
        # Full per-IP detail for single IP (so we always produce 2 files).
        {
            echo "timestamp,spoof_cidr,spoof_ip,direction,sent_est,received_pkts,status,method,note"
            if [ "${direct_res:-SKIPPED}" != "SKIPPED" ]; then
                _d_st="$(result_to_status "${direct_res:-}")"
                [ "$_d_st" = "SKIPPED" ] && _d_st="NOT_WORKED"
                _d_rcvd="${direct_spoof_cnt:-0}"
                _d_m="SNAT"; [ "${direct_raw_ran:-0}" -eq 1 ] && _d_m="SNAT+RAW"
                echo "$ts_iso,$spoof_label,$spoof_label,direct,5,$_d_rcvd,$_d_st,$_d_m,"
            fi
            if [ "${reverse_res:-SKIPPED}" != "SKIPPED" ]; then
                _r_st="$(result_to_status "${reverse_res:-}")"
                [ "$_r_st" = "SKIPPED" ] && _r_st="NOT_WORKED"
                _r_rcvd="${reverse_spoof_cnt:-0}"
                _r_m="SNAT+nft"; [ "${reverse_raw_ran:-0}" -eq 1 ] && _r_m="SNAT+nft+RAW"
                echo "$ts_iso,$spoof_label,$spoof_label,reverse,10,$_r_rcvd,$_r_st,$_r_m,"
            fi
        } | csv_sink "$full" "$_append" || {
            echo -e "${RED}[!] Could not write CSV: $full${NC}"
            return 1
        }
        CSV_SUMMARY_FILE="$summary"
        CSV_FULL_FILE="$full"
        echo
        echo -e "${GREEN}[+] CSV summary ${_mode_word}: $summary${NC}"
        cat "$summary" || true
        echo
        echo -e "${GREEN}[+] CSV full ${_mode_word}: $full${NC}"
        cat "$full" || true
    else
        # ---------- CIDR MODE: very summarized + full ----------
        local host_total sample_n
        host_total="$(cidr_host_count "$SPOOF_CIDR" 2>/dev/null || echo 0)"
        host_total="${host_total:-0}"
        sample_n="${CIDR_SAMPLE_MAX:-3}"
        # sample_n is numeric here (resolved at prompt time); guard anyway
        if ! [[ "$sample_n" =~ ^[0-9]+$ ]]; then
            sample_n=3
        fi

        # Tested sample list (deterministic: first N hosts)
        local -a tested_ips
        mapfile -t tested_ips < <(expand_spoof_ips "$SPOOF_CIDR" "$sample_n")
        if [ "${#tested_ips[@]}" -eq 0 ]; then
            tested_ips=("$(spoof_rule_ip)")
        fi

        # Observed per-IP counts from captures (may be empty if logs missing)
        declare -A d_obs r_obs
        local line ip cnt
        if [ -n "${DIRECT_RX_LOG:-}" ] && [ -f "$DIRECT_RX_LOG" ]; then
            while IFS=, read -r ip cnt; do
                [ -n "$ip" ] || continue
                d_obs["$ip"]="${cnt:-0}"
            done < <(per_ip_counts "$DIRECT_RX_LOG" "$SPOOF_CIDR")
        fi
        if [ -n "${REVERSE_RX_LOG:-}" ] && [ -f "$REVERSE_RX_LOG" ]; then
            while IFS=, read -r ip cnt; do
                [ -n "$ip" ] || continue
                r_obs["$ip"]="${cnt:-0}"
            done < <(per_ip_counts "$REVERSE_RX_LOG" "$SPOOF_CIDR")
        fi

        # Worked sample IPs per direction (tcpdump evidence only).
        # Overall WORKED may also come from nping reply proof (no tcpdump hit).
        local d_worked=0 r_worked=0
        local -a d_worked_ips r_worked_ips
        d_worked_ips=()
        r_worked_ips=()
        for ip in "${tested_ips[@]}"; do
            if [ "${d_obs[$ip]:-0}" -gt 0 ] 2>/dev/null; then
                d_worked=$((d_worked + 1))
                d_worked_ips+=("$ip")
            fi
            if [ "${r_obs[$ip]:-0}" -gt 0 ] 2>/dev/null; then
                r_worked=$((r_worked + 1))
                r_worked_ips+=("$ip")
            fi
        done
        # If nping proved arrival but tcpdump missed everything, count rep IP as worked
        # so summary worked_ips is not misleadingly 0 while overall is WORKED.
        local rep
        rep="$(spoof_rule_ip)"
        if [ "$d_worked" -eq 0 ] && [ "${direct_nping_proven:-0}" -eq 1 ] && [ "${direct_res:-}" != "SKIPPED" ]; then
            d_worked=1
            d_worked_ips=("$rep")
        fi
        if [ "$r_worked" -eq 0 ] && [ "${reverse_nping_proven:-0}" -eq 1 ] && [ "${reverse_res:-}" != "SKIPPED" ]; then
            r_worked=1
            r_worked_ips=("$rep")
        fi
        local d_worked_list r_worked_list
        # Truncate worked list in summary when huge (full /16 = 65k IPs -> 1MB line).
        # Full detail stays in spoof_full.csv; summary keeps first 20 + count.
        if [ "${#d_worked_ips[@]}" -gt 20 ]; then
            d_worked_list="$(IFS=';'; echo "${d_worked_ips[*]:0:20}")...(+$(( ${#d_worked_ips[@]} - 20 )) more; see spoof_full.csv)"
        elif [ "${#d_worked_ips[@]}" -gt 0 ]; then
            d_worked_list="$(IFS=';'; echo "${d_worked_ips[*]}")"
        else
            d_worked_list=""
        fi
        if [ "${#r_worked_ips[@]}" -gt 20 ]; then
            r_worked_list="$(IFS=';'; echo "${r_worked_ips[*]:0:20}")...(+$(( ${#r_worked_ips[@]} - 20 )) more; see spoof_full.csv)"
        elif [ "${#r_worked_ips[@]}" -gt 0 ]; then
            r_worked_list="$(IFS=';'; echo "${r_worked_ips[*]}")"
        else
            r_worked_list=""
        fi

        # ----- File 1: very summarized (one row per tested direction) -----
        {
            echo "timestamp,spoof_cidr,iran_ip,foreign_ip,direction,overall_result,status,total_spoofed_pkts,worked_ips,worked_ip_list,tested_ips,total_hosts_in_cidr,nping_proof"
            if [ "${direct_res:-SKIPPED}" != "SKIPPED" ]; then
                echo "$ts_iso,$SPOOF_CIDR,${LOCAL_IP:-},${FOREIGN_IP:-},direct,$d_res_s,$d_status,${direct_spoof_cnt:-0},$d_worked,$(csv_safe "$d_worked_list"),${#tested_ips[@]},$host_total,${direct_nping_proven:-0}"
            fi
            if [ "${reverse_res:-SKIPPED}" != "SKIPPED" ]; then
                echo "$ts_iso,$SPOOF_CIDR,${LOCAL_IP:-},${FOREIGN_IP:-},reverse,$r_res_s,$r_status,${reverse_spoof_cnt:-0},$r_worked,$(csv_safe "$r_worked_list"),${#tested_ips[@]},$host_total,${reverse_nping_proven:-0}"
            fi
        } | csv_sink "$summary" "$_append" || {
            echo -e "${RED}[!] Could not write CSV: $summary${NC}"
            return 1
        }

        # ----- File 2: full per-IP detail -----
        # ----- File 2: full per-IP detail (fast for full ranges: O(N) lookups, no per-row forks) -----
        {
            echo "timestamp,spoof_cidr,spoof_ip,direction,sent_est,received_pkts,status,method,note"
            # union of tested + observed ips so nothing seen on wire is lost
            declare -A all_ips tested_set
            local _t
            for _t in "${tested_ips[@]}"; do tested_set["$_t"]=1; all_ips["$_t"]=1; done
            for ip in "${!d_obs[@]}"; do all_ips["$ip"]=1; done
            for ip in "${!r_obs[@]}"; do all_ips["$ip"]=1; done
            # actual RAW packets/IP used this run (adaptive): scapy+nping per IP
            local _raw_per="${RAW_PKTS_PER_IP:-5}"
            if ! [[ "$_raw_per" =~ ^[0-9]+$ ]]; then _raw_per=5; fi
            local _raw_total=$((_raw_per * 2))
            local sorted_ips
            sorted_ips="$(printf '%s\n' "${!all_ips[@]}" | python3 -c 'import sys; ips=[l.strip() for l in sys.stdin if l.strip()]; ips.sort(key=lambda x: tuple(int(p) for p in x.split("."))); print("\n".join(ips))' 2>/dev/null || printf '%s\n' "${!all_ips[@]}" | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n)"
            # direct rows
            if [ "${direct_res:-SKIPPED}" != "SKIPPED" ]; then
                while IFS= read -r ip; do
                    [ -n "$ip" ] || continue
                    local rcvd="${d_obs[$ip]:-0}"
                    local sent method status note=""
                    if [ "$ip" = "$rep" ]; then
                        sent=5
                        method="SNAT"
                        if [ "${direct_raw_ran:-0}" -eq 1 ]; then
                            sent=$((sent + _raw_total))
                            method="SNAT+RAW"
                        fi
                    else
                        if [ "${direct_raw_ran:-0}" -eq 1 ]; then
                            sent="$_raw_total"
                            method="RAW"
                        else
                            sent=0
                            method="not-sent"
                            note="not in RAW sample; only rep IP sent via SNAT"
                        fi
                    fi
                    if [ "$rcvd" -gt 0 ] 2>/dev/null; then
                        status="WORKED"
                    elif [ "${direct_nping_proven:-0}" -eq 1 ] && [ "$ip" = "$rep" ]; then
                        status="WORKED"
                        if [ -n "$note" ]; then
                            note="$note; nping reply proof (tcpdump missed it)"
                        else
                            note="nping reply proof (tcpdump missed it)"
                        fi
                    else
                        status="NOT_WORKED"
                    fi
                    # mark observed-but-untested (O(1) assoc lookup, not O(N) loop)
                    if [ -z "${tested_set[$ip]:-}" ]; then
                        note="observed on wire but not in tested sample${note:+; $note}"
                        [ "$sent" -eq 0 ] && method="observed-only"
                    fi
                    # fast path: notes here contain no commas/quotes, skip csv_safe fork
                    if [[ "$note" == *[,\"\"]* ]]; then note="$(csv_safe "$note")"; fi
                    echo "$ts_iso,$SPOOF_CIDR,$ip,direct,$sent,$rcvd,$status,$method,$note"
                done <<< "$sorted_ips"
            fi
            # reverse rows
            if [ "${reverse_res:-SKIPPED}" != "SKIPPED" ]; then
                while IFS= read -r ip; do
                    [ -n "$ip" ] || continue
                    local rcvd="${r_obs[$ip]:-0}"
                    local sent method status note=""
                    if [ "$ip" = "$rep" ]; then
                        sent=10
                        method="SNAT+nft"
                        if [ "${reverse_raw_ran:-0}" -eq 1 ]; then
                            sent=$((sent + _raw_total))
                            method="SNAT+nft+RAW"
                        fi
                    else
                        if [ "${reverse_raw_ran:-0}" -eq 1 ]; then
                            sent="$_raw_total"
                            method="RAW"
                        else
                            sent=0
                            method="not-sent"
                            note="not in RAW sample; only rep IP sent via SNAT/nft"
                        fi
                    fi
                    if [ "$rcvd" -gt 0 ] 2>/dev/null; then
                        status="WORKED"
                    elif [ "${reverse_nping_proven:-0}" -eq 1 ] && [ "$ip" = "$rep" ]; then
                        status="WORKED"
                        note="nping reply proof (tcpdump missed it)${note:+; $note}"
                    else
                        status="NOT_WORKED"
                    fi
                    if [ -z "${tested_set[$ip]:-}" ]; then
                        note="observed on wire but not in tested sample${note:+; $note}"
                        [ "$sent" -eq 0 ] && method="observed-only"
                    fi
                    if [[ "$note" == *[,\"\"]* ]]; then note="$(csv_safe "$note")"; fi
                    echo "$ts_iso,$SPOOF_CIDR,$ip,reverse,$sent,$rcvd,$status,$method,$note"
                done <<< "$sorted_ips"
            fi
        } | csv_sink "$full" "$_append" || {
            echo -e "${RED}[!] Could not write CSV: $full${NC}"
            return 1
        }

        CSV_SUMMARY_FILE="$summary"
        CSV_FULL_FILE="$full"
        echo
        echo -e "${GREEN}[+] CSV summary (${_mode_word}): $summary${NC}"
        cat "$summary" || true
        echo
        echo -e "${GREEN}[+] CSV full per-IP detail (${_mode_word}): $full${NC}"
        echo -e "${BLUE}--- full CSV preview (first 20 lines) ---${NC}"
        head -20 "$full" || true
    fi

    # Cleanup preserved capture logs (keep when DEBUG=1 for analysis)
    if [ "${DEBUG:-0}" -eq 0 ]; then
        rm -f "${DIRECT_RX_LOG:-}" "${REVERSE_RX_LOG:-}" "${DIRECT_NPING_LOG:-}" "${REVERSE_NPING_LOG:-}" 2>/dev/null || true
    else
        echo -e "${CYAN}DEBUG=1: capture logs kept for analysis:${NC}"
        echo "  ${DIRECT_RX_LOG:-} ${REVERSE_RX_LOG:-} ${DIRECT_NPING_LOG:-} ${REVERSE_NPING_LOG:-}"
    fi
    return 0
}

cleanup() {
    if [ "$RULE_ADDED" -eq 1 ] && [ -n "${DST_IP:-}" ] && [ -n "${SPOOF_IP:-}" ]; then
        echo
        echo -e "${YELLOW}[*] Removing local iptables rule...${NC}"

        local _rep="${SPOOF_REP_IP:-${SPOOF_IP:-}}"
        iptables -t nat -D POSTROUTING \
            -p icmp \
            -d "$DST_IP" \
            -j SNAT \
            --to-source "$_rep" 2>/dev/null || true
        # Legacy fallback: also try raw input (covers old single-IP runs)
        if [ "$_rep" != "$SPOOF_IP" ]; then
            iptables -t nat -D POSTROUTING \
                -p icmp \
                -d "$DST_IP" \
                -j SNAT \
                --to-source "$SPOOF_IP" 2>/dev/null || true
        fi

        RULE_ADDED=0
        echo -e "${GREEN}[+] Local rule removed.${NC}"
    fi

    if [ "$REMOTE_RULE_ADDED" -eq 1 ] && [ -n "${FOREIGN_IP:-}" ] && [ -n "${FOREIGN_PASS:-}" ] && [ -n "${LOCAL_IP:-}" ] && [ -n "${SPOOF_IP:-}" ]; then
        echo
        echo -e "${YELLOW}[*] Removing remote iptables rule on Foreign server...${NC}"

        local remote_prefix=""
        if [ "${FOREIGN_USER:-root}" != "root" ]; then
            remote_prefix="echo '$FOREIGN_PASS' | sudo -S "
        fi
        local _rep="${SPOOF_REP_IP:-${SPOOF_IP:-}}"

        sshpass -p "$FOREIGN_PASS" ssh -p "${FOREIGN_PORT:-22}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            -o LogLevel=ERROR \
            "${FOREIGN_USER:-root}@$FOREIGN_IP" \
            "${remote_prefix}iptables -t nat -D POSTROUTING -p icmp -d '$LOCAL_IP' -j SNAT --to-source '$_rep' 2>/dev/null || true; ${remote_prefix}iptables -t nat -D POSTROUTING -p icmp -j SNAT --to-source '$_rep' 2>/dev/null || true; ${remote_prefix}iptables -t nat -D POSTROUTING -p icmp -d '$LOCAL_IP' -j SNAT --to-source '$SPOOF_IP' 2>/dev/null || true; ${remote_prefix}iptables -t nat -D POSTROUTING -p icmp -j SNAT --to-source '$SPOOF_IP' 2>/dev/null || true; ${remote_prefix}iptables -t nat -D POSTROUTING -s '$SPOOF_IP' -j ACCEPT 2>/dev/null || true; ${remote_prefix}iptables -t nat -D POSTROUTING -s '$_rep' -j ACCEPT 2>/dev/null || true; ${remote_prefix}nft delete table ip spoof_test 2>/dev/null || true" 2>/dev/null || true

        REMOTE_RULE_ADDED=0
        echo -e "${GREEN}[+] Remote rule removed.${NC}"
    fi

    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    if [ "$DEBUG" -eq 1 ]; then
        echo
        echo -e "${CYAN}=== DEBUG bundle saved: $DEBUG_LOG ===${NC}"
        echo "Capture logs kept: /tmp/foreign_rx_$$.log /tmp/iran_rx_$$.log /tmp/*_nping_$$.log"
        echo "Send the DEBUG bundle + capture logs for analysis."
    else
        rm -f /tmp/foreign_rx_$$.log /tmp/iran_rx_$$.log /tmp/*_nping_$$.log 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] Run this script as root:${NC}"
        echo "sudo bash $0"
        exit 1
    fi
}

check_tools() {
    # Install all local dependencies before showing the main menu.
    # The script must already be running as root (require_root runs first).
    local pm=""
    local updated=0
    local install_failed=0

    if command -v apt-get >/dev/null 2>&1; then
        pm="apt"
    elif command -v dnf >/dev/null 2>&1; then
        pm="dnf"
    elif command -v yum >/dev/null 2>&1; then
        pm="yum"
    elif command -v pacman >/dev/null 2>&1; then
        pm="pacman"
    elif command -v apk >/dev/null 2>&1; then
        pm="apk"
    fi

    _install_pkg() {
        local pkg="$1"
        case "$pm" in
            apt)
                if [ "$updated" -eq 0 ]; then
                    echo -e "${BLUE}[*] Updating APT package index...${NC}"
                    DEBIAN_FRONTEND=noninteractive apt-get update -y || return 1
                    updated=1
                fi
                DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
                ;;
            dnf)
                dnf install -y "$pkg"
                ;;
            yum)
                yum install -y "$pkg"
                ;;
            pacman)
                if [ "$updated" -eq 0 ]; then
                    pacman -Sy --noconfirm || return 1
                    updated=1
                fi
                pacman -S --needed --noconfirm "$pkg"
                ;;
            apk)
                apk add --no-cache "$pkg"
                ;;
            *)
                return 1
                ;;
        esac
    }

    # command: apt | dnf/yum | pacman | apk
    # Packages are intentionally mapped per command because distro names differ.
    _ensure_cmd() {
        local cmd="$1" apt_pkg="$2" rpm_pkg="$3" arch_pkg="$4" apk_pkg="$5"
        if command -v "$cmd" >/dev/null 2>&1; then
            return 0
        fi

        echo -e "${YELLOW}[*] Missing dependency: $cmd - installing...${NC}"
        local pkg=""
        case "$pm" in
            apt) pkg="$apt_pkg" ;;
            dnf|yum) pkg="$rpm_pkg" ;;
            pacman) pkg="$arch_pkg" ;;
            apk) pkg="$apk_pkg" ;;
        esac

        if [ -z "$pm" ] || [ -z "$pkg" ]; then
            echo -e "${RED}[!] No supported package manager/package mapping for: $cmd${NC}"
            return 1
        fi

        _install_pkg "$pkg" || {
            echo -e "${RED}[!] Package install failed for $cmd (package: $pkg).${NC}"
            return 1
        }

        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${RED}[!] $cmd is still unavailable after installation.${NC}"
            return 1
        fi
        echo -e "${GREEN}[+] $cmd installed.${NC}"
        return 0
    }

    echo -e "${BLUE}[*] Checking local dependencies...${NC}"
    if [ -z "$pm" ]; then
        echo -e "${YELLOW}[!] Supported package manager not detected (apt/dnf/yum/pacman/apk).${NC}"
        echo -e "${YELLOW}    Existing commands will be checked, but missing packages cannot be auto-installed.${NC}"
    else
        echo -e "${BLUE}[*] Package manager: $pm${NC}"
    fi

    # Core networking / capture tools used by all test modes.
    _ensure_cmd ip          iproute2          iproute             iproute2          iproute2          || install_failed=1
    _ensure_cmd iptables    iptables          iptables            iptables          iptables          || install_failed=1
    _ensure_cmd nft         nftables          nftables            nftables          nftables          || install_failed=1
    _ensure_cmd ping        iputils-ping      iputils             iputils           iputils           || install_failed=1
    _ensure_cmd tcpdump     tcpdump           tcpdump             tcpdump           tcpdump           || install_failed=1
    _ensure_cmd conntrack   conntrack         conntrack-tools     conntrack-tools   conntrack-tools   || install_failed=1
    _ensure_cmd nping       nmap              nmap                nmap              nmap              || install_failed=1
    _ensure_cmd ssh         openssh-client    openssh-clients     openssh           openssh-client     || install_failed=1
    _ensure_cmd sshpass     sshpass           sshpass             sshpass           sshpass           || install_failed=1
    _ensure_cmd curl        curl              curl                curl              curl              || install_failed=1
    _ensure_cmd python3     python3           python3             python            python3           || install_failed=1
    _ensure_cmd pip3        python3-pip       python3-pip         python-pip         py3-pip           || true

    # Common userland commands the script relies on. Usually already present,
    # but install the base package if they are not.
    _ensure_cmd timeout     coreutils         coreutils           coreutils          coreutils          || install_failed=1

    # Optional but recommended for long batch/CIDR runs over SSH.
    _ensure_cmd screen      screen            screen              screen             screen             ||         echo -e "${YELLOW}[!] Optional dependency 'screen' could not be installed; continuing without it.${NC}"

    # Scapy is imported by Python rather than exposed as a required command.
    if ! python3 -c 'import scapy' >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Missing Python module: scapy - installing...${NC}"
        case "$pm" in
            apt)
                _install_pkg python3-scapy || true
                ;;
            dnf|yum)
                # Package availability differs between RPM repositories; try pip below if needed.
                _install_pkg python3-scapy || true
                ;;
            pacman)
                _install_pkg python-scapy || true
                ;;
            apk)
                _install_pkg py3-scapy || true
                ;;
        esac

        if ! python3 -c 'import scapy' >/dev/null 2>&1; then
            if command -v pip3 >/dev/null 2>&1; then
                echo -e "${YELLOW}[*] Distro package did not provide Scapy; trying pip3...${NC}"
                pip3 install --break-system-packages scapy >/dev/null 2>&1 \
                    || pip3 install scapy >/dev/null 2>&1 \
                    || true
            fi
        fi

        if python3 -c 'import scapy' >/dev/null 2>&1; then
            echo -e "${GREEN}[+] Python Scapy installed.${NC}"
        else
            echo -e "${RED}[!] Python Scapy is still unavailable.${NC}"
            install_failed=1
        fi
    fi

    # Final verification: fail before the menu if a required dependency is missing.
    local missing=()
    local cmd
    for cmd in ip iptables nft ping tcpdump conntrack nping ssh sshpass curl python3 timeout; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    python3 -c 'import scapy' >/dev/null 2>&1 || missing+=("python3-scapy")

    if [ "${#missing[@]}" -gt 0 ]; then
        echo -e "${RED}[!] Required dependencies are still missing:${NC} ${missing[*]}"
        echo -e "${RED}[!] Install them manually and re-run the script.${NC}"
        return 1
    fi

    if [ "$install_failed" -ne 0 ]; then
        echo -e "${YELLOW}[*] Some installation attempts reported errors, but final dependency verification passed.${NC}"
    fi

    echo -e "${GREEN}[+] All local dependencies are ready.${NC}"
    return 0
}

check_sshpass() {
    if ! command -v sshpass >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] sshpass is required for automated SSH testing.${NC}"
        echo -e "${YELLOW}[*] Attempting to install sshpass...${NC}"
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y && apt-get install -y sshpass
        elif command -v yum >/dev/null 2>&1; then
            yum install -y sshpass
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y sshpass
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm sshpass
        elif command -v apk >/dev/null 2>&1; then
            apk add sshpass
        fi

        if ! command -v sshpass >/dev/null 2>&1; then
            echo -e "${RED}[!] Could not install sshpass automatically.${NC}"
            echo "Please install it manually (e.g., 'apt install -y sshpass') and re-run."
            return 1
        fi
        echo -e "${GREEN}[+] sshpass installed successfully.${NC}"
    fi
    return 0
}

wait_for_tcpdump_ready() {
    local logfile="$1"
    local i
    for i in $(seq 1 12); do
        if grep -qi "listening on" "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ssh_foreign() {
    dbg_log "SSH>> $*"
    sshpass -p "$FOREIGN_PASS" ssh -p "$FOREIGN_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -o LogLevel=ERROR \
        "$FOREIGN_USER@$FOREIGN_IP" "$@"
}

remote_prefix_cmd() {
    if [ "${FOREIGN_USER:-root}" != "root" ]; then
        echo "echo '$FOREIGN_PASS' | sudo -S "
    else
        echo ""
    fi
}

local_diag() {
    echo
    echo "======================================================"
    echo "   IRAN (LOCAL) SERVER DIAGNOSTICS"
    echo "======================================================"
    echo "===== virt ====="
    systemd-detect-virt 2>/dev/null || echo "no systemd-detect-virt"
    echo "===== os ====="
    cat /etc/os-release 2>/dev/null | head -5
    uname -r
    echo "===== iptables backend ====="
    iptables --version 2>&1
    ls -la /etc/alternatives/iptables* 2>/dev/null || true
    echo "===== nat table ====="
    iptables -t nat -L POSTROUTING -n -v --line-numbers 2>&1
    echo "===== mangle table ====="
    iptables -t mangle -L POSTROUTING -n -v --line-numbers 2>&1 | head -20 || true
    echo "===== route to Foreign ($FOREIGN_IP) ====="
    ip route get "$FOREIGN_IP" 2>&1 || true
    echo "===== sysctl ====="
    sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter 2>&1 || true
    echo "======================================================"
    echo
}

remote_diag() {
    local rp
    rp="$(remote_prefix_cmd)"
    echo
    echo "======================================================"
    echo "   FOREIGN SERVER DIAGNOSTICS (debug info)"
    echo "======================================================"
    ssh_foreign "
        echo '===== virt ====='
        systemd-detect-virt 2>/dev/null || echo 'no systemd-detect-virt'
        echo '===== os ====='
        cat /etc/os-release 2>/dev/null | head -5
        uname -r
        echo '===== iptables backend ====='
        iptables --version 2>&1
        update-alternatives --display iptables 2>/dev/null | head -10 || true
        ls -la /etc/alternatives/iptables* 2>/dev/null || true
        echo '===== nft nat table (FULL - Docker hides here) ====='
        (command -v nft >/dev/null 2>&1 && nft list table ip nat 2>&1 | head -100) || echo 'no nft nat table'
        echo '===== nft ruleset ip filter POSTROUTING refs ====='
        (command -v nft >/dev/null 2>&1 && nft list ruleset 2>&1 | grep -B2 -A8 -i 'postrouting\|snat\|masquerade' | head -80) || echo 'no nft or empty'
        echo '===== iptables-save nat (authoritative order) ====='
        ${rp}iptables-save -t nat 2>&1 | head -40 || true
        echo '===== nat table ====='
        ${rp}iptables -t nat -L POSTROUTING -n -v --line-numbers 2>&1
        echo '===== nat table (legacy check) ====='
        (command -v iptables-legacy >/dev/null 2>&1 && ${rp}iptables-legacy -t nat -L POSTROUTING -n -v --line-numbers 2>&1 | head -15) || echo 'no iptables-legacy'
        echo '===== mangle table ====='
        ${rp}iptables -t mangle -L POSTROUTING -n -v --line-numbers 2>&1 | head -20 || true
        echo '===== conntrack for Iran IP (stale entries shadow SNAT!) ====='
        (command -v conntrack >/dev/null 2>&1 && ${rp}conntrack -L -d '$LOCAL_IP' 2>&1 | head -10) || echo 'no conntrack tool'
        echo '===== route to Iran ($LOCAL_IP) ====='
        ip route get '$LOCAL_IP' 2>&1
        echo '===== policy routing (tunnels can hijack path!) ====='
        ip rule list 2>&1 | head -15
        ip addr show 2>&1 | grep -E 'inet ' | head -10
        echo '===== sysctl ====='
        sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter 2>&1
        echo '===== raw spoof tools ====='
        for t in nping hping3 python3 conntrack; do command -v \$t >/dev/null 2>&1 && echo \"FOUND: \$t\" || echo \"missing: \$t\"; done
        python3 -c 'import scapy; print(\"scapy OK\")' 2>&1 | head -2 || echo 'no scapy'
    "
    echo "======================================================"
    echo "   END DIAGNOSTICS (also saved to $DEBUG_LOG)"
    echo "======================================================"
    echo
}

ensure_scapy_remote() {
    local rp
    rp="$(remote_prefix_cmd)"
    ssh_foreign "
        python3 -c 'import scapy' 2>/dev/null && echo 'scapy OK' && exit 0
        echo '[*] Installing scapy on Foreign...'
        if command -v apt-get >/dev/null 2>&1; then
            ${rp}apt-get update -q 2>&1 | tail -1
            ${rp}apt-get install -y -q python3-scapy 2>&1 | tail -2
        fi
        python3 -c 'import scapy' 2>/dev/null && echo 'scapy OK via apt' && exit 0
        (pip3 install --break-system-packages -q scapy 2>&1 | tail -2 || pip install --break-system-packages -q scapy 2>&1 | tail -2) || true
        python3 -c 'import scapy' 2>/dev/null && echo 'scapy OK via pip' && exit 0
        echo 'scapy install FAILED'
    "
}

ensure_scapy_local() {
    python3 -c "import scapy" 2>/dev/null && return 0
    echo -e "${YELLOW}[*] Installing scapy locally...${NC}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -q 2>&1 | tail -1
        apt-get install -y -q python3-scapy 2>&1 | tail -2 || true
    fi
    python3 -c "import scapy" 2>/dev/null && return 0
    (pip3 install --break-system-packages -q scapy 2>&1 | tail -2 || pip install --break-system-packages -q scapy 2>&1 | tail -2) || true
    python3 -c "import scapy" 2>/dev/null && return 0
    return 1
}

check_nping_proof() {
    local nping_log="$1"
    local spoof="$2"
    if [ -f "$nping_log" ] && grep -q "RCVD" "$nping_log" 2>/dev/null && grep -q "Echo reply" "$nping_log" 2>/dev/null; then
        echo -e "${GREEN}[+] PROOF: target replied to spoofed source ($spoof) - spoofed packet ARRIVED (see RCVD line above).${NC}"
        echo "SPOOF_PROVEN_BY_REPLY" >> "$nping_log"
        return 0
    fi
    return 1
}

remote_nft_spoof() {
    local target="$1"
    local spoof="$2"
    local rp
    rp="$(remote_prefix_cmd)"
    # nft snat needs a single IP - resolve CIDR to first usable host
    local snat_ip="$spoof"
    if [[ "$spoof" == *"/"* ]]; then
        local _rep
        _rep="$(cidr_first_host "$spoof")"
        if [ -n "$_rep" ]; then
            snat_ip="$_rep"
            echo -e "${BLUE}[*] CIDR $spoof -> nft SNAT uses representative IP $snat_ip${NC}"
        fi
    fi
    echo -e "${CYAN}--- Phase 1b: nft-native SNAT (priority 90 beats Docker MASQUERADE at 100) ---${NC}"
    REMOTE_RULE_ADDED=1
    ssh_foreign "
        ${rp}nft create table ip spoof_test 2>/dev/null || true
        ${rp}nft flush table ip spoof_test 2>/dev/null || true
        ${rp}nft create chain ip spoof_test out '{ type nat hook postrouting priority 90; policy accept; }' 2>&1
        echo \"NFT_CHAIN_RC=\$?\"
        ${rp}nft insert rule ip spoof_test out counter ip protocol icmp ip daddr '$target' snat ip to '$snat_ip' 2>&1
        echo \"NFT_ADD_RC=\$?\"
        ${rp}nft list chain ip spoof_test out 2>&1
        (command -v conntrack >/dev/null 2>&1 && ${rp}conntrack -D -d '$target' 2>&1 | head -3) || echo '(no conntrack, skipping)'
        ping -c 5 -W 1 '$target' || true
        echo '--- nft counters after ping ---'
        ${rp}nft list chain ip spoof_test out 2>&1
        NFT_CNT=$(${rp}nft list chain ip spoof_test out 2>/dev/null | grep -o 'packets [0-9][0-9]*' | head -1 | grep -o '[0-9][0-9]*')
        echo \"NFT_MATCHED_PKTS=${NFT_CNT:-0} (0 = nft rule never matched)\"
    "
    REMOTE_RULE_ADDED=0
    ssh_foreign "${rp}nft delete table ip spoof_test 2>/dev/null || true" || true
}

remote_nat_exempt() {
    local spoof="$1"
    local rp
    rp="$(remote_prefix_cmd)"
    echo -e "${CYAN}--- Phase 1c: MASQUERADE exemption for spoofed src (temporary, removed after test) ---${NC}"
    REMOTE_RULE_ADDED=1
    ssh_foreign "
        ${rp}iptables -t nat -I POSTROUTING 1 -s '$spoof' -j ACCEPT 2>&1
        echo \"EXEMPT_ADD_RC=\$?\"
        ${rp}iptables -t nat -L POSTROUTING -n -v --line-numbers 2>&1 | head -8
    "
}

remote_nat_unexempt() {
    local spoof="$1"
    local rp
    rp="$(remote_prefix_cmd)"
    ssh_foreign "${rp}iptables -t nat -D POSTROUTING -s '$spoof' -j ACCEPT 2>/dev/null || true" || true
    REMOTE_RULE_ADDED=0
    echo -e "${BLUE}[*] MASQUERADE exemption removed.${NC}"
}

remote_raw_spoof() {
    local target="$1"
    local spoof="$2"
    local nping_log="${3:-/dev/null}"
    local rp
    rp="$(remote_prefix_cmd)"
    # How many IPs will we cover? (single IP -> 1)
    local sample_n=1
    if [[ "$spoof" == *"/"* ]]; then
        sample_n="${CIDR_SAMPLE_MAX:-3}"
        if ! [[ "$sample_n" =~ ^[0-9]+$ ]]; then sample_n=3; fi
    fi
    local PKTS
    PKTS="$(raw_pkts_for_n "$sample_n")"
    RAW_PKTS_PER_IP="$PKTS"
    local thresh="${CIDR_FAST_THRESHOLD:-20}"
    echo -e "${CYAN}--- Phase 2a: RAW spoof via scapy (bypass iptables/Docker) ---${NC}"
    echo -e "${BLUE}[*] Covering $sample_n IP(s) from $spoof, $PKTS pkt(s)/IP (batched, 1 SSH)${NC}"
    ensure_scapy_remote || true
    if [ "$sample_n" -le "$thresh" ]; then
        # ---- SMALL sample: expand list, ONE ssh for scapy + ONE ssh for nping ----
        local -a spoof_list
        mapfile -t spoof_list < <(expand_spoof_ips "$spoof" "$sample_n")
        if [ "${#spoof_list[@]}" -eq 0 ]; then
            spoof_list=("$spoof")
        fi
        if [[ "$spoof" == *"/"* ]]; then
            echo -e "${BLUE}[*] CIDR $spoof -> RAW spoofing sample IPs (${#spoof_list[@]}): ${spoof_list[*]:0:10}$([ "${#spoof_list[@]}" -gt 10 ] && echo " ...")${NC}"
        fi
        local ip_args
        ip_args="$(printf " '%s'" "${spoof_list[@]}")"
        ssh_foreign "
            ${rp}python3 -u - '$target' '$PKTS' $ip_args <<'PYEOF' 2>&1
import sys
try:
    from scapy.all import IP, ICMP, send
    dst = sys.argv[1]
    per = int(sys.argv[2])
    srcs = sys.argv[3:]
    ok = 0
    for src in srcs:
        pkt = IP(src=src, dst=dst)/ICMP()
        send(pkt, count=per, inter=0.2, verbose=False)
        print('RAW_SPOOF_SENT (scapy src=%s x%d)' % (src, per))
        ok += 1
    print('RAW_SPOOF_BATCH_DONE scapy=%d' % ok)
except Exception as e:
    print('RAW_SPOOF_FAIL (scapy): %s' % e)
PYEOF
        " || true
        echo -e "${CYAN}--- Phase 2b: RAW spoof via nping (fallback, captures replies as proof) ---${NC}"
        rm -f "$nping_log"
        ssh_foreign "
            command -v nping >/dev/null 2>&1 || { echo 'nping missing, skipping Phase 2b'; exit 0; }
            for src in ${spoof_list[*]}; do
                ${rp}nping --icmp -c $PKTS --delay 200ms --source-ip \"\$src\" '$target' 2>&1
                echo \"RAW_SPOOF_SENT (nping src=\$src)\"
            done
        " >> "$nping_log" 2>&1 || true
        tail -30 "$nping_log" 2>/dev/null || true
    else
        # ---- LARGE / FULL-RANGE mode: single SSH, python enumerates CIDR internally ----
        # No 65k-line bash array, no per-IP SSH. nping runs on rep IP only for proof
        # (per-IP nping on 65k hosts would take hours; tcpdump still proves per-IP arrival).
        local rep
        rep="$(spoof_rule_ip)"
        [ -n "$rep" ] || rep="$spoof"
        echo -e "${BLUE}[*] FULL-RANGE fast mode: scapy covers $sample_n IPs in ONE remote python (inter=0, no per-IP SSH).${NC}"
        echo -e "${BLUE}[*] nping proof runs on rep IP $rep only (1 SSH). Per-IP proof comes from tcpdump.${NC}"
        ssh_foreign "
            ${rp}python3 -u - '$target' '$spoof' '$sample_n' '$PKTS' <<'PYEOF' 2>&1
import sys, ipaddress
try:
    from scapy.all import IP, ICMP, send
    dst = sys.argv[1]
    cidr = sys.argv[2]
    want = int(sys.argv[3])
    per = int(sys.argv[4])
    net = ipaddress.ip_network(cidr, strict=False)
    total = net.num_addresses
    if total <= 2:
        srcs = [str(net.network_address)]
    else:
        usable = total - 2
        n = want if want < usable else usable
        base = int(net.network_address)
        # generator: no big list held longer than needed, progress every 2000
        done = 0
        for i in range(1, n + 1):
            src = str(ipaddress.ip_address(base + i))
            pkt = IP(src=src, dst=dst)/ICMP()
            send(pkt, count=per, inter=0, verbose=False)
            done += 1
            if done % 2000 == 0:
                print('RAW_PROGRESS scapy %d/%d' % (done, n))
        print('RAW_SPOOF_BATCH_DONE scapy=%d x%d cidr=%s' % (done, per, cidr))
        sys.exit(0)
    # single-IP CIDR edge (/32): fall through
    pkt = IP(src=str(net.network_address), dst=dst)/ICMP()
    send(pkt, count=per, inter=0, verbose=False)
    print('RAW_SPOOF_BATCH_DONE scapy=1')
except Exception as e:
    print('RAW_SPOOF_FAIL (scapy): %s' % e)
PYEOF
        " || true
        echo -e "${CYAN}--- Phase 2b: RAW spoof via nping (rep-IP proof only in full-range mode) ---${NC}"
        rm -f "$nping_log"
        ssh_foreign "
            command -v nping >/dev/null 2>&1 || { echo 'nping missing, skipping Phase 2b'; exit 0; }
            ${rp}nping --icmp -c $PKTS --delay 200ms --source-ip '$rep' '$target' 2>&1
            echo 'RAW_SPOOF_SENT (nping src=$rep)'
        " >> "$nping_log" 2>&1 || true
        tail -30 "$nping_log" 2>/dev/null || true
    fi
    check_nping_proof "$nping_log" "$spoof" || true
}

local_raw_spoof() {
    local target="$1"
    local spoof="$2"
    local nping_log="${3:-/dev/null}"
    local sample_n=1
    if [[ "$spoof" == *"/"* ]]; then
        sample_n="${CIDR_SAMPLE_MAX:-3}"
        if ! [[ "$sample_n" =~ ^[0-9]+$ ]]; then sample_n=3; fi
    fi
    local PKTS
    PKTS="$(raw_pkts_for_n "$sample_n")"
    RAW_PKTS_PER_IP="$PKTS"
    echo -e "${CYAN}--- Phase 2a: RAW spoof via scapy (bypass iptables) ---${NC}"
    echo -e "${BLUE}[*] Covering $sample_n IP(s) from $spoof, $PKTS pkt(s)/IP (batched, 1 python)${NC}"
    local _have_scapy=1
    if ! ensure_scapy_local; then
        echo -e "${RED}[!] scapy unavailable locally, trying nping...${NC}"
        _have_scapy=0
    fi
    local thresh="${CIDR_FAST_THRESHOLD:-20}"
    if [ "$sample_n" -le "$thresh" ]; then
        # ---- SMALL sample: one local python for all IPs + one nping loop ----
        local -a spoof_list
        mapfile -t spoof_list < <(expand_spoof_ips "$spoof" "$sample_n")
        if [ "${#spoof_list[@]}" -eq 0 ]; then
            spoof_list=("$spoof")
        fi
        if [[ "$spoof" == *"/"* ]]; then
            echo -e "${BLUE}[*] CIDR $spoof -> RAW spoofing sample IPs (${#spoof_list[@]}): ${spoof_list[*]:0:10}$([ "${#spoof_list[@]}" -gt 10 ] && echo " ...")${NC}"
        fi
        if [ "$_have_scapy" -eq 1 ]; then
            python3 -u - "$target" "$PKTS" "${spoof_list[@]}" <<'PYEOF' || true
import sys
try:
    from scapy.all import IP, ICMP, send
    dst = sys.argv[1]
    per = int(sys.argv[2])
    srcs = sys.argv[3:]
    ok = 0
    for src in srcs:
        pkt = IP(src=src, dst=dst)/ICMP()
        send(pkt, count=per, inter=0.2, verbose=False)
        print('RAW_SPOOF_SENT (scapy src=%s x%d)' % (src, per))
        ok += 1
    print('RAW_SPOOF_BATCH_DONE scapy=%d' % ok)
except Exception as e:
    print('RAW_SPOOF_FAIL (scapy): %s' % e)
PYEOF
        fi
        echo -e "${CYAN}--- Phase 2b: RAW spoof via nping (fallback, captures replies as proof) ---${NC}"
        rm -f "$nping_log"
        if command -v nping >/dev/null 2>&1; then
            local _src
            for _src in "${spoof_list[@]}"; do
                nping --icmp -c "$PKTS" --delay 200ms --source-ip "$_src" "$target" >> "$nping_log" 2>&1 || true
                echo "RAW_SPOOF_SENT (nping src=$_src)"
            done
            tail -30 "$nping_log"
            check_nping_proof "$nping_log" "$spoof" || true
        else
            echo "(nping missing locally, skipping)"
        fi
    else
        # ---- LARGE / FULL-RANGE mode: one local python enumerates CIDR, nping on rep IP only ----
        local rep
        rep="$(spoof_rule_ip)"
        [ -n "$rep" ] || rep="$spoof"
        if [[ "$spoof" == *"/"* ]]; then
            echo -e "${BLUE}[*] FULL-RANGE fast mode: scapy covers $sample_n IPs in ONE python (inter=0).${NC}"
        fi
        if [ "$_have_scapy" -eq 1 ]; then
            python3 -u - "$target" "$spoof" "$sample_n" "$PKTS" <<'PYEOF' || true
import sys, ipaddress
try:
    from scapy.all import IP, ICMP, send
    dst = sys.argv[1]
    cidr = sys.argv[2]
    want = int(sys.argv[3])
    per = int(sys.argv[4])
    net = ipaddress.ip_network(cidr, strict=False)
    total = net.num_addresses
    if total <= 2:
        pkt = IP(src=str(net.network_address), dst=dst)/ICMP()
        send(pkt, count=per, inter=0, verbose=False)
        print('RAW_SPOOF_BATCH_DONE scapy=1')
    else:
        usable = total - 2
        n = want if want < usable else usable
        base = int(net.network_address)
        done = 0
        for i in range(1, n + 1):
            src = str(ipaddress.ip_address(base + i))
            pkt = IP(src=src, dst=dst)/ICMP()
            send(pkt, count=per, inter=0, verbose=False)
            done += 1
            if done % 2000 == 0:
                print('RAW_PROGRESS scapy %d/%d' % (done, n))
        print('RAW_SPOOF_BATCH_DONE scapy=%d x%d cidr=%s' % (done, per, cidr))
except Exception as e:
    print('RAW_SPOOF_FAIL (scapy): %s' % e)
PYEOF
        fi
        echo -e "${CYAN}--- Phase 2b: RAW spoof via nping (rep-IP proof only in full-range mode) ---${NC}"
        rm -f "$nping_log"
        if command -v nping >/dev/null 2>&1; then
            nping --icmp -c "$PKTS" --delay 200ms --source-ip "$rep" "$target" >> "$nping_log" 2>&1 || true
            echo "RAW_SPOOF_SENT (nping src=$rep)"
            tail -30 "$nping_log"
            check_nping_proof "$nping_log" "$spoof" || true
        else
            echo "(nping missing locally, skipping)"
        fi
    fi
}

direct_test() {
    echo
    echo "======================================"
    echo "   TEST 1: DIRECT (Iran -> Foreign)   "
    echo "======================================"
    echo "Testing if Iran allows outbound spoofed packets (Egress),"
    echo "and Foreign server receives them."
    echo

    local remote_rx_log="/tmp/foreign_rx_$$.log"
    rm -f "$remote_rx_log"

    local remote_prefix=""
    if [ "$FOREIGN_USER" != "root" ]; then
        remote_prefix="echo '$FOREIGN_PASS' | sudo -S "
    fi

    local _spoof_filter
    _spoof_filter="$(spoof_filter_expr)"
    echo -e "${YELLOW}[*] Starting tcpdump on Foreign server (listening for ICMP)...${NC}"
    echo -e "${BLUE}[*] Capture filter: icmp and ($_spoof_filter or src host $LOCAL_IP)${NC}"
    local _cap_to
    _cap_to="$(capture_timeout_for_n "${CIDR_SAMPLE_MAX:-1}")"
    echo -e "${BLUE}[*] Capture window: ${_cap_to}s (auto-sized for ${CIDR_SAMPLE_MAX:-1} IP(s))${NC}"
    sshpass -p "$FOREIGN_PASS" ssh -p "$FOREIGN_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$FOREIGN_USER@$FOREIGN_IP" \
        "${remote_prefix}timeout ${_cap_to} tcpdump -n -l -i any 'icmp and ($_spoof_filter or src host $LOCAL_IP)'" > "$remote_rx_log" 2>&1 &
    local remote_pid=$!

    if ! wait_for_tcpdump_ready "$remote_rx_log"; then
        echo -e "${RED}[!] Remote tcpdump did not become ready. Log:${NC}"
        cat "$remote_rx_log" 2>/dev/null || true
        kill $remote_pid 2>/dev/null || true
        direct_res="ERROR (tcpdump not ready)"
        direct_spoof_cnt=0; direct_new_real=0; direct_nping_proven=0; direct_raw_ran=0
        DIRECT_RX_LOG="$remote_rx_log"; DIRECT_NPING_LOG=""
        return 0
    fi
    echo -e "${GREEN}[+] Remote tcpdump is listening.${NC}"

    echo
    echo -e "${CYAN}--- Phase 0: Baseline (NO spoof, expect REAL IP) ---${NC}"
    ping -c 2 -W 1 "$FOREIGN_IP" || true
    sleep 2

    local base_real=0
    base_real=$(grep -c -F "${LOCAL_IP} >" "$remote_rx_log" 2>/dev/null || true)
    base_real="${base_real:-0}"
    echo -e "${BLUE}[*] Baseline packets from REAL IP seen so far: $base_real${NC}"
    if [ "$base_real" -eq 0 ]; then
        echo -e "${RED}[!] WARNING: Baseline FAILED - Foreign saw nothing even WITHOUT spoof.${NC}"
        echo -e "${RED}    This means tcpdump/filter/connectivity is broken, NOT filtering.${NC}"
        echo -e "${RED}    Check: Foreign firewall, ICMP blocked, wrong LOCAL_IP.${NC}"
        echo "--- Remote log so far ---"
        cat "$remote_rx_log" || true
    else
        echo -e "${GREEN}[+] Baseline OK: path Iran -> Foreign works, capture works.${NC}"
    fi

    echo
    echo -e "${CYAN}--- Phase 1: Spoofed ($LOCAL_IP -> $SPOOF_IP) ---${NC}"
    if [ -n "${SPOOF_CIDR:-}" ]; then
        echo -e "${BLUE}[*] CIDR mode: capture matches whole $SPOOF_CIDR, SNAT/scapy/nping use $(spoof_rule_ip) (first usable host)${NC}"
    fi
    echo -e "${YELLOW}[*] Flushing conntrack for $FOREIGN_IP (stale entries bypass NAT table)...${NC}"
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -D -d "$FOREIGN_IP" 2>/dev/null || echo "(nothing to flush)"
    else
        echo "(no conntrack tool, skipping)"
    fi
    echo -e "${YELLOW}[*] Installing temporary SNAT rule on Iran server...${NC}"
    DST_IP="$FOREIGN_IP"
    iptables -t nat -I POSTROUTING 1 \
        -p icmp \
        -d "$FOREIGN_IP" \
        -j SNAT \
        --to-source "$(spoof_rule_ip)"
    RULE_ADDED=1
    echo -e "${BLUE}[*] Local NAT table (should show SNAT at top):${NC}"
    iptables -t nat -L POSTROUTING -n -v --line-numbers | head -10
    local snat_before=0
    snat_before=$(iptables -t nat -L POSTROUTING -n -v --line-numbers 2>/dev/null | awk '$1==1 {print $2; exit}')
    snat_before="${snat_before:-0}"

    echo
    echo -e "${YELLOW}[*] Sending 5 SPOOFED ping packets to $FOREIGN_IP...${NC}"
    echo -e "${BLUE}(Expect 100% loss here - replies go to $SPOOF_IP. If you get replies, SNAT did NOT apply.)${NC}"
    ping -c 5 -W 1 "$FOREIGN_IP" || true

    echo
    local snat_after=0
    snat_after=$(iptables -t nat -L POSTROUTING -n -v --line-numbers 2>/dev/null | awk '$1==1 {print $2; exit}')
    snat_after="${snat_after:-0}"
    echo -e "${BLUE}[*] SNAT counter before=$snat_before after=$snat_after (delta>0 proves rule matched; NAT counts only 1st pkt per connection)${NC}"
    iptables -t nat -L POSTROUTING -n -v --line-numbers | head -10

    echo -e "${YELLOW}[*] Removing local SNAT rule...${NC}"
    iptables -t nat -D POSTROUTING \
        -p icmp \
        -d "$FOREIGN_IP" \
        -j SNAT \
        --to-source "$(spoof_rule_ip)" 2>/dev/null || true
    (command -v iptables-legacy >/dev/null 2>&1 && iptables-legacy -t nat -D POSTROUTING -p icmp -d "$FOREIGN_IP" -j SNAT --to-source "$(spoof_rule_ip)" 2>/dev/null) || true
    RULE_ADDED=0

    local interim_spoof=0
    interim_spoof=$(count_spoof_packets "$remote_rx_log" 2>/dev/null || true)
    interim_spoof="${interim_spoof:-0}"
    local local_nping_log="/tmp/iran_nping_$$.log"
    direct_raw_ran=0
    rm -f "$local_nping_log" 2>/dev/null || true
    touch "$local_nping_log" 2>/dev/null || true
    if [ "$interim_spoof" -eq 0 ]; then
        echo
        echo -e "${YELLOW}[*] No spoofed packets via SNAT so far - trying RAW socket spoof (bypass iptables/Docker)...${NC}"
        local_raw_spoof "$FOREIGN_IP" "$SPOOF_IP" "$local_nping_log"
        direct_raw_ran=1
        sleep 3
    else
        echo -e "${GREEN}[+] SNAT spoof packets already seen, skipping RAW fallback.${NC}"
    fi

    echo -e "${YELLOW}[*] Waiting for capture on Foreign server to complete...${NC}"
    sleep 2
    kill $remote_pid 2>/dev/null || true
    wait $remote_pid 2>/dev/null || true

    echo
    echo -e "${BLUE}[*] Packets captured on Foreign server:${NC}"
    if [ -s "$remote_rx_log" ]; then
        grep " > " "$remote_rx_log" || cat "$remote_rx_log"
    else
        echo "(No packets captured)"
        cat "$remote_rx_log" || true
    fi
    echo

    local spoof_cnt=0 total_real=0
    spoof_cnt=$(count_spoof_packets "$remote_rx_log" 2>/dev/null || true)
    total_real=$(grep -c -F "${LOCAL_IP} >" "$remote_rx_log" 2>/dev/null || true)
    spoof_cnt="${spoof_cnt:-0}"
    total_real="${total_real:-0}"
    local new_real=$((total_real - base_real))

    echo -e "${BLUE}[*] Baseline REAL count: $base_real, Total REAL now: $total_real (new: $new_real), SPOOFED count: $spoof_cnt (filter: $(spoof_filter_expr))${NC}"
    echo

    local nping_proven=0
    if [ -f "$local_nping_log" ] && grep -q "SPOOF_PROVEN_BY_REPLY" "$local_nping_log" 2>/dev/null; then
        nping_proven=1
    fi

    if [ "$spoof_cnt" -gt 0 ]; then
        echo -e "${GREEN}>>> DIRECT TEST RESULT: SUCCESS (SPOOFED) <<<${NC}"
        echo -e "${GREEN}Foreign server received $spoof_cnt packets with spoofed source: $SPOOF_IP (matched via $(spoof_filter_expr))${NC}"
        echo -e "${GREEN}Iran egress allows IP spoofing (No BCP 38 filtering).${NC}"
        direct_res="SUCCESS (SPOOFED)"
    elif [ "$nping_proven" -eq 1 ]; then
        echo -e "${GREEN}>>> DIRECT TEST RESULT: SUCCESS (SPOOFED, proven by nping reply) <<<${NC}"
        echo -e "${GREEN}Foreign tcpdump missed it but Iran nping RCVD Echo replies to spoofed src -> packet ARRIVED.${NC}"
        direct_res="SUCCESS (nping reply)"
    elif [ "$new_real" -gt 0 ]; then
        echo -e "${YELLOW}>>> DIRECT TEST RESULT: FAILED (REAL IP LEAKED) <<<${NC}"
        echo -e "${YELLOW}Foreign saw $new_real NEW packets with REAL IP ($LOCAL_IP) during spoof phases.${NC}"
        echo -e "${YELLOW}Check: before/after counter delta, RAW_SPOOF_SENT lines above.${NC}"
        direct_res="FAILED (REAL IP)"
    else
        echo -e "${RED}>>> DIRECT TEST RESULT: BLOCKED / DROPPED <<<${NC}"
        echo -e "${RED}Baseline worked ($base_real pkts) but 0 spoofed packets arrived.${NC}"
        echo -e "${RED}Iran ISP or transit drops spoofed packets (BCP 38 egress filtering).${NC}"
        echo -e "${RED}This is EXPECTED on most Iranian providers (MCI/MTN/TCI filter spoof).${NC}"
        direct_res="BLOCKED / DROPPED"
    fi

    # Preserve for CSV builder (write_csv_results cleans up later respecting DEBUG)
    direct_spoof_cnt="$spoof_cnt"
    direct_new_real="$new_real"
    direct_nping_proven="$nping_proven"
    DIRECT_RX_LOG="$remote_rx_log"
    DIRECT_NPING_LOG="$local_nping_log"
}

reverse_test() {
    echo
    echo "======================================"
    echo "   TEST 2: REVERSE (Foreign -> Iran)  "
    echo "======================================"
    echo "Testing if Foreign server can send spoofed packets (Egress),"
    echo "and Iran server receives them (Ingress)."
    echo

    local local_rx_log="/tmp/iran_rx_$$.log"
    rm -f "$local_rx_log"

    local _spoof_filter
    _spoof_filter="$(spoof_filter_expr)"
    echo -e "${YELLOW}[*] Starting local tcpdump on Iran server (listening for ICMP)...${NC}"
    echo -e "${BLUE}[*] Capture filter: icmp and ($_spoof_filter or src host $FOREIGN_IP)${NC}"
    local _cap_to
    _cap_to="$(capture_timeout_for_n "${CIDR_SAMPLE_MAX:-1}")"
    echo -e "${BLUE}[*] Capture window: ${_cap_to}s (auto-sized for ${CIDR_SAMPLE_MAX:-1} IP(s))${NC}"
    timeout "$_cap_to" tcpdump -n -l -i any "icmp and ($_spoof_filter or src host $FOREIGN_IP)" > "$local_rx_log" 2>&1 &
    local local_pid=$!

    if ! wait_for_tcpdump_ready "$local_rx_log"; then
        echo -e "${RED}[!] Local tcpdump did not become ready. Log:${NC}"
        cat "$local_rx_log" 2>/dev/null || true
        kill $local_pid 2>/dev/null || true
        reverse_res="ERROR (tcpdump not ready)"
        reverse_spoof_cnt=0; reverse_new_real=0; reverse_nping_proven=0; reverse_raw_ran=0
        REVERSE_RX_LOG="$local_rx_log"; REVERSE_NPING_LOG=""
        return 0
    fi
    echo -e "${GREEN}[+] Local tcpdump is listening.${NC}"

    local remote_prefix=""
    if [ "$FOREIGN_USER" != "root" ]; then
        remote_prefix="echo '$FOREIGN_PASS' | sudo -S "
    fi

    echo
    echo -e "${CYAN}--- Phase 0: Baseline (NO spoof, expect REAL Foreign IP) ---${NC}"
    ssh_foreign "ping -c 2 -W 1 '$LOCAL_IP'" || true
    sleep 2

    local base_real=0
    base_real=$(grep -c -F "${FOREIGN_IP} >" "$local_rx_log" 2>/dev/null || true)
    base_real="${base_real:-0}"
    echo -e "${BLUE}[*] Baseline packets from REAL Foreign IP seen so far: $base_real${NC}"
    if [ "$base_real" -eq 0 ]; then
        echo -e "${RED}[!] WARNING: Baseline FAILED - Iran saw nothing even WITHOUT spoof.${NC}"
        echo -e "${RED}    Capture/filter/connectivity broken. Check LOCAL_IP value and firewall.${NC}"
        echo "--- Local log so far ---"
        cat "$local_rx_log" || true
    else
        echo -e "${GREEN}[+] Baseline OK: path Foreign -> Iran works, capture works.${NC}"
    fi

    echo
    echo -e "${CYAN}--- Phase 1: Spoofed ($FOREIGN_IP -> $SPOOF_IP) ---${NC}"
    local _snat_ip
    _snat_ip="$(spoof_rule_ip)"
    if [ -n "${SPOOF_CIDR:-}" ]; then
        echo -e "${BLUE}[*] CIDR mode: capture matches whole $SPOOF_CIDR, SNAT/scapy/nping use $_snat_ip (first usable host)${NC}"
    fi
    echo -e "${YELLOW}[*] Triggering Foreign server to SNAT and ping Iran server ($LOCAL_IP)...${NC}"
    echo -e "${BLUE}(Expect 100% loss on Foreign side - replies go to $SPOOF_IP.)${NC}"
    REMOTE_RULE_ADDED=1
    ssh_foreign "
        echo '[*] Flushing conntrack for $LOCAL_IP on Foreign (stale entries bypass NAT)...'
        (command -v conntrack >/dev/null 2>&1 && ${remote_prefix}conntrack -D -d '$LOCAL_IP' 2>&1 | head -5) || echo '(no conntrack tool, skipping)'
        ${remote_prefix}iptables -t nat -I POSTROUTING 1 -p icmp -d '$LOCAL_IP' -j SNAT --to-source '$_snat_ip'
        echo \"ADD_RC=\$?\"
        ${remote_prefix}iptables -t nat -L POSTROUTING -n -v --line-numbers | head -10
        SNAT_BEFORE=\$(${remote_prefix}iptables -t nat -L POSTROUTING -n -v --line-numbers 2>/dev/null | awk '\$1==1 {print \$2; exit}')
        echo \"SNAT_BEFORE=\$SNAT_BEFORE\"
        ping -c 5 -W 1 '$LOCAL_IP' || true
        echo '--- counters after ping (delta>0 proves match; NAT counts only 1st pkt/connection) ---'
        ${remote_prefix}iptables -t nat -L POSTROUTING -n -v --line-numbers | head -10
        SNAT_AFTER=\$(${remote_prefix}iptables -t nat -L POSTROUTING -n -v --line-numbers 2>/dev/null | awk '\$1==1 {print \$2; exit}')
        echo \"SNAT_AFTER=\$SNAT_AFTER\"
        if [ \"\$SNAT_AFTER\" = \"\$SNAT_BEFORE\" ] || [ -z \"\$SNAT_AFTER\" ]; then
            echo '[!] SNAT rule never matched - trying FALLBACK: broad rule without -d (policy-routing/tunnel may change dst seen by netfilter)...'
            ${remote_prefix}iptables -t nat -I POSTROUTING 1 -p icmp -j SNAT --to-source '$_snat_ip'
            echo \"FALLBACK_ADD_RC=\$?\"
            ${remote_prefix}iptables -t nat -L POSTROUTING -n -v --line-numbers | head -8
            (command -v conntrack >/dev/null 2>&1 && ${remote_prefix}conntrack -D -d '$LOCAL_IP' 2>&1 | head -3) || true
            ping -c 5 -W 1 '$LOCAL_IP' || true
            echo '--- counters after fallback ping ---'
            ${remote_prefix}iptables -t nat -L POSTROUTING -n -v --line-numbers | head -8
            ${remote_prefix}iptables -t nat -D POSTROUTING -p icmp -j SNAT --to-source '$_snat_ip' 2>/dev/null || true
            echo \"FALLBACK_DEL_RC=\$?\"
        fi
        ${remote_prefix}iptables -t nat -D POSTROUTING -p icmp -d '$LOCAL_IP' -j SNAT --to-source '$_snat_ip' || true
        echo \"DEL_RC=\$?\"
    "
    REMOTE_RULE_ADDED=0
    (command -v iptables-legacy >/dev/null 2>&1 && ssh_foreign "${remote_prefix}iptables-legacy -t nat -D POSTROUTING -p icmp -d '$LOCAL_IP' -j SNAT --to-source '$_snat_ip' 2>/dev/null || true") || true
    ssh_foreign "${remote_prefix}iptables -t nat -D POSTROUTING -p icmp -j SNAT --to-source '$_snat_ip' 2>/dev/null || true" || true

    echo
    echo -e "${YELLOW}[*] SNAT via iptables is shadowed on this box (Docker/pg NAT chains win) - trying nft-native SNAT at priority 90...${NC}"
    remote_nft_spoof "$LOCAL_IP" "$SPOOF_IP"
    sleep 2

    local interim_spoof=0
    interim_spoof=$(count_spoof_packets "$local_rx_log" 2>/dev/null || true)
    interim_spoof="${interim_spoof:-0}"
    local foreign_nping_log="/tmp/foreign_nping_$$.log"
    reverse_raw_ran=0
    rm -f "$foreign_nping_log" 2>/dev/null || true
    touch "$foreign_nping_log" 2>/dev/null || true
    if [ "$interim_spoof" -eq 0 ]; then
        echo
        echo -e "${YELLOW}[*] No spoofed packets via SNAT/nft - adding MASQUERADE exemption for $SPOOF_IP so RAW packets leave intact...${NC}"
        remote_nat_exempt "$SPOOF_IP"
        remote_raw_spoof "$LOCAL_IP" "$SPOOF_IP" "$foreign_nping_log"
        reverse_raw_ran=1
        sleep 3
        remote_nat_unexempt "$SPOOF_IP"
    else
        echo -e "${GREEN}[+] Spoofed packets already seen, skipping RAW fallback.${NC}"
    fi

    echo -e "${YELLOW}[*] Stopping local capture...${NC}"
    sleep 2
    kill $local_pid 2>/dev/null || true
    wait $local_pid 2>/dev/null || true

    echo
    echo -e "${BLUE}[*] Packets captured on Iran server:${NC}"
    if [ -s "$local_rx_log" ]; then
        grep " > " "$local_rx_log" || cat "$local_rx_log"
    else
        echo "(No packets captured)"
        cat "$local_rx_log" || true
    fi
    echo

    local spoof_cnt=0 total_real=0
    spoof_cnt=$(count_spoof_packets "$local_rx_log" 2>/dev/null || true)
    total_real=$(grep -c -F "${FOREIGN_IP} >" "$local_rx_log" 2>/dev/null || true)
    spoof_cnt="${spoof_cnt:-0}"
    total_real="${total_real:-0}"
    local new_real=$((total_real - base_real))

    echo -e "${BLUE}[*] Baseline REAL count: $base_real, Total REAL now: $total_real (new: $new_real), SPOOFED count: $spoof_cnt (filter: $(spoof_filter_expr))${NC}"
    echo

    local nping_proven=0
    if [ -f "$foreign_nping_log" ] && grep -q "SPOOF_PROVEN_BY_REPLY" "$foreign_nping_log" 2>/dev/null; then
        nping_proven=1
    fi

    local nping_id="" rewritten=0
    nping_id=$(grep -m1 -o 'id=[0-9][0-9]*' "$foreign_nping_log" 2>/dev/null | head -1 | cut -d= -f2 || true)
    if [ -n "${nping_id:-}" ]; then
        rewritten=$(grep -F "${FOREIGN_IP} >" "$local_rx_log" 2>/dev/null | grep -c "id ${nping_id}," || true)
        rewritten="${rewritten:-0}"
        echo -e "${BLUE}[*] Cross-check: nping raw id=$nping_id arrived on wire with REAL src $rewritten time(s).${NC}"
    fi

    if [ "$spoof_cnt" -gt 0 ]; then
        echo -e "${GREEN}>>> REVERSE TEST RESULT: SUCCESS (SPOOFED) <<<${NC}"
        echo -e "${GREEN}Iran server received $spoof_cnt packets with spoofed source: $SPOOF_IP${NC}"
        echo -e "${GREEN}Foreign egress allows spoofing, and Iran ingress does not drop it.${NC}"
        reverse_res="SUCCESS (SPOOFED)"
    elif [ "$nping_proven" -eq 1 ] && [ "$rewritten" -eq 0 ]; then
        echo -e "${GREEN}>>> REVERSE TEST RESULT: SUCCESS (SPOOFED, proven by nping reply) <<<${NC}"
        echo -e "${GREEN}Foreign nping RCVD Echo replies from $LOCAL_IP to spoofed src $SPOOF_IP.${NC}"
        echo -e "${GREEN}A reply can only exist if the spoofed request ARRIVED -> egress spoofing WORKS.${NC}"
        reverse_res="SUCCESS (nping reply)"
    elif [ "$nping_proven" -eq 1 ] && [ "$rewritten" -gt 0 ]; then
        echo -e "${YELLOW}>>> REVERSE TEST RESULT: REWRITTEN BY EGRESS NAT (not datacenter filtering) <<<${NC}"
        echo -e "${YELLOW}nping got replies, BUT Iran tcpdump shows the same packets (id $nping_id) arriving with REAL src.${NC}"
        echo -e "${YELLOW}Foreign MASQUERADE rewrote the spoofed source on egress; conntrack un-NATed the replies (false positive).${NC}"
        echo -e "${YELLOW}Check Phase 1c exemption result above - it bypasses local NAT for the real answer.${NC}"
        reverse_res="REWRITTEN BY EGRESS NAT"
    elif [ "$new_real" -gt 0 ]; then
        echo -e "${YELLOW}>>> REVERSE TEST RESULT: FAILED (REAL IP LEAKED) <<<${NC}"
        echo -e "${YELLOW}Iran saw $new_real NEW packets with REAL Foreign IP during spoof phases.${NC}"
        echo -e "${YELLOW}iptables SNAT shadowed by Docker/pg NAT chains - check Phase 1b nft result + RAW lines above.${NC}"
        echo -e "${YELLOW}This is a LOCAL NAT-ordering problem, NOT datacenter filtering.${NC}"
        reverse_res="FAILED (REAL IP)"
    else
        echo -e "${RED}>>> REVERSE TEST RESULT: BLOCKED / DROPPED <<<${NC}"
        echo -e "${RED}Baseline worked ($base_real pkts) but 0 spoofed packets arrived.${NC}"
        echo -e "${RED}Foreign datacenter or transit drops spoofed egress packets.${NC}"
        reverse_res="BLOCKED / DROPPED"
    fi

    # Preserve for CSV builder (write_csv_results cleans up later respecting DEBUG)
    reverse_spoof_cnt="$spoof_cnt"
    reverse_new_real="$new_real"
    reverse_nping_proven="$nping_proven"
    REVERSE_RX_LOG="$local_rx_log"
    REVERSE_NPING_LOG="$foreign_nping_log"
}

print_summary() {
    local d_res="$1"
    local r_res="$2"

    echo
    echo "======================================================"
    echo "                   TEST SUMMARY"
    echo "======================================================"
    printf "%-30s | %-20s\n" "TEST DIRECTION" "RESULT"
    echo "------------------------------------------------------"
    printf "%-30s | %-20s\n" "Direct  (Iran -> Foreign)" "$d_res"
    printf "%-30s | %-20s\n" "Reverse (Foreign -> Iran)" "$r_res"
    echo "======================================================"
    echo
}

auto_test() {
    check_sshpass || return 1

    echo
    echo "======================================"
    echo "   AUTOMATED IRAN <-> FOREIGN TEST   "
    echo "======================================"
    echo "This test connects to your Foreign server via SSH and"
    echo "tests IP spoofing in both directions automatically."
    echo

    FOREIGN_IP=""
    while [ -z "$FOREIGN_IP" ]; do
        read -rp "Foreign Server IP: " FOREIGN_IP
        FOREIGN_IP="$(echo "$FOREIGN_IP" | tr -d '[:space:]')"
    done

    read -rp "Foreign SSH Port [22]: " FOREIGN_PORT
    FOREIGN_PORT="${FOREIGN_PORT:-22}"
    FOREIGN_PORT="$(echo "$FOREIGN_PORT" | tr -d '[:space:]')"

    read -rp "Foreign SSH Username [root]: " FOREIGN_USER
    FOREIGN_USER="${FOREIGN_USER:-root}"
    FOREIGN_USER="$(echo "$FOREIGN_USER" | tr -d '[:space:]')"

    read -s -rp "Foreign SSH Password: " FOREIGN_PASS
    echo
    if [ -z "$FOREIGN_PASS" ]; then
        echo -e "${RED}[!] Password cannot be empty.${NC}"
        return 1
    fi

    local detected_local_ip
    detected_local_ip=$(ip route get "$FOREIGN_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [ -z "$detected_local_ip" ]; then
        detected_local_ip=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
    fi

    echo
    read -rp "Iran Server Real IP [$detected_local_ip]: " LOCAL_IP
    LOCAL_IP="${LOCAL_IP:-$detected_local_ip}"
    LOCAL_IP="$(echo "$LOCAL_IP" | tr -d '[:space:]')"

    local _spoof_in=""
    read -rp "Spoof Source IP/CIDR or file (one IP/CIDR per line) [1.1.1.1, 10.99.0.0/24, ./list.txt or @./list.txt]: " _spoof_in
    _spoof_in="${_spoof_in:-1.1.1.1}"
    _spoof_in="$(strip_spoof_arg "$_spoof_in")"
    # Detect file input: '@path' prefix or an existing file path
    local _spoof_file="" _from_file=0
    if [[ "$_spoof_in" == @* ]]; then
        _spoof_file="${_spoof_in#@}"
        _from_file=1
    elif [ -f "$_spoof_in" ]; then
        _spoof_file="$_spoof_in"
        _from_file=1
    fi
    local -a SPOOF_TARGETS=()
    local GLOBAL_CIDR_N="3"
    if [ "$_from_file" -eq 1 ]; then
        if [ -z "$_spoof_file" ] || [ ! -f "$_spoof_file" ]; then
            echo -e "${RED}[!] Spoof list file not found: ${_spoof_file:-<empty>}${NC}"
            echo -e "${BLUE}    Tip: use @/path/to/file or a plain path. One IP or CIDR per line, '#' comments allowed.${NC}"
            return 1
        fi
        mapfile -t SPOOF_TARGETS < <(load_spoof_list_file "$_spoof_file")
        if [ "${#SPOOF_TARGETS[@]}" -eq 0 ]; then
            echo -e "${RED}[!] No valid entries in file: $_spoof_file${NC}"
            return 1
        fi
        echo -e "${GREEN}[+] Loaded ${#SPOOF_TARGETS[@]} spoof target(s) from file: $_spoof_file${NC}"
        for _e in "${SPOOF_TARGETS[@]:0:5}"; do echo -e "${BLUE}    - $_e${NC}"; done
        if [ "${#SPOOF_TARGETS[@]}" -gt 5 ]; then
            echo -e "${BLUE}    ... (+$(( ${#SPOOF_TARGETS[@]} - 5 )) more)${NC}"
        fi
        # Validate each entry now (fail fast on bad lines, but keep good ones)
        local -a _valid=()
        local _bad=0
        for _e in "${SPOOF_TARGETS[@]}"; do
            SPOOF_CIDR=""; SPOOF_REP_IP=""; SPOOF_FILTER=""
            if normalize_spoof_input "$_e" 2>/dev/null; then
                _valid+=("$_e")
            else
                echo -e "${YELLOW}[!] Skipping invalid entry: $_e${NC}"
                _bad=$((_bad + 1))
            fi
        done
        SPOOF_TARGETS=("${_valid[@]}")
        if [ "${#SPOOF_TARGETS[@]}" -eq 0 ]; then
            echo -e "${RED}[!] All entries invalid. Nothing to test.${NC}"
            return 1
        fi
        [ "$_bad" -gt 0 ] && echo -e "${YELLOW}[*] Continuing with ${#SPOOF_TARGETS[@]} valid target(s).${NC}"
        SPOOF_CIDR=""; SPOOF_REP_IP=""; SPOOF_FILTER=""
    else
        SPOOF_CIDR=""; SPOOF_REP_IP=""; SPOOF_FILTER=""
        if ! normalize_spoof_input "$_spoof_in"; then
            echo -e "${RED}[!] Invalid spoof IP/CIDR. Use single IPv4 (1.1.1.1), CIDR (10.99.0.0/24), or a file path.${NC}"
            return 1
        fi
        SPOOF_TARGETS=("$_spoof_in")
    fi
    CIDR_SAMPLE_MAX=3
    RAW_PKTS_PER_IP=5
    # Do any targets need CIDR sampling?
    local _need_cidr=0
    for _e in "${SPOOF_TARGETS[@]}"; do
        if [[ "$_e" == *"/"* ]]; then _need_cidr=1; break; fi
    done
    if [ "$_need_cidr" -eq 1 ]; then
        if [ "${#SPOOF_TARGETS[@]}" -eq 1 ] && [ "$_from_file" -eq 0 ]; then
            local _one="${SPOOF_TARGETS[0]}"
            echo -e "${BLUE}[*] CIDR mode: will match ${_one} in capture; SNAT/raw use $(spoof_rule_ip) (+ samples).${NC}"
            local _host_total _n_in
            _host_total="$(cidr_host_count "$_one" 2>/dev/null || echo 0)"
            _host_total="${_host_total:-0}"
            echo -e "${BLUE}[*] CIDR $_one contains ~${_host_total} usable host(s).${NC}"
            echo -e "${BLUE}[*] Full range is supported: fast mode batches all IPs in 1 SSH (1-2 pkts/IP).${NC}"
            echo -e "${BLUE}    e.g. /24 all (254 IPs) ~= 10-20s extra; /16 all (65k) ~= a few minutes extra.${NC}"
            read -rp "How many sample IPs to test from CIDR? [3, N, or 'all']: " _n_in
            _n_in="$(echo "${_n_in:-3}" | tr -d '[:space:]')"
            if [[ "$_n_in" =~ ^[Aa][Ll][Ll]$ ]]; then
                GLOBAL_CIDR_N="ALL"
                if [ "$_host_total" -gt 0 ] 2>/dev/null; then
                    CIDR_SAMPLE_MAX="$_host_total"
                else
                    CIDR_SAMPLE_MAX=3
                fi
            elif [[ "$_n_in" =~ ^[0-9]+$ ]] && [ "$_n_in" -ge 1 ] 2>/dev/null; then
                GLOBAL_CIDR_N="$_n_in"
                CIDR_SAMPLE_MAX="$_n_in"
                if [ "$_host_total" -gt 0 ] 2>/dev/null && [ "$CIDR_SAMPLE_MAX" -gt "$_host_total" ] 2>/dev/null; then
                    CIDR_SAMPLE_MAX="$_host_total"
                fi
            else
                GLOBAL_CIDR_N="3"
                CIDR_SAMPLE_MAX=3
            fi
            _est_pkts="$(raw_pkts_for_n "$CIDR_SAMPLE_MAX")"
            echo -e "${BLUE}[*] Will test $CIDR_SAMPLE_MAX sample IP(s) from $_one (${_est_pkts} pkt(s)/IP via scapy + ${_est_pkts} via nping-proof path).${NC}"
        else
            # Batch/file mode: ask once, applies to every CIDR in the list
            local _cidr_n=0
            for _e in "${SPOOF_TARGETS[@]}"; do
                [[ "$_e" == *"/"* ]] && _cidr_n=$((_cidr_n + 1))
            done
            echo -e "${BLUE}[*] ${_cidr_n} CIDR target(s) in list. One setting applies to all CIDRs.${NC}"
            echo -e "${BLUE}[*] Full range is supported: fast mode batches all IPs in 1 SSH (1-2 pkts/IP).${NC}"
            local _n_in
            read -rp "How many sample IPs per CIDR? [3, N, or 'all']: " _n_in
            _n_in="$(echo "${_n_in:-3}" | tr -d '[:space:]')"
            if [[ "$_n_in" =~ ^[Aa][Ll][Ll]$ ]]; then
                GLOBAL_CIDR_N="ALL"
            elif [[ "$_n_in" =~ ^[0-9]+$ ]] && [ "$_n_in" -ge 1 ] 2>/dev/null; then
                GLOBAL_CIDR_N="$_n_in"
            else
                GLOBAL_CIDR_N="3"
            fi
            _est_pkts="$(raw_pkts_for_n "${GLOBAL_CIDR_N:-3}")"
            [ "$GLOBAL_CIDR_N" = "ALL" ] && _est_pkts="$(raw_pkts_for_n 1000)"
            echo -e "${BLUE}[*] Per-CIDR samples: $GLOBAL_CIDR_N (~${_est_pkts} pkt(s)/IP via scapy + ${_est_pkts} via nping-proof path; 'all' resolves per-CIDR).${NC}"
            CIDR_SAMPLE_MAX=3
        fi
    else
        CIDR_SAMPLE_MAX=1
        GLOBAL_CIDR_N="1"
    fi

    echo
    echo "Select test direction:"
    echo "  1) Both directions (Direct + Reverse) [All possible ways]"
    echo "  2) Direct only (Iran -> Foreign)"
    echo "  3) Reverse only (Foreign -> Iran)"
    read -rp "Select [1-3, default 1]: " TEST_DIR
    TEST_DIR="${TEST_DIR:-1}"

    echo
    read -rp "Enable DEBUG mode (full trace + diagnostics bundle to send for analysis)? [y/N]: " DBG_ASK
    case "$DBG_ASK" in
        y|Y|yes|YES) enable_debug ;;
    esac

    echo
    echo "--------------------------------------"
    echo "Iran Server IP   : $LOCAL_IP"
    echo "Foreign Server IP: $FOREIGN_IP"
    echo "Foreign SSH User : $FOREIGN_USER"
    echo "Foreign SSH Port : $FOREIGN_PORT"
    if [ "${#SPOOF_TARGETS[@]}" -eq 1 ]; then
        echo "Spoofed IP Test  : ${SPOOF_TARGETS[0]}"
        if [[ "${SPOOF_TARGETS[0]}" == *"/"* ]]; then
            echo "Spoof SNAT/RAW IP: $(spoof_rule_ip) (first host)"
            echo "Spoof capture  : $(spoof_filter_expr)"
        fi
    else
        echo "Spoof targets    : ${#SPOOF_TARGETS[@]} (from file${_spoof_file:+: $_spoof_file})"
        for _e in "${SPOOF_TARGETS[@]:0:10}"; do echo "  - $_e"; done
        [ "${#SPOOF_TARGETS[@]}" -gt 10 ] && echo "  ... (+$(( ${#SPOOF_TARGETS[@]} - 10 )) more)"
        echo "Per-CIDR samples : $GLOBAL_CIDR_N"
    fi
    echo "Test Mode        : $([ "$TEST_DIR" -eq 1 ] && echo "Both (Direct + Reverse)" || ([ "$TEST_DIR" -eq 2 ] && echo "Direct Only" || echo "Reverse Only"))"
    echo "Output files     : ./spoof_summary.csv + ./spoof_full.csv (overwritten, appended per target)"
    echo "--------------------------------------"
    echo

    read -rp "Start automated test? [y/N]: " CONFIRM
    case "$CONFIRM" in
        y|Y|yes|YES) ;;
        *) echo "Cancelled."; return 0 ;;
    esac

    echo
    echo -e "${BLUE}[*] Testing SSH connection to Foreign server...${NC}"
    if ! sshpass -p "$FOREIGN_PASS" ssh -p "$FOREIGN_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -o LogLevel=ERROR \
        "$FOREIGN_USER@$FOREIGN_IP" "echo SSH_OK" >/dev/null 2>&1; then
        echo -e "${RED}[!] SSH connection failed. Check IP, port, username, and password.${NC}"
        return 1
    fi
    echo -e "${GREEN}[+] SSH connection successful.${NC}"

    echo -e "${BLUE}[*] Checking required tools on Foreign server...${NC}"
    local remote_prefix=""
    if [ "$FOREIGN_USER" != "root" ]; then
        remote_prefix="echo '$FOREIGN_PASS' | sudo -S "
    fi

    local missing_remote
    missing_remote=$(sshpass -p "$FOREIGN_PASS" ssh -p "$FOREIGN_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$FOREIGN_USER@$FOREIGN_IP" "
        for cmd in iptables tcpdump ping nft conntrack nping; do
            command -v \$cmd >/dev/null 2>&1 || echo \$cmd
        done
    ")

    if [ -n "$missing_remote" ]; then
        echo -e "${YELLOW}[!] Missing tools on Foreign server: $missing_remote${NC}"
        echo -e "${YELLOW}[*] Attempting to install missing tools on Foreign server...${NC}"
        sshpass -p "$FOREIGN_PASS" ssh -p "$FOREIGN_PORT" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$FOREIGN_USER@$FOREIGN_IP" "
            if command -v apt-get >/dev/null 2>&1; then
                ${remote_prefix}apt-get update -y && ${remote_prefix}apt-get install -y tcpdump iptables iputils-ping nftables conntrack nmap python3-scapy
            elif command -v yum >/dev/null 2>&1; then
                ${remote_prefix}yum install -y tcpdump iptables iputils nftables conntrack-tools nmap
            elif command -v dnf >/dev/null 2>&1; then
                ${remote_prefix}dnf install -y tcpdump iptables iputils nftables conntrack-tools nmap
            fi
        "
    else
        echo -e "${GREEN}[+] Foreign server has all required tools.${NC}"
    fi

    if [ "$DEBUG" -eq 1 ]; then
        local_diag
        remote_diag
    fi

    # ---- Batch run: one loop iteration per spoof target from prompt or file ----
    # First target overwrites ./spoof_summary.csv + ./spoof_full.csv, rest append.
    CSV_APPEND=0
    CSV_SUMMARY_FILE=""; CSV_FULL_FILE=""
    local -a _batch_summary=()
    local _t_idx=0 _t_total="${#SPOOF_TARGETS[@]}"
    for _t_idx in "${!SPOOF_TARGETS[@]}"; do
        local _entry="${SPOOF_TARGETS[$_t_idx]}"
        local _num=$((_t_idx + 1))
        echo
        echo "======================================================================"
        echo "   TARGET [_num/$_t_total]: $_entry"
        echo "======================================================================"
        SPOOF_CIDR=""; SPOOF_REP_IP=""; SPOOF_FILTER=""
        if ! normalize_spoof_input "$_entry"; then
            echo -e "${YELLOW}[!] Skipping invalid target: $_entry${NC}"
            _batch_summary+=("$_entry | SKIPPED (bad input) | SKIPPED (bad input)")
            continue
        fi
        # Per-target sample size: single IP -> 1; CIDR -> GLOBAL_CIDR_N (or ALL->host count)
        if [[ "$_entry" == *"/"* ]]; then
            if [ "${GLOBAL_CIDR_N:-3}" = "ALL" ]; then
                local _ht
                _ht="$(cidr_host_count "$_entry" 2>/dev/null || echo 3)"
                CIDR_SAMPLE_MAX="${_ht:-3}"
            else
                CIDR_SAMPLE_MAX="${GLOBAL_CIDR_N:-3}"
                local _ht2
                _ht2="$(cidr_host_count "$_entry" 2>/dev/null || echo 0)"
                if [ "${_ht2:-0}" -gt 0 ] 2>/dev/null && [ "$CIDR_SAMPLE_MAX" -gt "$_ht2" ] 2>/dev/null; then
                    CIDR_SAMPLE_MAX="$_ht2"
                fi
            fi
        else
            CIDR_SAMPLE_MAX=1
        fi
        RAW_PKTS_PER_IP=5
        echo -e "${BLUE}[*] Samples for $_entry: $CIDR_SAMPLE_MAX IP(s)${NC}"

        direct_res="SKIPPED"
        reverse_res="SKIPPED"
        direct_spoof_cnt=0; reverse_spoof_cnt=0
        direct_new_real=0; reverse_new_real=0
        direct_nping_proven=0; reverse_nping_proven=0
        direct_raw_ran=0; reverse_raw_ran=0
        DIRECT_RX_LOG=""; REVERSE_RX_LOG=""
        DIRECT_NPING_LOG=""; REVERSE_NPING_LOG=""

        case "$TEST_DIR" in
            1)
                direct_test
                reverse_test
                ;;
            2)
                direct_test
                ;;
            3)
                reverse_test
                ;;
            *)
                direct_test
                reverse_test
                ;;
        esac

        print_summary "$direct_res" "$reverse_res"
        write_csv_results || true
        CSV_APPEND=1
        _batch_summary+=("$_entry | $direct_res | $reverse_res")
    done

    echo
    echo "======================================================================"
    echo "   BATCH SUMMARY (${#SPOOF_TARGETS[@]} target(s))"
    echo "======================================================================"
    printf "%-32s | %-24s | %-24s\n" "SPOOF TARGET" "DIRECT" "REVERSE"
    echo "----------------------------------------------------------------------"
    local _row _t _d _r _rest
    if [ "${#_batch_summary[@]}" -gt 0 ]; then
    for _row in "${_batch_summary[@]}"; do
        _t="${_row%% | *}"; _rest="${_row#* | }"; _d="${_rest%% | *}"; _r="${_rest#* | }"
        printf "%-32s | %-24s | %-24s\n" "$_t" "$_d" "$_r"
    done
    fi
    echo "======================================================================"
    echo -e "${GREEN}[+] Final files (replaced this run, appended per target):${NC}"
    echo "  ./spoof_summary.csv"
    echo "  ./spoof_full.csv"
}

sender() {
    echo
    echo "======================================"
    echo "          SPOOF TEST - SENDER"
    echo "======================================"
    echo

    read -rp "Receiver server REAL IP: " DST_IP
    DST_IP="$(echo "$DST_IP" | tr -d '[:space:]')"
    local _spoof_in=""
    read -rp "Spoof Source IP or CIDR (an IP/range you control, e.g. 1.1.1.1 or 10.99.0.0/24): " _spoof_in
    _spoof_in="$(echo "$_spoof_in" | tr -d '[:space:]')"
    SPOOF_CIDR=""; SPOOF_REP_IP=""; SPOOF_FILTER=""
    if ! normalize_spoof_input "$_spoof_in"; then
        echo "Cancelled (invalid spoof IP/CIDR)."
        return 1
    fi
    if [ -n "${SPOOF_CIDR:-}" ]; then
        echo -e "${BLUE}[*] CIDR mode: SNAT will use $(spoof_rule_ip) (first host of $SPOOF_CIDR).${NC}"
    fi

    echo
    echo -e "${BLUE}[*] Route to receiver:${NC}"
    ip route get "$DST_IP" 2>/dev/null || true
    echo

    read -rp "Number of ping packets [5]: " COUNT
    COUNT="${COUNT:-5}"

    echo
    echo "--------------------------------------"
    echo "Receiver IP : $DST_IP"
    echo "Spoof IP    : $SPOOF_IP"
    if [ -n "${SPOOF_CIDR:-}" ]; then
        echo "SNAT source : $(spoof_rule_ip)"
    fi
    echo "Packets     : $COUNT"
    echo "--------------------------------------"
    echo

    read -rp "Start test? [y/N]: " CONFIRM
    case "$CONFIRM" in
        y|Y|yes|YES) ;;
        *) echo "Cancelled."; return 0 ;;
    esac

    echo
    echo -e "${YELLOW}[*] Adding temporary SNAT rule...${NC}"

    iptables -t nat -I POSTROUTING 1 \
        -p icmp \
        -d "$DST_IP" \
        -j SNAT \
        --to-source "$(spoof_rule_ip)"

    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Could not add iptables rule.${NC}"
        exit 1
    fi

    RULE_ADDED=1

    echo
    echo -e "${GREEN}[+] Rule installed:${NC}"

    iptables -t nat -L POSTROUTING -n -v \
        --line-numbers | head -15

    echo
    echo -e "${YELLOW}[*] Sending ICMP packets...${NC}"
    echo

    ping \
        -c "$COUNT" \
        -W 1 \
        "$DST_IP" || true

    echo
    echo "======================================"
    echo "              TEST DONE"
    echo "======================================"
    echo
    echo "Check the Receiver output."
    echo
    echo "If Receiver saw:"
    echo
    echo "  SRC = $SPOOF_IP"
    echo
    echo "then the spoofed packet reached it."
    echo
    echo "If it saw your real server IP instead,"
    echo "the source was not spoofed."
    echo
    echo "If it saw nothing, the packet may have"
    echo "been filtered/dropped somewhere."
    echo

    cleanup
    RULE_ADDED=0
}

receiver() {
    echo
    echo "======================================"
    echo "         SPOOF TEST - RECEIVER"
    echo "======================================"
    echo

    read -rp "Sender REAL IP: " REAL_SENDER
    REAL_SENDER="$(echo "$REAL_SENDER" | tr -d '[:space:]')"
    read -rp "Expected SPOOF IP or CIDR (e.g. 1.1.1.1 or 10.99.0.0/24): " EXPECTED_SPOOF
    EXPECTED_SPOOF="$(echo "$EXPECTED_SPOOF" | tr -d '[:space:]')"

    echo
    echo "Available interfaces:"
    echo

    ip -br link

    echo
    read -rp "Interface [any]: " INTERFACE
    INTERFACE="${INTERFACE:-any}"

    echo
    echo "======================================"
    echo "Listening for ICMP..."
    echo
    echo "Expected spoof IP:"
    echo "  $EXPECTED_SPOOF"
    echo
    echo "Sender real IP:"
    echo "  $REAL_SENDER"
    echo
    echo "Press CTRL+C when finished."
    echo "======================================"
    echo

    local _exp_filter
    _exp_filter="$(spoof_filter_for "$EXPECTED_SPOOF")"
    echo -e "${BLUE}[*] Capture filter: icmp and ($_exp_filter or src host $REAL_SENDER)${NC}"
    tcpdump \
        -n \
        -l \
        -i "$INTERFACE" \
        "icmp and ($_exp_filter or src host $REAL_SENDER)"
}

main() {
    require_root
    check_tools || exit 1

    clear

    echo "======================================"
    echo "       TWO SERVER IP SPOOF TEST"
    echo "======================================"
    echo
    echo "1) Automated Test (Iran <-> Foreign via SSH)"
    echo "2) Manual Sender"
    echo "3) Manual Receiver"
    echo "4) Exit"
    echo

    read -rp "Select [1-4]: " MODE

    case "$MODE" in
        1)
            auto_test
            ;;
        2)
            sender
            ;;
        3)
            receiver
            ;;
        *)
            exit 0
            ;;
    esac
}

main
