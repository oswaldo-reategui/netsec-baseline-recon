#!/usr/bin/env bash
set -euo pipefail

ts_local() { TZ="${TZ:-Europe/Berlin}" date +"%Y-%m-%d %H:%M:%S %Z"; }

die() { echo "ERROR: $*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
}

load_env_file() {
  local env_file="${1:-.env}"
  [[ -r "$env_file" ]] || die ".env is missing or not readable. Fix with: sudo chown media:media .env && chmod 600 .env"
  set -a
  # shellcheck disable=SC1091
  source "$env_file"
  set +a
}

require_env() {
  : "${TELEGRAM_BOT_TOKEN:?Missing TELEGRAM_BOT_TOKEN in .env}"
  : "${TELEGRAM_CHAT_ID:?Missing TELEGRAM_CHAT_ID in .env}"
  : "${NVD_API_KEY:?Missing NVD_API_KEY in .env}"
}

usage() {
  cat <<'EOF'
Usage:
  ./netsec-recon.sh              Scan WiFi subnet and WiFi gateway
  ./netsec-recon.sh 192.168.2.42 Scan a specific IPv4 host

Notes:
  - Requires Docker Compose service named "nmap" that provides the nmap binary
  - Uses NVD API to classify CVEs if nvd_classify.py is present
EOF
}

port_risk_note() {
  local port="$1"
  case "$port" in
    22/tcp)   echo "Remote admin access (SSH). Risk: credential guessing, misconfig exposure, lateral movement if reachable." ;;
    53/tcp)   echo "DNS service. Risk: traffic observation or manipulation if misconfigured; can reveal internal naming." ;;
    80/tcp)   echo "Web admin or portal (HTTP). Risk: unauthenticated pages, weak auth, session issues." ;;
    443/tcp)  echo "Web admin or portal (HTTPS). Risk: management surface still exposed." ;;
    8080/tcp) echo "App console (HTTP). Risk: admin consoles, default apps, exposed management endpoints." ;;
    8443/tcp) echo "App console (HTTPS). Risk: management interfaces exposed to the subnet." ;;
    7443/tcp) echo "Alternate HTTPS admin or app port. Risk: non standard management surface exposed." ;;
    6789/tcp) echo "Filtered service. Not reachable now, but indicates additional services exist behind firewall rules." ;;
    *)        echo "Service exposed to the subnet. Risk depends on configuration and authentication." ;;
  esac
}

send_telegram_section() {
  local text="$1"
  curl -fsS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${text}" \
    -d "disable_web_page_preview=true" >/dev/null
}

detect_wifi_context() {
  local wifi_if="$1"

  local gw subnet
  gw="$(ip -4 route show default dev "${wifi_if}" 2>/dev/null | awk '{print $3; exit}')"
  subnet="$(ip -4 addr show dev "${wifi_if}" 2>/dev/null | awk '/inet /{print $2; exit}')"

  [[ -n "$gw" && -n "$subnet" ]] || die "Could not detect WiFi gateway/subnet on ${wifi_if}. Try: ip -4 route show default dev ${wifi_if} and ip -4 addr show dev ${wifi_if}"

  printf "%s %s\n" "$gw" "$subnet"
}

run_nmap() {
  docker compose run --rm --entrypoint nmap nmap "$@"
}

nmap_discovery() {
  local subnet_cidr="$1"
  run_nmap -sn -T3 "$subnet_cidr" || true
}

nmap_services() {
  local target="$1"
  run_nmap -Pn -sT -sV -T3 "$target" || true
}

nmap_vuln() {
  local target="$1"
  run_nmap -Pn -sT -sV -T3 --script vuln "$target" || true
}

parse_hosts_up() {
  local discovery_raw="$1"
  printf "%s\n" "$discovery_raw" | awk '
    /^Nmap scan report for/ {
      name=$5
      ip=$NF
      gsub(/[()]/,"",ip)
      if (name ~ /^[0-9]+\./) {
        print ip
      } else {
        print ip " (" name ")"
      }
    }'
}

resolve_name_best_effort() {
  local ip="$1"
  local name=""

  name="$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}' || true)"
  [[ -n "$name" ]] && { echo "$name"; return 0; }

  if have avahi-resolve-address; then
    name="$(avahi-resolve-address "$ip" 2>/dev/null | awk '{print $2; exit}' | sed 's/\.$//' || true)"
    [[ -n "$name" ]] && { echo "$name"; return 0; }
  fi

  if have nmblookup; then
    name="$(nmblookup -A "$ip" 2>/dev/null | awk '/<00> -/ && !/GROUP/ {print $1; exit}' || true)"
    [[ -n "$name" ]] && { echo "$name"; return 0; }
  fi

  echo ""
}

vendor_from_discovery_table() {
  local ip="$1"
  local table="$2"
  [[ -n "$table" ]] || { echo ""; return 0; }
  printf "%s\n" "$table" | awk -v ip="$ip" '$1==ip { $1=""; sub(/^[ \t]+/,""); print; exit }'
}

build_vendor_table_from_discovery() {
  local discovery_raw="$1"
  printf "%s\n" "$discovery_raw" | awk '
    /^Nmap scan report for/ {
      ip=$NF; gsub(/[()]/,"",ip); curip=ip; next
    }
    /MAC Address:/ {
      if (match($0, /\(([^)]+)\)/, m)) {
        vendor=m[1]
        if (curip != "") print curip "\t" vendor
      }
    }'
}

enrich_hosts() {
  local hosts_up="$1"
  local vendor_table="$2"

  while read -r entry; do
    [[ -z "$entry" ]] && continue
    local ip
    ip="$(printf "%s\n" "$entry" | awk '{print $1}' | tr -d '()')"

    local name vendor out
    name="$(resolve_name_best_effort "$ip")"
    vendor="$(vendor_from_discovery_table "$ip" "$vendor_table")"

    out="$ip"
    [[ -n "$name" ]] && out+=" ($name)"
    [[ -n "$vendor" ]] && out+=" [$vendor]"
    echo "$out"
  done <<< "$(printf "%s\n" "$hosts_up" | awk '{print $1}')"
}

parse_target_identity() {
  local target_raw="$1"
  local mac vendor os

  mac="$(printf "%s\n" "$target_raw" | awk '/MAC Address:/ {print $3; exit}')"
  vendor="$(printf "%s\n" "$target_raw" | awk -F'[(|)]' '/MAC Address:/ {gsub(/^ +| +$/,"",$2); print $2; exit}')"
  os="$(printf "%s\n" "$target_raw" | awk -F'OS: ' '/Service Info: OS:/ {print $2; exit}' | tr -d '\n')"
  os="$(echo "$os" | sed 's/[[:space:]]\+/ /g')"

  printf "%s\n" "${mac:-}" "${vendor:-}" "${os:-}"
}

fallback_mac_from_arp_cache() {
  local ip="$1"
  local mac
  mac="$(ip neigh show "$ip" 2>/dev/null | awk '{print $5; exit}' || true)"
  [[ "$mac" == "FAILED" ]] && mac=""
  echo "$mac"
}

parse_services() {
  local target_raw="$1"
  printf "%s\n" "$target_raw" | awk '
    /^[0-9]+\/tcp/ {
      port=$1; service=$3;
      version="";
      for (i=4;i<=NF;i++) version=version" "$i;
      printf "- %s (%s)%s\n", port, service, version
    }'
}

extract_cves() {
  local vuln_raw="$1"
  printf "%s\n" "$vuln_raw" | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort -u || true
}

map_cves_to_ports() {
  local vuln_raw="$1"
  printf "%s\n" "$vuln_raw" | awk '
    /^[0-9]+\/tcp[[:space:]]/ {cur=$1 " " $3; next}
    {
      while (match($0, /CVE-[0-9]{4}-[0-9]+/)) {
        cve=substr($0, RSTART, RLENGTH)
        if (cur != "") print cur " -> " cve
        else print "unknown -> " cve
        $0=substr($0, RSTART+RLENGTH)
      }
    }' | sort -u
}

classify_cves_with_nvd() {
  local cve_list="$1"
  local cve_by_port="$2"
  local classifier="./nvd_classify.py"

  [[ -n "$cve_list" ]] || { echo "No NVD classification available."; return 0; }
  have python3 || { echo "python3 missing. Cannot classify CVEs."; return 0; }
  [[ -f "$classifier" ]] || { echo "nvd_classify.py not found. Cannot classify CVEs."; return 0; }

  local map_file
  map_file="$(mktemp)"
  printf "%s\n" "$cve_by_port" > "$map_file"

  printf "%s\n" "$cve_list" | NVD_API_KEY="${NVD_API_KEY}" python3 "$classifier" "$map_file" || true
  rm -f "$map_file"
}

assess_risk() {
  local hosts_count="$1"
  local cve_count="$2"
  local vuln_raw="$3"

  local risk="LOW"
  local reason="No significant exposure signals observed."

  if [[ "$hosts_count" -gt 2 ]]; then
    risk="MEDIUM"
    reason="Multiple devices are reachable on the local subnet. Guest isolation does not appear to be enforced."
  fi

  if (( cve_count > 0 )) || [[ "${vuln_raw:-}" =~ (VULNERABLE|LIKELY[[:space:]]VULNERABLE) ]]; then
    risk="ELEVATED"
    reason="Vulnerability indicators were reported for the target. Review and update firmware and configurations."
  fi

  printf "%s\t%s\n" "$risk" "$reason"
}

recommended_actions() {
  local hosts_count="$1"
  local exposed_services="$2"
  local vuln_raw="$3"
  local cve_count="$4"

  local actions="No action required."

  if [[ "$hosts_count" -gt 2 ]]; then
    actions=$(
      cat <<'EOF'
• Enable client or guest isolation on the WiFi router
• Prevent guests from seeing each other on the local network
• Use a VPN on untrusted networks
• Avoid local file sharing and device discovery
EOF
    )
  fi

  if echo "${exposed_services}" | grep -Eq '80/tcp|443/tcp|22/tcp|23/tcp'; then
    actions=$(
      cat <<'EOF'
• Restrict management interfaces from guest WiFi
• Allow administration only from wired or trusted networks
• Review firewall rules on the gateway or host
EOF
    )
  fi

  if (( cve_count > 0 )) || [[ "${vuln_raw:-}" =~ (VULNERABLE|LIKELY[[:space:]]VULNERABLE) ]]; then
    actions=$(
      cat <<'EOF'
• Patch or update the target and relevant services
• Reduce exposed ports to what is strictly required
• Restrict access to admin services using firewall rules
EOF
    )
  fi

  printf "%s\n" "$actions"
}

render_services_with_notes() {
  local exposed_services="$1"
  local out=""
  local line port

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    port="$(echo "$line" | awk '{print $2}')"
    out+="${line}
  Note: $(port_risk_note "$port")

"
  done <<< "$exposed_services"

  printf "%s" "${out:-No services detected (or scan failed).}"
}