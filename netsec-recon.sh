#!/usr/bin/env bash
set -euo pipefail

WIFI_IF="${WIFI_IF:-wlan0}"

cd "$(dirname "$0")"
# shellcheck source=lib/core.sh
source "./lib/core.sh"

main() {
  local target_ip="${1:-}"
  local scan_mode="network"

  if [[ -n "$target_ip" ]]; then
    scan_mode="host"
    is_ipv4 "$target_ip" || { usage; die "Invalid IPv4 address: ${target_ip}"; }
  fi

  load_env_file ".env"
  require_env

  have docker || die "docker is required"
  have ip || die "iproute2 is required"

  local wifi_gw wifi_subnet
  read -r wifi_gw wifi_subnet < <(detect_wifi_context "$WIFI_IF")

  local scan_target="$wifi_gw"
  [[ "$scan_mode" == "host" ]] && scan_target="$target_ip"

  local discovery_raw=""
  local vendor_table=""
  if [[ "$scan_mode" == "network" ]]; then
    discovery_raw="$(nmap_discovery "$wifi_subnet")"
    vendor_table="$(build_vendor_table_from_discovery "$discovery_raw" || true)"
  fi

  local target_raw vuln_raw
  target_raw="$(nmap_services "$scan_target")"
  vuln_raw="$(nmap_vuln "$scan_target")"

  local gw_mac gw_vendor gw_os
  read -r gw_mac gw_vendor gw_os < <(parse_target_identity "$target_raw")

  # Fallback MAC via ARP cache when nmap did not provide it
  if [[ -z "${gw_mac:-}" ]]; then
    gw_mac="$(fallback_mac_from_arp_cache "$scan_target")"
  fi

  # Fallback vendor from discovery table in network mode
  if [[ -z "${gw_vendor:-}" && -n "${vendor_table:-}" ]]; then
    gw_vendor="$(vendor_from_discovery_table "$scan_target" "$vendor_table")"
  fi

  local hosts_up="" hosts_up_count="0" hosts_up_enriched=""
  if [[ "$scan_mode" == "network" ]]; then
    hosts_up="$(parse_hosts_up "$discovery_raw")"
    hosts_up_count="$(printf "%s\n" "$hosts_up" | sed '/^$/d' | wc -l | tr -d ' ')"
    hosts_up_enriched="$(enrich_hosts "$hosts_up" "$vendor_table")"
  fi

  local exposed_services
  exposed_services="$(parse_services "$target_raw")"

  local cve_list cve_by_port cve_count
  cve_list="$(extract_cves "$vuln_raw")"
  cve_by_port="$(map_cves_to_ports "$vuln_raw")"
  cve_count="$(printf "%s\n" "$cve_list" | sed '/^$/d' | wc -l | tr -d ' ')"

  local nvd_block
  nvd_block="$(classify_cves_with_nvd "$cve_list" "$cve_by_port")"

  local risk risk_reason
  IFS=$'\t' read -r risk risk_reason < <(assess_risk "$hosts_up_count" "$cve_count" "$vuln_raw")

  local actions
  actions="$(recommended_actions "$hosts_up_count" "$exposed_services" "$vuln_raw" "$cve_count")"

  local section_overview section_visibility section_target section_services section_vulns section_risk
  section_overview="$(cat <<EOF
NETWORK BASELINE SECURITY CHECK

Network:
- Scan interface: ${WIFI_IF} (WiFi)
- Scan mode: ${scan_mode}
- Target: ${scan_target}
- WiFi subnet: ${wifi_subnet}
- WiFi gateway: ${wifi_gw}
- Time: $(ts_local)
EOF
)"

  if [[ "$scan_mode" == "host" ]]; then
    section_visibility="$(cat <<EOF
NETWORK VISIBILITY

Mode: host scan
Subnet discovery was skipped.
Target: ${scan_target}
EOF
)"
  else
    local hosts_trunc hosts_note=""
    hosts_trunc="$(printf "%s\n" "$hosts_up_enriched" | sed '/^$/d' | head -n 50)"
    [[ "$hosts_up_count" -gt 50 ]] && hosts_note="- (list truncated)"

    section_visibility="$(cat <<EOF
NETWORK VISIBILITY

Reachable devices: ${hosts_up_count}

Devices (IP, hostname, vendor if available):
$(printf "%s\n" "$hosts_trunc" | sed 's/^/- /')
${hosts_note}

Interpretation:
More than 2 reachable hosts indicates no client isolation on this network.
EOF
)"
  fi

  section_target="$(cat <<EOF
TARGET IDENTIFICATION

- IP: ${scan_target}
- MAC: ${gw_mac:-Unknown}
- MAC vendor: ${gw_vendor:-Unknown}
- OS (best-effort): ${gw_os:-Unknown}

Note:
OS and vendor are best-effort from Nmap output and local resolution. They are not guaranteed.
EOF
)"

  section_services="$(cat <<EOF
EXPOSED SERVICES

Scope:
These ports are reachable from your current subnet (${wifi_subnet}) to the target (${scan_target}).

$(render_services_with_notes "$exposed_services")
EOF
)"

  section_vulns="$(cat <<EOF
VULNERABILITY INDICATORS

Referenced CVEs: ${cve_count}

${nvd_block}

Note:
NVD severity is sourced from CVSS metrics returned by the NVD API.
These are indicators based on fingerprints and NSE script heuristics. They are not proof of exploitability.
EOF
)"

  section_risk="$(cat <<EOF
RISK ASSESSMENT

Risk level: ${risk}

Reason:
${risk_reason}

Recommended actions:
${actions}
EOF
)"

  send_telegram_section "$section_overview"
  send_telegram_section "$section_visibility"
  send_telegram_section "$section_target"
  send_telegram_section "$section_services"
  send_telegram_section "$section_vulns"
  send_telegram_section "$section_risk"

  echo "Telegram report sent to chat_id=${TELEGRAM_CHAT_ID}"
}

main "$@"