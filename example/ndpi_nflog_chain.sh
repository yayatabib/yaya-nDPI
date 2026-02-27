#!/bin/bash
#
# ndpi_nflog_chain.sh
#
# Passive NFLOG tap organized by nDPI protocol category.
# Replaces pcap/raw-socket packet capture with NFLOG as the
# packet source for userspace nDPI classification.
#
# Architecture:
#
#   Packet (traversing netfilter normally — not intercepted)
#     |
#     v
#   FORWARD / INPUT / OUTPUT  (configurable hook points)
#     |
#     +---> -j NDPI_TAP
#             |
#             +-- tcp/udp ports 80,443,...    -g NDPI_CAT_WEB       → NFLOG group  5
#             +-- tcp ports 25,110,143,...    -g NDPI_CAT_MAIL      → NFLOG group  3
#             +-- tcp/udp ports 53,88,...     -g NDPI_CAT_NETWORK   → NFLOG group 14
#             +-- tcp/udp ports 22,23,...     -g NDPI_CAT_REM_ACC   → NFLOG group 12
#             +-- tcp ports 1433,3306,...     -g NDPI_CAT_DATABASE  → NFLOG group 11
#             +-- ... (more categories) ...
#             |
#             +-- (no port match)            -j NFLOG               → group 200
#             |
#             v
#           RETURN → packet continues normal forwarding
#
#   Goto (-g) gives first-match-wins behavior: once a packet
#   enters a category sub-chain via goto, RETURN exits to the
#   caller of NDPI_TAP (e.g. FORWARD), skipping later rules
#   and the catch-all.
#
#   NFLOG is non-terminating: packets are COPIED to userspace
#   via a netlink socket, then continue normal forwarding.
#   No traffic is blocked or delayed.
#
#   Port matching uses --ports (matches source OR destination),
#   so both directions of a flow are captured in the same
#   category group. nDPI needs both directions for classification.
#
# Userspace reads per-category packet streams via:
#
#   nflog_fd = nflog_open();
#   nflog_bind_group(h, 5);   /* subscribe to WEB traffic */
#   nflog_bind_group(h, 200); /* or subscribe to catch-all  */
#   // Feed received packets to nDPI for full DPI classification
#
# Usage:
#   ./ndpi_nflog_chain.sh install   - Install all rules
#   ./ndpi_nflog_chain.sh remove    - Remove all rules
#   ./ndpi_nflog_chain.sh dump      - Print rules to stdout (dry run)
#   ./ndpi_nflog_chain.sh list      - Show category-to-group mappings
#
# Requirements:
#   - iptables with NFLOG, multiport, and goto (-g) support
#   - Root privileges for install/remove
#   - Kernel with CONFIG_NETFILTER_NETLINK_LOG enabled
#
# Notes:
#   - NFLOG group numbers match ndpi_protocol_category_t enum values
#     from src/include/ndpi_typedefs.h for direct userspace mapping.
#   - Port assignments derived from ndpi_set_proto_defaults() in
#     src/lib/ndpi_main.c — covers all protocols with known ports.
#   - Many modern protocols (Netflix, YouTube, Discord, etc.) run
#     over TLS/QUIC on port 443 and will land in the WEB group.
#     nDPI's DPI engine distinguishes them from generic HTTPS.
#   - For IPv6, replace "iptables" with "ip6tables" throughout,
#     or set NDPI_IPTABLES=ip6tables.
#   - On high-throughput links, tune /proc/net/netfilter/nf_log
#     buffer sizes to avoid packet drops.
#

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────

# iptables binary (override with ip6tables for IPv6)
IPTABLES="${NDPI_IPTABLES:-iptables}"

# Which base chains to hook into (space-separated)
HOOK_CHAINS="${NDPI_HOOK_CHAINS:-FORWARD INPUT}"

# Maximum bytes per NFLOG packet (0 = entire packet, needed for DPI)
NFLOG_COPY_RANGE="${NDPI_NFLOG_RANGE:-0}"

# Main dispatch chain name
TAP_CHAIN="NDPI_TAP"

# Catch-all NFLOG group for traffic not matching any known port
CATCHALL_GROUP="${NDPI_CATCHALL_GROUP:-200}"

# ── Category Sub-Chain Definitions ─────────────────────────────────
#
# Format: NFLOG_GROUP:CHAIN_NAME
#
# Group numbers are nDPI category enum values.
# Chain names are kept under 29 chars (iptables limit = 30).

CAT_CHAINS=(
  "1:NDPI_CAT_MEDIA"
  "2:NDPI_CAT_VPN"
  "3:NDPI_CAT_MAIL"
  "4:NDPI_CAT_DATA_XFER"
  "5:NDPI_CAT_WEB"
  "7:NDPI_CAT_DOWNLOAD"
  "8:NDPI_CAT_GAME"
  "9:NDPI_CAT_CHAT"
  "10:NDPI_CAT_VOIP"
  "11:NDPI_CAT_DATABASE"
  "12:NDPI_CAT_REM_ACCESS"
  "14:NDPI_CAT_NETWORK"
  "15:NDPI_CAT_COLLAB"
  "16:NDPI_CAT_RPC"
  "18:NDPI_CAT_SYSTEM"
  "31:NDPI_CAT_IOT_SCADA"
  "106:NDPI_CAT_CRYPTO"
)

# ── Functions ──────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $0 {install|remove|dump|list}

  install  - Create NFLOG tap chains and hook into ${HOOK_CHAINS}
  remove   - Remove all nDPI NFLOG tap rules
  dump     - Print iptables commands without executing (dry run)
  list     - Show category-to-NFLOG-group mappings

Environment variables:
  NDPI_IPTABLES       iptables binary (default: iptables; set ip6tables for IPv6)
  NDPI_HOOK_CHAINS    Chains to tap (default: "FORWARD INPUT")
  NDPI_NFLOG_RANGE    Bytes to copy per packet, 0=full (default: 0)
  NDPI_CATCHALL_GROUP NFLOG group for unmatched traffic (default: 200)
EOF
  exit 1
}

# Execute or print depending on mode
run() {
  if [ "$MODE" = "dump" ]; then
    echo "$@"
  else
    "$@"
  fi
}

# Create chain (flush if it already exists)
ensure_chain() {
  local chain="$1"
  if [ "$MODE" = "dump" ]; then
    echo "$IPTABLES -N $chain 2>/dev/null || $IPTABLES -F $chain"
  else
    $IPTABLES -N "$chain" 2>/dev/null || $IPTABLES -F "$chain"
  fi
}

install_rules() {

  # ── Phase 1: Create category sub-chains ──────────────────────
  #
  # Each sub-chain has a single NFLOG rule. Packets entering via
  # goto (-g) will fire the NFLOG, then fall off the end of the
  # sub-chain, returning to the base chain (not NDPI_TAP).

  echo "# ── Phase 1: Category sub-chains (${#CAT_CHAINS[@]} categories) ──"
  echo ""

  for entry in "${CAT_CHAINS[@]}"; do
    local group="${entry%%:*}"
    local chain="${entry#*:}"
    local label="${chain#NDPI_CAT_}"

    ensure_chain "$chain"
    run $IPTABLES -A "$chain" \
      -j NFLOG \
      --nflog-group "$group" \
      --nflog-prefix "$label" \
      --nflog-range "$NFLOG_COPY_RANGE"
  done

  # ── Phase 2: Create the main dispatch chain ──────────────────
  #
  # Rules use -g (goto) to category sub-chains. With goto, when
  # the sub-chain finishes, control returns to the CALLER of
  # NDPI_TAP (e.g. FORWARD), not to NDPI_TAP itself. This means
  # the first matching rule wins and the catch-all is skipped.
  #
  # Rules use --ports (matches either src or dst port) to capture
  # both directions of each flow in the same category group.
  # Multiport supports up to 15 port entries per rule.

  echo ""
  echo "# ── Phase 2: Dispatch chain ${TAP_CHAIN} ──"
  echo ""

  ensure_chain "$TAP_CHAIN"

  # ── WEB (group 5) ──
  # HTTP, TLS, QUIC, SOCKS, HTTP proxies
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 80,443,1080,3128,8080,8443 \
    -g NDPI_CAT_WEB
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 443,1080 \
    -g NDPI_CAT_WEB

  # ── MAIL (group 3) ──
  # SMTP (25,587), SMTPS (465), POP3 (110), POPS (995), IMAP (143), IMAPS (993)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 25,110,143,465,587,993,995 \
    -g NDPI_CAT_MAIL

  # ── VPN (group 2) ──
  # IPSec (500,4500), OpenVPN (1194), WireGuard (51820), Tailscale (41641)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 500,1194 \
    -g NDPI_CAT_VPN
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 500,1194,4500,41641,51820 \
    -g NDPI_CAT_VPN

  # ── REMOTE_ACCESS (group 12) ──
  # SSH (22), Telnet (23), RDP (3389), NoMachine (4000),
  # Radmin (4899), VNC (5800,5900,5901), TeamViewer (5938)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 22,23,3389,4000,4899,5800,5900,5901,5938 \
    -g NDPI_CAT_REM_ACCESS
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 3389,4000,5938 \
    -g NDPI_CAT_REM_ACCESS

  # ── DATABASE (group 11) ──
  # MSSQL (1433,1434), Oracle (1521), MySQL (3306), PostgreSQL (5432),
  # Redis/RESP (6379), Cassandra (7000,9042), MongoDB (27017)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 1433,1434,1521,3306,5432,6379,7000,9042,27017 \
    -g NDPI_CAT_DATABASE

  # ── NETWORK (group 14) ──
  # DNS (53), Kerberos (88), BGP (179,2605), Radius (1812,1813),
  # STUN (3478), LLMNR (5355)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 53,88,179,1812,1813,2605,3478,5355 \
    -g NDPI_CAT_NETWORK
  # DNS (53), DHCP (67,68), Kerberos (88), SNMP (161,162),
  # Radius (1812,1813), NetFlow (2055), GTP (2123,2152),
  # STUN (3478), WSD (3702), MDNS (5353,5354), LLMNR (5355)
  # Split into two rules (15-port multiport limit)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 53,67,68,88,161,162,1812,1813,2055,2123,2152,3478,3702,5353,5354 \
    -g NDPI_CAT_NETWORK
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 5355,6343 \
    -g NDPI_CAT_NETWORK

  # ── VOIP (group 10) ──
  # H.323 (1719,1720), SIP (5060,5061)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 1719,1720,5060,5061 \
    -g NDPI_CAT_VOIP
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 1719,1720,5060,5061 \
    -g NDPI_CAT_VOIP

  # ── SYSTEM_OS (group 18) ──
  # NetBIOS (139), LDAP (389), SMB (445), Syslog (514,601,6514),
  # Roughtime (2002), Munin (4949)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 139,389,445,514,601,2002,4949,6514 \
    -g NDPI_CAT_SYSTEM
  # NTP (123), NetBIOS (137,138,139), PTPv2 (319,320), LDAP (389),
  # Syslog (514), RMCP (623), Roughtime (2002), BJNP (8612), collectd (25826)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 123,137,138,139,319,320,389,514,623,2002,8612,25826 \
    -g NDPI_CAT_SYSTEM

  # ── IOT_SCADA (group 31) ──
  # Modbus (502), ANSI-C12.22 (1153), IEC60870 (2404), KNXnet/IP (3671),
  # IEC62056 (4059), IEEE-C37118 (4712), OPC-UA (4840), HiSLIP (4880),
  # HART-IP (5094), FINS (9600), TPLINK-SHP (9999), TRDP (17225),
  # DNP3 (20000), BeckhoffADS (48898)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 502,1153,2404,3671,4059,4712,4840,4880,5094,9600,9999,17225,20000,48898 \
    -g NDPI_CAT_IOT_SCADA
  # ANSI-C12.22 (1153), TriStation (1501,1502), CIP (2222), KNXnet/IP (3671),
  # IEC62056 (4059), IEEE-C37118 (4713), Ether-S-Bus (5050),
  # Matter (5540,5542), EtherSIO (6060), TuyaLP (6667),
  # FINS (9600), TPLINK-SHP (9999), TRDP (17224,17225)
  # Split into two rules (15-port multiport limit)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 1153,1501,1502,2222,3671,4059,4713,5050,5540,5542,6060,6667,9600,9999,17224 \
    -g NDPI_CAT_IOT_SCADA
  # BACnet (47808), TRDP (17225)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 17225,47808 \
    -g NDPI_CAT_IOT_SCADA

  # ── RPC (group 16) ──
  # DCERPC (135), SLP (427), JRMI (1099), MQTT (1883,8883),
  # Gearman (4730), Kafka (9092), SOME/IP (30491,30501),
  # STOMP (61613), OpenWire (61616)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 135,427,1099,1883,4730,8883,9092,30491,30501,61613,61616 \
    -g NDPI_CAT_RPC
  # DCERPC (135), SLP (427), CoAP (5683,5684), RTPS (7401),
  # SOME/IP (30490,30491,30501)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 135,427,5683,5684,7401,30490,30491,30501 \
    -g NDPI_CAT_RPC

  # ── GAME (group 8) ──
  # Blizzard (1119), GuildWars2 (6112)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 1119,6112 \
    -g NDPI_CAT_GAME
  # Blizzard (1119), TocaBoca (5055), GaijinEntertainment (20011),
  # AmongUs (22023), GenshinImpact (22102), Source Engine (27015)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 1119,5055,20011,22023,22102,27015 \
    -g NDPI_CAT_GAME

  # ── CHAT (group 9) ──
  # IRC (194), Viber (4244,5242,5243,7985)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 194,4244,5242,5243,7985 \
    -g NDPI_CAT_CHAT
  # IRC (194), Viber (4244,5242,5243,7985,7987), OICQ (8000)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 194,4244,5242,5243,7985,7987,8000 \
    -g NDPI_CAT_CHAT

  # ── DATA_TRANSFER (group 4) ──
  # AFP (548), RSYNC (873), NFS (2049)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 548,873,2049 \
    -g NDPI_CAT_DATA_XFER
  # TFTP (69), AFP (548), NFS (2049)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 69,548,2049 \
    -g NDPI_CAT_DATA_XFER

  # ── DOWNLOAD_FT (group 7) ──
  # FTP-DATA (20), FTP-CONTROL (21), BitTorrent (6881-6889,51413,53646)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 20,21,6881:6889,51413,53646 \
    -g NDPI_CAT_DOWNLOAD
  # BitTorrent (6771,6881-6889,51413)
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    -m multiport --ports 6771,6881:6889,51413 \
    -g NDPI_CAT_DOWNLOAD

  # ── MEDIA (group 1) ──
  # RTSP (554), RTMP (1935)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 554,1935 \
    -g NDPI_CAT_MEDIA
  run $IPTABLES -A "$TAP_CHAIN" -p udp \
    --dport 554 \
    -g NDPI_CAT_MEDIA

  # ── COLLABORATIVE (group 15) ──
  # HCL Notes (1352), Git (9418)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 1352,9418 \
    -g NDPI_CAT_COLLAB

  # ── CRYPTO_BLOCKCHAIN (group 106) ──
  # Nano (7075), Bitcoin (8333), Ethereum (30303)
  run $IPTABLES -A "$TAP_CHAIN" -p tcp \
    -m multiport --ports 7075,8333,30303 \
    -g NDPI_CAT_CRYPTO

  # ── Catch-all: unmatched traffic ──
  #
  # Packets not matching any known port pattern above are copied
  # to the catch-all group. nDPI will classify these using DPI
  # regardless of the NFLOG group they arrive in.

  echo ""
  echo "# ── Phase 2b: Catch-all for unmatched traffic ──"
  echo ""

  run $IPTABLES -A "$TAP_CHAIN" \
    -j NFLOG \
    --nflog-group "$CATCHALL_GROUP" \
    --nflog-prefix "OTHER" \
    --nflog-range "$NFLOG_COPY_RANGE"

  # ── Phase 3: Hook into base chains ──────────────────────────

  echo ""
  echo "# ── Phase 3: Hook into base chains ──"
  echo ""

  for chain in $HOOK_CHAINS; do
    run $IPTABLES -A "$chain" -j "$TAP_CHAIN"
  done

  echo ""
  echo "# ── Done ──"
  echo "#"
  echo "# ${#CAT_CHAINS[@]} category groups + 1 catch-all group installed."
  echo "# NFLOG groups: 1-106 (categories) + ${CATCHALL_GROUP} (catch-all)"
  echo "#"
  echo "# Userspace: nflog_bind_group(h, <group>) to subscribe."
  echo ""
}

remove_rules() {
  echo "# Removing nDPI NFLOG tap rules..."

  # Remove hooks from base chains
  for chain in $HOOK_CHAINS; do
    while $IPTABLES -D "$chain" -j "$TAP_CHAIN" 2>/dev/null; do :; done
  done

  # Flush and delete dispatch chain
  $IPTABLES -F "$TAP_CHAIN" 2>/dev/null || true
  $IPTABLES -X "$TAP_CHAIN" 2>/dev/null || true

  # Flush and delete category sub-chains
  for entry in "${CAT_CHAINS[@]}"; do
    local chain="${entry#*:}"
    $IPTABLES -F "$chain" 2>/dev/null || true
    $IPTABLES -X "$chain" 2>/dev/null || true
  done

  echo "# Done. All nDPI NFLOG tap rules removed."
}

list_categories() {
  cat <<'EOF'
nDPI Protocol Category → NFLOG Group Mapping
=============================================

Group  Chain                 Category           Key Protocols (ports)
─────  ────────────────────  ─────────────────  ─────────────────────────────────
  1    NDPI_CAT_MEDIA        MEDIA              RTSP (554), RTMP (1935)
  2    NDPI_CAT_VPN          VPN                IPSec (500), OpenVPN (1194), WireGuard (51820)
  3    NDPI_CAT_MAIL         MAIL               SMTP (25,587), POP3 (110), IMAP (143) +TLS
  4    NDPI_CAT_DATA_XFER    DATA_TRANSFER      NFS (2049), AFP (548), RSYNC (873), TFTP (69)
  5    NDPI_CAT_WEB          WEB                HTTP (80), TLS (443), QUIC (443/udp), SOCKS
  7    NDPI_CAT_DOWNLOAD     DOWNLOAD_FT        FTP (20,21), BitTorrent (6881-6889)
  8    NDPI_CAT_GAME         GAME               Blizzard (1119), Source Engine (27015)
  9    NDPI_CAT_CHAT         CHAT               IRC (194), Viber (5242), OICQ (8000)
 10    NDPI_CAT_VOIP         VOIP               SIP (5060-5061), H.323 (1719-1720)
 11    NDPI_CAT_DATABASE     DATABASE            MySQL (3306), PostgreSQL (5432), Redis (6379)
 12    NDPI_CAT_REM_ACCESS   REMOTE_ACCESS      SSH (22), Telnet (23), RDP (3389), VNC (5900)
 14    NDPI_CAT_NETWORK      NETWORK            DNS (53), DHCP (67-68), BGP (179), SNMP (161)
 15    NDPI_CAT_COLLAB       COLLABORATIVE      Git (9418), HCL Notes (1352)
 16    NDPI_CAT_RPC          RPC                MQTT (1883), CoAP (5683), Kafka (9092)
 18    NDPI_CAT_SYSTEM       SYSTEM_OS          SMB (445), NTP (123), Syslog (514), LDAP (389)
 31    NDPI_CAT_IOT_SCADA    IOT_SCADA          Modbus (502), OPC-UA (4840), BACnet (47808)
106    NDPI_CAT_CRYPTO       CRYPTO_BLOCKCHAIN  Bitcoin (8333), Ethereum (30303)
200    (catch-all)           OTHER              All traffic not matching above ports

Notes:
  - Group numbers match ndpi_protocol_category_t enum in ndpi_typedefs.h
  - Many protocols (Netflix, YouTube, Discord, etc.) use TLS/QUIC on port 443
    and will appear in the WEB group; nDPI distinguishes them via DPI.
  - Categories without well-known ports (SOCIAL_NETWORK, STREAMING, CLOUD,
    SW_UPDATE, MUSIC, VIDEO, etc.) route through the catch-all group.
EOF
}

# ── Main ───────────────────────────────────────────────────────────

MODE="${1:-}"

case "$MODE" in
  install)
    install_rules
    ;;
  remove)
    remove_rules
    ;;
  dump)
    install_rules
    ;;
  list)
    list_categories
    ;;
  *)
    usage
    ;;
esac
