#!/bin/bash
#
# ndpi_nflog_chain.sh
#
# Generates iptables rules that assign each nDPI-classified protocol
# to its own NFLOG group, enabling per-protocol packet capture without
# raw sockets.
#
# Architecture:
#
#   Packet
#     |
#     v
#   PREROUTING / INPUT / FORWARD
#     |
#     +---> NFQUEUE --queue-num 0
#               |
#               v
#         Userspace nDPI classifier
#         (reads via libnetfilter_queue,
#          classifies with nDPI,
#          sets CONNMARK = protocol_id,
#          issues NF_ACCEPT verdict)
#               |
#               v
#         Packet re-enters netfilter
#               |
#               v
#         NDPI_DISPATCH chain
#         (matches CONNMARK, fans out to NFLOG groups)
#               |
#               +-- connmark 7  --> NFLOG group 7   (HTTP)
#               +-- connmark 91 --> NFLOG group 91  (TLS)
#               +-- connmark 5  --> NFLOG group 5   (DNS)
#               +-- ...one rule per protocol...
#               |
#               v
#         RETURN (normal forwarding continues)
#
# Userspace reads per-protocol captures via:
#   nflog_fd = nflog_open()
#   nflog_bind_group(h, <group_number>)
#
# Usage:
#   ./ndpi_nflog_chain.sh install   - Install all rules
#   ./ndpi_nflog_chain.sh remove    - Remove all rules
#   ./ndpi_nflog_chain.sh dump      - Print rules to stdout (dry run)
#
# Requirements:
#   - iptables with NFLOG and connmark support
#   - A userspace nDPI classifier that sets CONNMARK (not included)
#   - Root privileges
#

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────

# Which base chain to hook into (FORWARD, INPUT, OUTPUT, or all)
HOOK_CHAINS="${NDPI_HOOK_CHAINS:-FORWARD}"

# NFQUEUE number for the userspace classifier
NFQUEUE_NUM="${NDPI_NFQUEUE_NUM:-0}"

# Custom chain name for the dispatch table
DISPATCH_CHAIN="NDPI_DISPATCH"

# NFLOG group offset (group = offset + protocol_id)
# Set to 0 to use protocol IDs directly as group numbers.
# Set to e.g. 1000 to avoid collisions with other NFLOG users.
NFLOG_GROUP_OFFSET="${NDPI_NFLOG_OFFSET:-0}"

# Maximum number of bytes to copy per packet into NFLOG
NFLOG_COPY_RANGE="${NDPI_NFLOG_RANGE:-128}"

# ── Protocol Table ─────────────────────────────────────────────────
#
# Format: PROTOCOL_ID:DISPLAY_NAME
#
# Derived from src/include/ndpi_protocol_ids.h and
# ndpi_set_proto_defaults() in src/lib/ndpi_main.c.
# Protocol ID 0 (Unknown) is omitted — unclassified traffic
# stays in the default chain without NFLOG.

PROTOCOLS=(
  "1:FTP_CONTROL"
  "2:POP3"
  "3:SMTP"
  "4:IMAP"
  "5:DNS"
  "6:IPP"
  "7:HTTP"
  "8:MDNS"
  "9:NTP"
  "10:NetBIOS"
  "11:NFS"
  "12:SSDP"
  "13:BGP"
  "14:SNMP"
  "15:XDMCP"
  "16:SMBv1"
  "17:Syslog"
  "18:DHCP"
  "19:PostgreSQL"
  "20:MySQL"
  "21:Outlook"
  "22:VK"
  "23:POPS"
  "24:Tailscale"
  "25:Yandex"
  "26:ntop"
  "27:COAP"
  "28:VMware"
  "29:SMTPS"
  "30:DTLS"
  "31:UBNTAC2"
  "32:BFCP"
  "33:YandexMail"
  "34:YandexMusic"
  "35:Gnutella"
  "36:eDonkey"
  "37:BitTorrent"
  "38:TeamsCall"
  "39:Signal"
  "40:Memcached"
  "41:SMBv23"
  "42:Mining"
  "43:NestLogSink"
  "44:Modbus"
  "45:WhatsAppCall"
  "46:DataSaver"
  "47:Xbox"
  "48:QQ"
  "49:TikTok"
  "50:RTSP"
  "51:IMAPS"
  "52:IceCast"
  "53:CPHA"
  "54:iQIYI"
  "55:Zattoo"
  "56:YandexMarket"
  "57:YandexDisk"
  "58:Discord"
  "59:AdobeConnect"
  "60:MongoDB"
  "61:Pluralsight"
  "62:YandexCloud"
  "63:OCSP"
  "64:VXLAN"
  "65:IRC"
  "66:MerakiCloud"
  "67:Jabber"
  "68:Nats"
  "69:AmongUs"
  "70:Yahoo"
  "71:DisneyPlus"
  "72:HART-IP"
  "73:VRRP"
  "74:Steam"
  "75:MELSEC"
  "76:WorldOfWarcraft"
  "77:Telnet"
  "78:STUN"
  "79:IPSec"
  "80:GRE"
  "81:ICMP"
  "82:IGMP"
  "83:EGP"
  "84:SCTP"
  "85:OSPF"
  "86:IP_in_IP"
  "87:RTP"
  "88:RDP"
  "89:VNC"
  "90:Tumblr"
  "91:TLS"
  "92:SSH"
  "93:Usenet"
  "94:MGCP"
  "95:IAX"
  "96:TFTP"
  "97:AFP"
  "98:YandexMetrika"
  "99:YandexDirect"
  "100:SIP"
  "101:TruPhone"
  "102:ICMPV6"
  "103:DHCPV6"
  "104:Armagetron"
  "105:Crossfire"
  "106:Dofus"
  "107:Blacknut"
  "108:Boosteroid"
  "109:GuildWars2"
  "110:AmazonAlexa"
  "111:Kerberos"
  "112:LDAP"
  "113:Nexon"
  "114:MsSQL-TDS"
  "115:PPTP"
  "116:AH"
  "117:ESP"
  "118:Slack"
  "119:Facebook"
  "120:Twitter"
  "121:Dropbox"
  "122:Gmail"
  "123:GoogleMaps"
  "124:YouTube"
  "125:Mozilla"
  "126:Google"
  "127:MS-RPCH"
  "128:NetFlow"
  "129:sFlow"
  "130:HTTP_Connect"
  "131:HTTP_Proxy"
  "132:Citrix"
  "133:Netflix"
  "134:LastFM"
  "135:Waze"
  "136:YouTubeUpload"
  "137:Hulu"
  "138:CHECKMK"
  "139:AJP"
  "140:Apple"
  "141:Webex"
  "142:WhatsApp"
  "143:AppleiCloud"
  "144:Viber"
  "145:AppleiTunes"
  "146:Radius"
  "147:WindowsUpdate"
  "148:TeamViewer"
  "149:EGD"
  "150:HCL_Notes"
  "151:SAP"
  "152:GTP"
  "153:WSD"
  "154:LLMNR"
  "155:TocaBoca"
  "156:Spotify"
  "157:FacebookMessenger"
  "158:H323"
  "159:OpenVPN"
  "160:NOE"
  "161:CiscoVPN"
  "162:TeamSpeak"
  "163:Tor"
  "164:CiscoSkinny"
  "165:RTCP"
  "166:RSYNC"
  "167:Oracle"
  "168:Corba"
  "169:Canonical"
  "170:Whois-DAS"
  "171:SD-RTN"
  "172:SOCKS"
  "173:Nintendo"
  "174:RTMP"
  "175:FTP_DATA"
  "176:Wikipedia"
  "177:ZeroMQ"
  "178:Amazon"
  "179:eBay"
  "180:CNN"
  "181:Megaco"
  "182:RESP"
  "183:Pinterest"
  "184:OSPF_v2"
  "185:Telegram"
  "186:CoD_Mobile"
  "187:Pandora"
  "188:QUIC"
  "189:Zoom"
  "190:EAQ"
  "191:Ookla"
  "192:AMQP"
  "193:KakaoTalk"
  "194:KakaoTalkVoice"
  "195:Twitch"
  "196:DoH_DoT"
  "197:WeChat"
  "198:MPEG_TS"
  "199:Snapchat"
  "200:Sina"
  "201:GoogleMeet"
  "202:iflix"
  "203:GitHub"
  "204:BJNP"
  "205:Reddit"
  "206:WireGuard"
  "207:SMPP"
  "208:DNScrypt"
  "209:TINC"
  "210:Deezer"
  "211:Instagram"
  "212:Microsoft"
  "213:Blizzard"
  "214:Teredo"
  "215:HotspotShield"
  "216:IMO"
  "217:GoogleDrive"
  "218:OCS"
  "219:Microsoft365"
  "220:Cloudflare"
  "221:MS_OneDrive"
  "222:MQTT"
  "223:RX"
  "224:AppleStore"
  "225:OpenDNS"
  "226:Git"
  "227:DRDA"
  "228:PlayStore"
  "229:SOMEIP"
  "230:FIX"
  "231:PlayStation"
  "232:Pastebin"
  "233:LinkedIn"
  "234:SoundCloud"
  "235:SteamDatagramRelay"
  "236:LISP"
  "237:Diameter"
  "238:ApplePush"
  "239:GoogleServices"
  "240:AmazonVideo"
  "241:GoogleDocs"
  "242:WhatsAppFiles"
  "243:TargusDataspeed"
  "244:DNP3"
  "245:IEC60870"
  "246:Bloomberg"
  "247:CAPWAP"
  "248:Zabbix"
  "249:S7Comm"
  "250:Teams"
  "251:WebSocket"
  "252:AnyDesk"
  "253:SOAP"
  "254:AppleSiri"
  "255:SnapchatCall"
  "256:HP_VIRTGRP"
  "257:GenshinImpact"
  "258:Activision"
  "259:FortiClient"
  "260:Z3950"
  "261:Likee"
  "262:GitLab"
  "263:AVASTSecureDNS"
  "264:Cassandra"
  "265:AmazonAWS"
  "266:Salesforce"
  "267:Vimeo"
  "268:FacebookVoip"
  "269:SignalVoip"
  "270:Fuze"
  "271:GTP_U"
  "272:GTP_C"
  "273:GTP_PRIME"
  "274:Alibaba"
  "275:Crashlytics"
  "276:Azure"
  "277:iCloudPrivateRelay"
  "278:EthernetIP"
  "279:Badoo"
  "280:AccuWeather"
  "281:GoogleClassroom"
  "282:HSRP"
  "283:Cybersecurity"
  "284:GoogleCloud"
  "285:Tencent"
  "286:RakNet"
  "287:Xiaomi"
  "288:Edgecast"
  "289:Cachefly"
  "290:Softether"
  "291:MpegDash"
  "292:DAZN"
  "293:GoTo"
  "294:RSH"
  "295:1KXUN"
  "296:PGM"
  "297:PIM"
  "298:collectd"
  "299:TunnelBear"
  "300:CloudflareWarp"
  "301:i3D"
  "302:RiotGames"
  "303:Psiphon"
  "304:UltraSurf"
  "305:Threema"
  "306:AliCloud"
  "307:AVAST"
  "308:TiVoConnect"
  "309:Kismet"
  "310:FastCGI"
  "311:FTPS"
  "312:NAT-PMP"
  "313:Syncthing"
  "314:CryNetwork"
  "315:Line"
  "316:LineCall"
  "317:AppleTVPlus"
  "318:DirecTV"
  "319:HBO"
  "320:Vudu"
  "321:Showtime"
  "322:Dailymotion"
  "323:Livestream"
  "324:TencentVideo"
  "325:iHeartRadio"
  "326:Tidal"
  "327:TuneIn"
  "328:SiriusXMRadio"
  "329:Munin"
  "330:Elasticsearch"
  "331:TuyaLP"
  "332:TPLINK_SHP"
  "333:Source_Engine"
  "334:BACnet"
  "335:OICQ"
  "336:HeroesOfTheStorm"
  "337:FacebookReelStory"
  "338:SRTP"
  "339:OperaVPN"
  "340:EpicGames"
  "341:GeForceNow"
  "342:Nvidia"
  "343:Bitcoin"
  "344:ProtonVPN"
  "345:Thrift"
  "346:Roblox"
  "347:ServiceLocation"
  "348:Mullvad"
  "349:HTTP2"
  "350:HAProxy"
  "351:RMCP"
  "352:CAN"
  "353:Protobuf"
  "354:Ethereum"
  "355:TelegramVoip"
  "356:SinaWeibo"
  "357:TeslaServices"
  "358:PTPv2"
  "359:RTPS"
  "360:OPC-UA"
  "361:S7CommPlus"
  "362:FINS"
  "363:EtherSIO"
  "364:UMAS"
  "365:BeckhoffADS"
  "366:ISO9506-1-MMS"
  "367:IEEE-C37118"
  "368:Ether-S-Bus"
  "369:Monero"
  "370:DCERPC"
  "371:PROFINET_IO"
  "372:HiSLIP"
  "373:UFTP"
  "374:OpenFlow"
  "375:JSON-RPC"
  "376:WebDAV"
  "377:Kafka"
  "378:NoMachine"
  "379:IEC62056"
  "380:HL7"
  "381:Ceph"
  "382:GoogleChat"
  "383:Roughtime"
  "384:PIA"
  "385:KCP"
  "386:Dota2"
  "387:Mumble"
  "388:Yojimbo"
  "389:ElectronicArts"
  "390:STOMP"
  "391:Radmin"
  "392:Raft"
  "393:CIP"
  "394:Gearman"
  "395:TencentGames"
  "396:GaijinEntertainment"
  "397:ANSI_C1222"
  "398:Huawei"
  "399:HuaweiCloud"
  "400:DLEP"
  "401:BFD"
  "402:NetEaseGames"
  "403:PathofExile"
  "404:GoogleCall"
  "405:PFCP"
  "406:FLUTE"
  "407:LoLWildRift"
  "408:TES_Online"
  "409:LDP"
  "410:KNXnet_IP"
  "411:Bluesky"
  "412:Mastodon"
  "413:Threads"
  "414:ViberVoip"
  "415:ZUG"
  "416:JRMI"
  "417:RipeAtlas"
  "418:HLS"
  "419:ClickHouse"
  "420:Nano"
  "421:OpenWire"
  "422:CNP-IP"
  "423:ATG"
  "424:TRDP"
  "425:Lustre"
  "426:NordVPN"
  "427:Surfshark"
  "428:CactusVPN"
  "429:Windscribe"
  "430:Sonos"
  "431:DingTalk"
  "432:Paltalk"
  "433:Naver"
  "434:Shein"
  "435:Temu"
  "436:Taobao"
  "437:Mikrotik"
  "438:DICOM"
  "439:ParamountPlus"
  "440:YandexAlice"
  "441:Vivox"
  "442:DigitalOcean"
  "443:Rutube"
  "444:LagoFast"
  "445:GearUP_Booster"
  "446:Rumble"
  "447:Ubiquity"
  "448:MSDO"
  "449:RockstarGames"
  "450:Kick"
  "451:Hamachi"
  "452:GLBP"
  "453:EasyWeather"
  "454:Mudfish"
  "455:TriStation"
  "456:SamsungSDP"
  "457:Matter"
  "458:AWS_Cognito"
  "459:AWS_APIGateway"
  "460:AWS_Kinesis"
  "461:AWS_EC2"
  "462:AWS_EMR"
  "463:AWS_S3"
  "464:AWS_CloudFront"
  "465:AWS_DynamoDB"
  "466:ESPN"
  "467:Akamai"
)

# ── Functions ──────────────────────────────────────────────────────

usage() {
  echo "Usage: $0 {install|remove|dump}"
  echo ""
  echo "  install  - Create NDPI_DISPATCH chain and hook into ${HOOK_CHAINS}"
  echo "  remove   - Remove all nDPI iptables rules"
  echo "  dump     - Print iptables commands without executing (dry run)"
  echo ""
  echo "Environment variables:"
  echo "  NDPI_HOOK_CHAINS   Chains to hook into (default: FORWARD)"
  echo "  NDPI_NFQUEUE_NUM   NFQUEUE number for classifier (default: 0)"
  echo "  NDPI_NFLOG_OFFSET  Added to protocol ID for NFLOG group (default: 0)"
  echo "  NDPI_NFLOG_RANGE   Bytes to copy per NFLOG packet (default: 128)"
  exit 1
}

run_or_print() {
  if [ "$MODE" = "dump" ]; then
    echo "$@"
  else
    "$@"
  fi
}

install_rules() {
  echo "# ── Phase 1: Create the dispatch chain ──"

  # Flush if exists, create if not
  run_or_print iptables -N "$DISPATCH_CHAIN" 2>/dev/null || \
    run_or_print iptables -F "$DISPATCH_CHAIN"

  echo ""
  echo "# ── Phase 2: NFQUEUE rule (sends packets to userspace nDPI classifier) ──"
  echo "#"
  echo "# The userspace program must:"
  echo "#   1. Read packets from NFQUEUE ${NFQUEUE_NUM}"
  echo "#   2. Classify each flow with nDPI"
  echo "#   3. Set CONNMARK = nDPI protocol ID"
  echo "#   4. Issue NF_ACCEPT verdict"
  echo "#"

  for chain in $HOOK_CHAINS; do
    # Restore connmark from connection tracking into packet mark
    run_or_print iptables -A "$chain" \
      -m connmark ! --mark 0 \
      -j CONNMARK --restore-mark

    # Only queue unmarked packets (not yet classified)
    run_or_print iptables -A "$chain" \
      -m mark --mark 0 \
      -j NFQUEUE --queue-num "$NFQUEUE_NUM" --queue-bypass
  done

  echo ""
  echo "# ── Phase 3: Per-protocol NFLOG dispatch (${#PROTOCOLS[@]} protocols) ──"

  for entry in "${PROTOCOLS[@]}"; do
    proto_id="${entry%%:*}"
    proto_name="${entry#*:}"
    nflog_group=$(( proto_id + NFLOG_GROUP_OFFSET ))

    run_or_print iptables -A "$DISPATCH_CHAIN" \
      -m connmark --mark "$proto_id" \
      -j NFLOG \
      --nflog-group "$nflog_group" \
      --nflog-prefix "$proto_name" \
      --nflog-range "$NFLOG_COPY_RANGE"
  done

  echo ""
  echo "# ── Phase 4: Hook dispatch chain into forwarding path ──"

  for chain in $HOOK_CHAINS; do
    run_or_print iptables -A "$chain" \
      -m connmark ! --mark 0 \
      -j "$DISPATCH_CHAIN"
  done

  echo ""
  echo "# Done. ${#PROTOCOLS[@]} protocols mapped to NFLOG groups."
  echo "# NFLOG groups: $(( 1 + NFLOG_GROUP_OFFSET )) - $(( 467 + NFLOG_GROUP_OFFSET ))"
}

remove_rules() {
  echo "# Removing nDPI iptables rules..."

  for chain in $HOOK_CHAINS; do
    # Remove references to dispatch chain
    while iptables -D "$chain" -m connmark ! --mark 0 -j "$DISPATCH_CHAIN" 2>/dev/null; do :; done
    # Remove NFQUEUE rules
    while iptables -D "$chain" -m mark --mark 0 -j NFQUEUE --queue-num "$NFQUEUE_NUM" --queue-bypass 2>/dev/null; do :; done
    # Remove connmark restore rules
    while iptables -D "$chain" -m connmark ! --mark 0 -j CONNMARK --restore-mark 2>/dev/null; do :; done
  done

  # Flush and delete dispatch chain
  iptables -F "$DISPATCH_CHAIN" 2>/dev/null || true
  iptables -X "$DISPATCH_CHAIN" 2>/dev/null || true

  echo "# Done."
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
  *)
    usage
    ;;
esac
