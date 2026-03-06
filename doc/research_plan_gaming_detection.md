# Research Plan: 100% Detection of Cloud Gaming & Online Gaming Traffic

## Objective

Achieve 100% detection and correct classification of ALL cloud gaming and online gaming traffic in nDPI, with proper QoE categorization:
- **`CLOUD_GAMING`** — Game runs remotely; network carries video/audio streams + input commands (high bandwidth, low latency)
- **`ONLINE_GAMING`** — Game runs locally; network carries game state/events (low bandwidth, low latency)

---

## Part 1: Current nDPI Detection Inventory

### 1.1 Cloud Gaming Services Currently Detected (BUT WRONG QoE)

These exist as protocols in nDPI but are all tagged `ONLINE_GAMING` instead of `CLOUD_GAMING`:

| Protocol | nDPI ID | Detection Method | Domains in nDPI | File Reference |
|---|---|---|---|---|
| GeForce Now | 341 | Hostname match | `nvidiagrid.net`, `gfe.nvidia.com`, `geforcenow.com`, `geforce.com`, `kaizen.nvidia.com`, `dtrace.nvidia.com`, `nvgs.nvidia.com`, `gx.nvidia.com`, `userstore.nvidia.com` | `ndpi_content_match.c.inc:1378-1386` |
| Blacknut | 107 | Hostname match | `blacknut.com` | `ndpi_content_match.c.inc:1521` |
| Boosteroid | 108 | Hostname match | `boosteroid.com` | `ndpi_content_match.c.inc:1524` |

**Immediate fix required:** Reclassify these to `CLOUD_GAMING` QoE category.

### 1.2 Online Gaming Protocols Currently Detected

#### With Dedicated Dissector (`.c` file) — Deep Packet Inspection

| Protocol | nDPI ID | Dissector File | Key Domains |
|---|---|---|---|
| AmongUs | 75 | `among_us.c` | — |
| Xbox | 47 | `xbox.c` | xbox.com, xboxlive.com, xboxservices.com, xboxab.com |
| Playstation | 231 | `playstation.c` | playstation.net, playstation.com, sonyentertainmentnetwork.com |
| Steam | 74 | `steam.c` | steampowered.com, steamcommunity.com, steamcontent.com, steamstatic.com, steamserver.net |
| SteamDatagramRelay | 283 | `steam_datagram_relay.c` | — |
| Armagetron | 162 | `armagetron.c` | — |
| Dofus | 166 | `dofus.c` | ankama.com, ankama-games.com, dofus-touch.com |
| GuildWars2 | 109 | `guildwars2.c` | — |
| Blizzard | 252 | `blizzard.c` | battle.net, blizzard.com, starcraft2.com, blzstatic.com + many CDN subdomains |
| GenshinImpact | 303 | `genshin_impact.c` | — |
| Activision | 305 | `activision.c` | activision.com |
| RakNet | 330 | `raknet.c` | — |
| i3D | 340 | `i3d.c` | — |
| RiotGames | 342 | `riotgames.c` | riotgames.com, pvp.net, riotcdn.net |
| CryNetwork | 358 | `crynet.c` | — |
| Source_Engine | 369 | `source_engine.c` | — |
| Heroes_of_the_Storm | 373 | `hots.c` | — |
| Roblox | 381 | `roblox.c` | roblox.com, rbxcdn.com |
| Yojimbo | 427 | `yojimbo.c` | — |
| TencentGames | 433 | `tencent_games.c` | — |
| GaijinEntertainment | 434 | `gaijin_entertainment.c` | gaijin.net, gaijinent.com, crossout.net, warthunder.com |
| NetEaseGames | 437 | `netease_games.c` | easebar.com |
| PathofExile | 438 | `path_of_exile.c` | pathofexile.com |
| LoLWildRift | 439 | `lol_wild_rift.c` | — |
| CoD_Mobile | 444 | `cod_mobile.c` | codmwest.com |
| EpicGames | 337 | `epicgames.c` | epicgames.com, unrealengine.com, fortnite.com, epicgames.net, epicgames.dev |

#### Hostname-Only Detection (No Dissector — Higher Miss Risk)

| Protocol | nDPI ID | Domains |
|---|---|---|
| WorldOfWarcraft | 67 | worldofwarcraft.com |
| Nexon | 187 | nexon.com, nexoncdn.co.kr, nexon.io |
| Nintendo | 284 | nintendo.net, nintendo.com |
| TocaBoca | 225 | — |
| ElectronicArts | 389 | ea.com, origin-a.akamaihd.net |
| Dota2 | 386 | dota2.com |
| Vivox | 441 | vivox.com |
| RockstarGames | 449 | rockstargames.com, rsg.sc |
| TES_Online | 440 | elderscrollsonline.com |

#### Category-Only Detection (No Protocol ID)

| Domain | Category |
|---|---|
| callofduty.com | GAME |
| king.com | GAME |
| supercell.com | GAME |

#### Game VPN/Boosters (QoE=ONLINE_GAMING)

| Protocol | nDPI ID | Dissector File |
|---|---|---|
| LagoFast | 452 | `lagofast.c` |
| GearUP_Booster | 453 | `gearup_booster.c` |
| Mudfish | 455 | `mudfish.c` |

---

## Part 2: Cloud Gaming Services — Research Required

For each service below, researchers must produce a complete report. See the **Research Template** at the end of this section.

### 2.1 Xbox Cloud Gaming (xCloud) — HIGH PRIORITY

- **Status:** Active
- **Parent Company:** Microsoft
- **Website:** xbox.com/play
- **Why research needed:** The Xbox protocol exists in nDPI but does NOT distinguish xCloud (cloud streaming) from regular Xbox Live (online gaming). These need separate QoE categories.
- **Known domains:** `*.xboxlive.com` (shared with regular Xbox Live), specifically `*.gssv-play-prod.xboxlive.com`, `*.gssv-play-prodxhome.xboxlive.com`, `*.gssv-fastlane-prod.xboxlive.com` for cloud streaming
- **Known protocol:** WebRTC (custom implementation using SCTP Data Channels, DTLS-SRTP handshake, ICE/STUN for NAT traversal)
- **Known ports:** TCP 443 (required); UDP 3074 (Xbox network core); UDP 9002 (console streaming port forward)
- **Known ASN:** AS8075 (Microsoft/Azure)
- **User base:** 20M+ users; 140M+ cumulative streaming hours by GDC 2025

**Research tasks:**
1. Capture PCAP of an xCloud session and a regular Xbox Live gaming session side by side
2. Identify the SNI/hostname patterns that uniquely identify xCloud streaming vs regular Xbox Live
3. Document the WebRTC DTLS fingerprint and STUN/TURN server addresses used
4. Determine if there are unique IP ranges for xCloud streaming servers vs Xbox Live game servers
5. Measure typical bitrate/packet-rate patterns for xCloud (expected: 10-50 Mbps sustained video stream)

### 2.2 PlayStation Plus Cloud Streaming — HIGH PRIORITY

- **Status:** Active (PS Plus Premium tier)
- **Parent Company:** Sony Interactive Entertainment
- **Website:** playstation.com
- **Why research needed:** PlayStation protocol exists but cloud streaming (formerly PS Now) is NOT distinguished from regular PSN gaming.
- **Known domains:** `*.playstation.com`, `*.playstation.net`, `*.sonyentertainmentnetwork.com`
- **Known protocol:** Proprietary low-latency streaming protocol (not publicly documented)
- **Known ports:** TCP 80, 443, 1935, 3478-3480; UDP 3478, 3479, 3658; PS Remote Play: TCP 9295, UDP 9296-9297
- **User base:** PS Plus has 46M+ subscribers; Premium cloud tier is a subset

**Research tasks:**
1. Capture PCAP of a PS Plus Cloud Streaming session vs regular PS online gaming
2. Identify unique hostnames, SNI patterns, or IP ranges for cloud streaming endpoints
3. Document whether PS Remote Play (TCP 9295, UDP 9296-9297) traffic overlaps or is separate
4. Characterize the streaming protocol's packet structure and any distinguishing signatures
5. Determine if RTSP port 1935 is used for cloud streaming signaling

### 2.3 Amazon Luna — HIGH PRIORITY

- **Status:** Active
- **Parent Company:** Amazon (AWS)
- **Website:** luna.amazon.com
- **Why research needed:** Not detected at all in nDPI.
- **Known domains:** `luna.amazon.com`, `*.amazon.com` (shared with all Amazon services — need specific subdomains)
- **Known protocol:** Likely based on Amazon DCV technology (QUIC over port 8443 for DCV); exact Luna protocol not publicly documented
- **Known infrastructure:** AWS (ip-ranges.json published); ASN AS16509, AS14618
- **Available in:** US, UK, Canada, major EU countries

**Research tasks:**
1. Capture PCAP of a Luna gaming session from browser and native app
2. Identify all Luna-specific domains (API, streaming, auth, CDN) — critical since `*.amazon.com` is too broad
3. Determine the streaming protocol: is it WebRTC, QUIC/DCV, or something proprietary?
4. Document port ranges and IP ranges dedicated to Luna streaming servers
5. Identify any distinguishing TLS/DTLS fingerprints or packet signatures
6. Check if Luna uses the same `QUIC port 8443` as Amazon DCV

### 2.4 Shadow PC — MEDIUM PRIORITY

- **Status:** Active
- **Parent Company:** Shadow (formerly Blade; was acquired by OVHcloud, now independent)
- **Website:** shadow.tech
- **Why research needed:** Not detected at all in nDPI. This is a full cloud PC, not just gaming.
- **Known domains:** `shadow.tech`, `pc.shadow.tech`, `eu.shadow.tech`, `support.shadow.tech`, `help.shadow.tech`
- **Known protocol:** Proprietary protocol with UDP (default, "Prefer speed") or TCP ("Prefer stability"); H.265 mode option
- **Known ports:** Outbound TCP/UDP 8001-15299 (updated range; legacy was 8001-11299)
- **Known infrastructure:** OVHcloud datacenters across EU and US

**Research tasks:**
1. Capture PCAP of a Shadow PC session using both UDP and TCP modes
2. Document the exact domain names used during session establishment and streaming
3. Identify the port range and any magic bytes/signatures in the streaming protocol
4. Determine if Shadow uses DTLS or its own encryption for UDP mode
5. Investigate whether Shadow traffic can be distinguished from general OVHcloud traffic

### 2.5 Parsec — MEDIUM PRIORITY

- **Status:** Active (acquired by Unity in 2021)
- **Parent Company:** Unity Technologies
- **Website:** parsec.app
- **Why research needed:** Not detected in nDPI. Very popular for game streaming and remote desktop in enterprise.
- **Known domains:** `parsec.app` and all subdomains; uses AWS S3/CloudFront for distribution
- **Known protocol:** **BUD (Better User Datagrams)** — custom UDP-based protocol with DTLS 1.2 encryption (AES128/AES256); WebRTC for browser clients
- **Known ports:** TCP 443 (backend); UDP random/configurable (default random, can set static; cloud hosting uses UDP 8000); 97% NAT traversal success via UPnP + hole punching
- **Known ASN:** AWS infrastructure (AS16509, AS14618)

**Research tasks:**
1. Capture PCAP of a Parsec streaming session (both native app and browser)
2. Document the BUD protocol DTLS handshake — can we fingerprint it?
3. Identify all `*.parsec.app` subdomains used (STUN servers, signaling, API)
4. Determine if BUD has any identifiable magic bytes in the UDP header
5. Note that AirGPU and Maximum Settings also use Parsec under the hood — same protocol

### 2.6 Steam Remote Play / Steam Link — MEDIUM PRIORITY

- **Status:** Active
- **Parent Company:** Valve Corporation
- **Website:** store.steampowered.com/remoteplay
- **Why research needed:** Steam protocol exists in nDPI with a TODO for Remote Play detection. Steam Remote Play is cloud gaming (video streaming) but currently classified as `ONLINE_GAMING`.
- **Known domains:** `*.steampowered.com`, `*.steamcontent.com`, `*.steamstatic.com` (shared with regular Steam)
- **Known protocol:** Custom low-latency proprietary protocol over UDP
- **Known ports:** UDP 27031-27036 (streaming + discovery); TCP 27036-27037 (streaming); Steam general: UDP 27000-27100, TCP 27015-27050

**Research tasks:**
1. Capture PCAP of a Steam Remote Play session vs regular Steam game download vs regular online game
2. Identify if Steam Remote Play uses different ports or packet patterns than regular Steam
3. Document the UDP 27031-27036 streaming protocol's packet structure
4. Determine if there are SNI/hostname differences for Remote Play relay servers
5. Check the `steam.c` TODO and assess feasibility of distinguishing Remote Play at the DPI level

### 2.7 Moonlight / Sunshine — LOW PRIORITY

- **Status:** Active (open source)
- **Website:** moonlight-stream.org (client); github.com/LizardByte/Sunshine (host)
- **Why research needed:** Not detected. Popular open-source game streaming solution.
- **Known protocol:** NVIDIA GameStream protocol (RTSP + custom Moonlight protocol); DTLS encryption; end-to-end encryption since Sunshine v0.22
- **Known ports:** UDP 47984-48010 (streaming); TCP 47989 (HTTPS control); TCP 47990 (Sunshine Web UI); TCP 47991 (control); TCP 48010 (streaming)

**Research tasks:**
1. Capture PCAP of a Moonlight/Sunshine streaming session
2. Document the RTSP handshake and any identifiable signatures
3. Identify if the port ranges (47984-48010) are distinctive enough for detection
4. Note overlap potential with GeForce Now detection (both use NVIDIA GameStream protocol)

### 2.8 Antstream Arcade — LOW PRIORITY

- **Status:** Active
- **Parent Company:** Antstream Ltd. (UK)
- **Website:** antstream.com
- **Why research needed:** Not detected. Growing user base (700K+ new players in 2025; 200K+ MAU).
- **Known domains:** `antstream.com`

**Research tasks:**
1. Capture PCAP of an Antstream session
2. Identify all domains used (streaming, auth, CDN)
3. Document streaming protocol and ports
4. Assess market relevance for prioritization

### 2.9 Loudplay — LOW PRIORITY

- **Status:** Active
- **Parent Company:** Loudplay (Moscow, Russia)
- **Website:** loudplay.io
- **Known domains:** `loudplay.io`, `future.loudplay.io` (Cloudflare CDN)
- **Known protocol:** Proprietary ultra-low-latency protocol; reportedly TCP-based (unusual); adaptive bitrate

**Research tasks:**
1. Capture PCAP if service is accessible in your region
2. Document domains and streaming protocol
3. Identify ports and packet signatures

### 2.10 NetBoom — LOW PRIORITY

- **Status:** Active
- **Parent Company:** Bifrost Cloud PTE. (Singapore)
- **Website:** netboom.com
- **Known domains:** `netboom.com`, `supernbicloud.com`
- **Focus market:** Southeast Asia mobile cloud gaming
- **Streaming quality:** Up to 4K/60fps, latency as low as 6ms in-region

**Research tasks:**
1. Capture PCAP if service is accessible
2. Document domains, protocol, and ports
3. Focus on mobile traffic patterns

### 2.11 Jio Cloud Gaming (JioGames Cloud) — LOW PRIORITY

- **Status:** Active
- **Parent Company:** Reliance Jio (India)
- **Website:** jiogames.com
- **Known domains:** `jiogames.com`
- **Infrastructure:** Multiple tech partners — Blacknut, Ubitus, Radian Arc, NVIDIA GeForce Now
- **Known ASN:** AS55836 (Reliance Jio)

**Research tasks:**
1. Capture PCAP if accessible (India-only)
2. Determine which backend is used per game (Blacknut vs GeForce Now vs Ubitus)
3. Identify Jio-specific domains vs partner domains

### 2.12 Shutdown/Defunct Services (NO ACTION NEEDED unless traffic still observed)

| Service | Status | Notes |
|---|---|---|
| Google Stadia | Shut down Jan 2023 | Used WebRTC, ports TCP/UDP 44700-44899 |
| Vortex | Shut down ~2022 | vortex.gg |
| Utomik | Shut down early 2025 | utomik.com |
| Nware | Shut down Aug 2023 | playnware.com |
| PlutoSphere | Shut down Mar 2024 | VR cloud streaming |
| Piepacker/Jam.gg | Shut down Jul 2023 | Used Amazon Chime SDK (WebRTC) |
| Playkey | Merged into VK Play Cloud (Jan 2024) | playkey.net redirects to VK Play |
| Gamestream | Acquired by Netgem (Oct 2024) | B2B white-label |

### 2.13 Wrapper Services (Use Parsec/Moonlight underneath — detect at protocol level)

| Service | Backend | Notes |
|---|---|---|
| AirGPU | Parsec or Moonlight | airgpu.com; AWS infrastructure |
| Maximum Settings | Parsec | maximumsettings.com; dedicated cloud PCs |
| Paperspace Gaming | Parsec or Moonlight | paperspace.com; primarily AI/ML, gaming secondary |

---

### Cloud Gaming Research Template

For each service, produce a report in this format:

```
=== SERVICE REPORT ===

Service Name: ___
Status: Active / Shutdown / Beta
Website: ___
Parent Company: ___
Approx. User Base: ___

--- DOMAINS ---
Primary website: ___
Authentication endpoints: ___
Streaming/signaling endpoints: ___
CDN/asset delivery: ___
API endpoints: ___
STUN/TURN servers: ___

--- NETWORK ---
ASN: ___
Known CIDR blocks: ___
Cloud provider: AWS / Azure / GCP / OVH / other
Hosting regions: ___

--- STREAMING PROTOCOL ---
Type: WebRTC / proprietary UDP / proprietary TCP / QUIC / RTSP / other
Signaling mechanism: WebSocket / HTTPS / other
Video codec: H.264 / H.265 / VP9 / AV1 / other
Audio codec: Opus / AAC / other
Encryption: DTLS / SRTP / TLS / custom / other

--- PORTS ---
TCP ports: ___
UDP ports: ___
Port ranges for streaming: ___
Fallback ports: ___

--- TRAFFIC FINGERPRINT ---
Distinctive packet sizes: ___
Typical bitrate (Mbps): ___
Typical packet rate (pps): ___
Any magic bytes in header: ___
TLS/DTLS cipher suites: ___
SNI patterns: ___
Certificate CN/SAN patterns: ___

--- PCAP EVIDENCE ---
[ ] Captured browser session
[ ] Captured native app session
[ ] File location: ___
[ ] Verified detection in nDPI after implementation
```

---

## Part 3: Online Gaming Protocols — Research Required

### 3.1 Ubisoft Connect — HIGH PRIORITY

- **Publisher/Developer:** Ubisoft Entertainment SA (France)
- **Why research needed:** Major publisher, NOT detected in nDPI at all
- **Known domains:** `*.ubisoft.com`, `*.ubi.com`, `ubisoft-connect.com`, `smetrics.ubi.com`, `ubistatic-a.akamaihd.net` (CDN)
- **Known ports:** TCP 80, 443, 13000, 13005, 13200, 14000, 14001, 14008, 14020-14024
- **Protocol:** HTTPS for auth/launcher; game-specific UDP varies per title
- **Anti-cheat:** Varies by title (BattlEye for R6 Siege, EAC for some others)
- **Voice chat:** Vivox
- **Est. MAU:** ~100M+ registered accounts

**Sub-titles to research separately:**
- **Rainbow Six Siege:** UDP 3074, 6015, 10000-10099; BattlEye anti-cheat; Vivox voice; ~10-15M MAU
- **The Division 2:** TCP 13000, 27015, 51000, 55000, 55002; UDP 22000-22032; BattlEye
- **Assassin's Creed (online components):** Research needed
- **For Honor:** Research needed

**Research tasks:**
1. Capture PCAP of Ubisoft Connect launcher login + game session for R6 Siege
2. Document all `*.ubisoft.com` and `*.ubi.com` subdomains observed
3. Identify Ubisoft-specific server IP ranges (if any dedicated ASN)
4. Document the UDP game protocol for Rainbow Six Siege (port 3074 is shared with Xbox/PlayStation — need additional distinguishing marks)

### 3.2 PUBG / KRAFTON — HIGH PRIORITY

- **Publisher/Developer:** KRAFTON (South Korea)
- **Why research needed:** Massive player base, not detected as dedicated protocol
- **Known domains:** `*.playbattlegrounds.com`, `*.pubg.com`; uses Steam infrastructure on PC
- **Known ports (PC):** TCP 27015-27030, 27036-27037 (Steam); UDP 4380, 7080-8000 (game), 27000-27031
- **Protocol:** Custom binary over UDP for gameplay; TCP for matchmaking/auth
- **Anti-cheat:** BattlEye (kernel-level)
- **Voice chat:** Vivox
- **MAU:** PC ~3-5M; total with console ~8-10M

**Research tasks:**
1. Capture PCAP of a PUBG PC session
2. Identify PUBG-specific domains vs Steam infrastructure domains
3. Document the game's UDP protocol — any identifiable header bytes?
4. Note: BattlEye traffic (to `*.battleye.com`) is a detectable sub-signal

### 3.3 PUBG Mobile — HIGH PRIORITY

- **Publisher/Developer:** Lightspeed & Quantum Studio (Tencent) / KRAFTON
- **Why research needed:** 146M MAU — enormous mobile game, not detected
- **Known domains:** `*.pubgmobile.com`; Tencent Cloud infrastructure
- **Known IP ranges:** Tencent Cloud IPs (e.g., 162.62.x.x range)
- **Known ports:** TCP 10012, 17500; UDP 10010, 10013, 10039, 10096, 10491, 10612, 11455, 12235, 13748, 13894, 13972, 20000-20002
- **Anti-cheat:** Tencent ACE (Anti-Cheat Expert) + proprietary server-side
- **Voice chat:** Built-in (Tencent proprietary)

**Research tasks:**
1. Capture PCAP of PUBG Mobile session on WiFi
2. Identify all Tencent Cloud domains and IPs used
3. Document the UDP game protocol and port patterns
4. Note: wide port scatter (10000-20000 range) is itself a potential fingerprint

### 3.4 Minecraft — MEDIUM PRIORITY

- **Publisher/Developer:** Mojang Studios / Microsoft
- **Why research needed:** 225M MAU — one of the largest games ever, not detected as dedicated protocol
- **Known domains:** `*.minecraft.net`, `*.mojang.com`, Xbox Live/Microsoft auth domains
- **Java Edition:** TCP 25565 (default). Custom binary protocol over TCP. Handshake packet starts with varint packet length + `0x00` (handshake ID).
- **Bedrock Edition:** UDP 19132 (IPv4), 19133 (IPv6). Uses **RakNet** protocol library. RakNet magic bytes: `0x00ffff00fefefefefdfdfdfd12345678`
- **No kernel anti-cheat.** Server-side only; third-party plugins.
- **No built-in voice chat.** Players use Discord.

**Research tasks:**
1. Capture PCAP of Java Edition server connection (TCP 25565)
2. Capture PCAP of Bedrock Edition server connection (UDP 19132)
3. Verify the RakNet magic bytes for Bedrock — note that nDPI already has `raknet.c`, so check if Minecraft Bedrock is already caught by that
4. Document the Java Edition handshake signature for a potential dissector
5. Identify all `*.minecraft.net` and `*.mojang.com` domains

### 3.5 Final Fantasy XIV — MEDIUM PRIORITY

- **Publisher/Developer:** Square Enix (Japan)
- **Why research needed:** Major MMO, not detected
- **Known domains:** `*.finalfantasyxiv.com`, `*.square-enix.com`, `*.ffxiv.com`
- **Known IP ranges:** 202.67.48.0/20 (Square Enix JP), 219.117.144.0/20
- **Known ports:** TCP 80, 443, 8080, 55296-55551; UDP 55296-55551; Alt: 32300-32303 TCP
- **Protocol:** Custom binary over TCP/UDP; HTTPS for launcher/auth
- **No kernel anti-cheat.** Server-side detection only.

**Research tasks:**
1. Capture PCAP of FFXIV launcher login + gameplay session
2. Document the custom binary protocol on TCP 55296-55551
3. Identify all Square Enix domains used
4. Verify the IP ranges (202.67.48.0/20, 219.117.144.0/20)

### 3.6 Valorant — MEDIUM PRIORITY

- **Publisher/Developer:** Riot Games (Parent: Tencent)
- **Why research needed:** Riot Games protocol exists in nDPI, but Valorant has distinct traffic patterns and Vanguard anti-cheat generates unique traffic
- **Known domains:** `*.riotgames.com` (already detected), `*.valorantgame.com`, `*.playvalorant.com`
- **Known ASN:** AS6507 (Riot Games NA), AS62830; IP range: 104.160.128.0/19
- **Known ports:** TCP 80, 443, 2099, 5222-5223, 8088, 8393-8400, 8446; UDP 3478-3480, 7000-8000, 8180-8181
- **Anti-cheat:** Riot Vanguard (kernel-level, always-on driver)
- **Voice chat:** Vivox
- **MAU:** ~25-35M

**Research tasks:**
1. Verify that `*.valorantgame.com` and `*.playvalorant.com` are caught by existing Riot Games detection
2. If not, add these domains to Riot Games content match
3. Document Vanguard's network signature if it has distinct traffic
4. Identify any Valorant-specific UDP port patterns (7000-8000)

### 3.7 League of Legends (PC) — MEDIUM PRIORITY

- **Publisher/Developer:** Riot Games (Parent: Tencent)
- **Why research needed:** 131M MAU — Riot Games detection exists, but LoL-specific traffic verification needed
- **Known domains:** `*.riotgames.com` (already detected), `*.leagueoflegends.com`
- **Known ASN:** AS6507, AS62830 (shared Riot infrastructure)
- **Known ports:** TCP 80, 443, 2099, 5222-5223, 8393-8400; UDP 5000-5500 (game client), 8088 (spectator)
- **Voice chat:** Vivox (League Voice)

**Research tasks:**
1. Verify `*.leagueoflegends.com` is caught by existing Riot Games detection
2. Document LoL-specific UDP game traffic on ports 5000-5500
3. Compare with LoL Wild Rift (already detected as separate protocol)

### 3.8 Destiny 2 — MEDIUM PRIORITY

- **Publisher/Developer:** Bungie / Sony Interactive Entertainment
- **Why research needed:** Not detected. 5-10M MAU.
- **Known domains:** `*.bungie.net`, `*.bungie.com`, `*.battleye.com` (anti-cheat)
- **Known ports:** TCP 80, 443, 1119-1120, 3074, 3724; UDP 3074, 3097, 4380, 27000-27031
- **Protocol:** Hybrid P2P + dedicated server; UDP for gameplay/P2P
- **Anti-cheat:** BattlEye (kernel-level)

**Research tasks:**
1. Capture PCAP of Destiny 2 session
2. Document `*.bungie.net` subdomains
3. Identify the P2P UDP protocol signatures
4. Note port 3074 UDP is shared with Xbox — need to distinguish

### 3.9 Apex Legends — MEDIUM PRIORITY

- **Publisher/Developer:** Respawn Entertainment / Electronic Arts
- **Why research needed:** EA protocol exists but Apex may have unique endpoints. 20-22M MAU.
- **Known domains:** `*.ea.com` (already partially detected), `*.respawn.com`, `download.eac-cdn.com`
- **Known ports:** TCP 80, 443, 1024-1124, 3216, 9960-9969, 18000, 18060, 18120, 27900, 28910, 29900; UDP 1024-1124, 18000, 29900, 37000-40000
- **Key game traffic:** UDP 37015, 37115, 37215 (primary game server ports observed)
- **Protocol:** Source Engine derivative; UDP for gameplay
- **Anti-cheat:** EasyAntiCheat (EAC)

**Research tasks:**
1. Verify that `*.respawn.com` is caught by EA detection — if not, add it
2. Document the Source Engine derivative protocol on UDP 37015/37115/37215
3. Identify Apex-specific server IP ranges

### 3.10 Garena Free Fire — MEDIUM PRIORITY

- **Publisher/Developer:** 111 Dots Studio / Garena (Sea Group, Singapore)
- **Why research needed:** Not detected. 110-130M MAU — one of the biggest mobile games.
- **Known domains:** `*.garena.com`, `*.ff.garena.com`
- **Known ports:** UDP 1513 (primary game port); TCP 1513 (auth/session)
- **Protocol:** Custom binary; UDP for real-time gameplay
- **Anti-cheat:** Proprietary server-side + AI behavior monitoring

**Research tasks:**
1. Capture PCAP of Free Fire session on WiFi
2. Document all Garena domains
3. Identify the UDP 1513 protocol signature
4. Assess if other Garena games (e.g., AOV SEA version) share the same infrastructure

### 3.11 Supercell Games (Brawl Stars / Clash Royale / Clash of Clans) — MEDIUM PRIORITY

- **Publisher/Developer:** Supercell (Finland; majority owned by Tencent)
- **Why research needed:** Currently only category-tagged (no protocol ID). Combined 200M MAU.
- **Known domains:** `game.clashofclans.com`, `*.brawlstarsgame.*`, `*.clashroyaleapp.*`, `service.supercell.net`, `clashroyale.com`, `brawlstars.com`, `clashofclans.com`, `supercell.com`
- **Infrastructure:** AWS (`*.amazonaws.com`)
- **Known ports:** TCP 9339 (primary game port, all titles), TCP 80
- **Protocol signature:** Binary protocol over TCP 9339. Known message IDs: ClientHello=10100, Login=10101, LoginOk=20104, OwnHomeData=24101. AES-encrypted payloads (public key exchange).
- **MAU:** Clash of Clans ~95-99M, Brawl Stars ~50-73M, Clash Royale ~20-30M

**Research tasks:**
1. Capture PCAP of a Clash of Clans or Brawl Stars session
2. Verify the TCP 9339 port pattern and binary protocol structure
3. Document the ClientHello (10100) message signature — can we detect this at DPI level?
4. Identify all Supercell domain names
5. Consider: should this be one "Supercell" protocol or per-game protocols?

### 3.12 HoYoverse / miHoYo (Honkai: Star Rail, Zenless Zone Zero) — MEDIUM PRIORITY

- **Publisher/Developer:** miHoYo / HoYoverse / Cognosphere
- **Why research needed:** Genshin Impact IS detected, but sister games share infrastructure and are not explicitly covered. Combined ~25-40M MAU across all titles.
- **Known domains:** `*.mihoyo.com`, `*.hoyoverse.com`, `*.yuanshen.com` (Genshin), `api-os-takumi.mihoyo.com`, `hk4e-sdk-os.mihoyo.com`
- **Infrastructure:** Alibaba Cloud (47.245.x.x, 8.211.x.x ranges)
- **Known ports:** UDP 22101-22109 (gameplay); TCP 443 (auth/API/patching)
- **Anti-cheat:** mhyprot2.sys / HoYoKProtect (kernel-level driver)

**Research tasks:**
1. Verify that Honkai: Star Rail traffic matches the Genshin Impact detection in nDPI
2. Capture PCAP of HSR and ZZZ sessions
3. Document if they use the same UDP 22101-22109 range
4. Identify any game-specific domains not under `*.mihoyo.com`

### 3.13 GTA Online / Red Dead Online (Rockstar) — MEDIUM PRIORITY

- **Publisher/Developer:** Rockstar Games / Take-Two Interactive
- **Why research needed:** Rockstar is hostname-only detection. P2P protocol needs DPI. 18.3M MAU for GTA Online.
- **Known domains:** `*.rockstargames.com`, `socialclub.rockstargames.com` (already partially detected)
- **Known ASN:** AS46555 (Take-Two Interactive); IP: 104.255.105.0/24, 104.255.106.0/24, 192.81.241.0/24
- **Known ports:** TCP 80, 443; UDP 6672, 61455-61458; Voice: UDP 6500-6505
- **Protocol:** P2P; UDP for gameplay; HTTPS for Social Club auth

**Research tasks:**
1. Capture PCAP of GTA Online session
2. Document the P2P UDP protocol on ports 6672, 61455-61458
3. Identify any packet signatures in the P2P protocol
4. Verify the IP ranges (AS46555)

### 3.14 Overwatch 2 / Diablo IV (Blizzard) — LOW PRIORITY

- **Why research needed:** Blizzard is already well-detected. These may need game-specific domain additions.
- **Known ASN:** AS57976 (Blizzard EU), AS32163 (Blizzard NA); IPs: 24.105.0.0/18, 37.244.0.0/18, 137.221.64.0/18, 5.42.160.0/19, 158.115.192.0/19
- **OW2 ports:** TCP 1119, 3724, 6113; UDP 3478-3479, 5060, 5062, 6250, 12000-64000
- **Diablo IV ports:** TCP 1119; UDP 1119, 6120

**Research tasks:**
1. Verify that all OW2 and D4 traffic is caught by existing Blizzard detection
2. If any domains are missed, add them

### 3.15 Escape from Tarkov — LOW PRIORITY

- **Publisher/Developer:** Battlestate Games (Russia)
- **Why research needed:** Not detected. Niche but dedicated player base (2-4M MAU).
- **Known domains:** `escapefromtarkov.com`, `profile.tarkov.com`, `arena.tarkov.com`, `status.escapefromtarkov.com`
- **Server providers:** LeaseWeb, G-Core Labs, OVH (multi-provider)
- **Known ports:** TCP 80, 443, 11007, 31780; UDP 17000-17025
- **Anti-cheat:** BattlEye (kernel-level)

**Research tasks:**
1. Capture PCAP of a Tarkov session
2. Document all BSG domains
3. Identify the UDP 17000-17025 game protocol

### 3.16 Lost Ark / New World (Amazon Games) — LOW PRIORITY

- **Lost Ark:** Smilegate RPG (dev) / Amazon Games (publisher). Game ports: 18887-18903. EAC anti-cheat. Vivox voice. ~1-2M MAU.
- **New World:** Amazon Games. UDP inbound 27000-27050; outbound 20000-59999. EAC. Vivox. ~500K-1M MAU.
- **Known domains:** `*.playlostark.com`, `*.newworld.com`, `*.amazongames.com`, `client.easyanticheat.net`

**Research tasks:**
1. Capture PCAPs of both games
2. Identify Amazon Games-specific domains vs general AWS domains
3. Document game-specific port patterns

### 3.17 Mobile Legends: Bang Bang — LOW PRIORITY

- **Publisher/Developer:** Moonton (Parent: ByteDance, China)
- **Known domains:** `*.mobilelegends.com`, `*.moonton.com`
- **Known ports:** TCP 30097-30147 (game range within 30000-30999)
- **MAU:** ~25-37M

**Research tasks:**
1. Capture PCAP on WiFi
2. Document domains and TCP port pattern

### 3.18 Rocket League — LOW PRIORITY

- **Publisher/Developer:** Psyonix / Epic Games
- **Known domains:** `*.epicgames.com` (may already be caught), `*.rocketleague.com`
- **Known ports:** TCP 80, 443, 27015-27030; UDP 3074, 3478-3479, 4380, 7000-9000, 27000-27031
- **Key game traffic:** UDP 7700-7800 range observed
- **MAU:** ~90-100M (including Sideswipe mobile)

**Research tasks:**
1. Verify `*.rocketleague.com` is caught by Epic Games detection
2. Document UDP 7700-7800 game traffic

### 3.19 Wuthering Waves (Kuro Games) — LOW PRIORITY

- **Known domains:** `*.aki-game.com`, `wutheringwaves.kurogames.com`
- **Protocol:** Unreal Engine 4; HTTPS for auth/API; UDP likely for co-op gameplay
- **Anti-cheat:** Tencent ACE
- **MAU:** ~5-10M

### 3.20 Arena of Valor / Honor of Kings (Tencent/TiMi) — LOW PRIORITY

- **Known domains:** `*.arenaofvalor.com`, Tencent infrastructure
- **Protocol:** Custom binary with AES-CBC encryption. IV: `000102030405060708090a0b0c0d0e0f`
- **Anti-cheat:** Tencent ACE (kernel-level on PC)
- **MAU:** AoV ~10-15M international; Honor of Kings ~200M+ in China

**Research tasks:**
1. Capture PCAP if accessible
2. Document the AES-CBC encrypted protocol pattern

---

### Online Gaming Research Template

For each game/platform, produce a report in this format:

```
=== GAME REPORT ===

Game/Platform Name: ___
Publisher: ___
Developer: ___
Parent Company: ___
Status: Active / Shutdown / Beta
Approx. MAU: ___

--- DOMAINS ---
Game launcher/auth: ___
Game servers: ___
CDN/patching: ___
Matchmaking: ___
Anti-cheat: ___
Voice chat: ___

--- NETWORK ---
ASN (if dedicated): ___
Known IP ranges: ___
Server hosting provider: ___

--- GAME PROTOCOL ---
Transport: TCP / UDP / both
Game traffic ports: ___
Auth/login ports: ___
Protocol type: Custom binary / RakNet / Source Engine / Unreal / other
Encryption: None / AES / TLS / DTLS / other
Any magic bytes/signatures: ___
Packet size patterns: ___

--- ANTI-CHEAT ---
System: BattlEye / EAC / Vanguard / ACE / Warden / other / none
Network traffic: (does the anti-cheat generate identifiable network traffic?)
Domains: ___

--- VOICE CHAT ---
System: Vivox / Discord / proprietary / none
Domains: ___
Ports: ___

--- PCAP EVIDENCE ---
[ ] Captured launcher session
[ ] Captured gameplay session
[ ] File location: ___
[ ] Verified detection in nDPI after implementation
```

---

## Part 4: Cross-Cutting Systems to Detect

These middleware/infrastructure systems are used by many games. Detecting them helps with classification even when the specific game is unknown.

### 4.1 Anti-Cheat Systems

| System | Owner | Used By | Detectable Domains | Notes |
|---|---|---|---|---|
| **BattlEye** | BattlEye Innovations | PUBG, Destiny 2, R6 Siege, Division 2, Tarkov, Fortnite, DayZ, Arma | `*.battleye.com` | Kernel-level driver (BEDaisy.sys). RCon protocol: 7-byte header `0x42 0x45 [4-byte CRC32] 0xFF`. |
| **EasyAntiCheat (EAC)** | Epic Games | Apex, Fortnite, Lost Ark, New World, Fall Guys, Hunt, Dead by Daylight, Rust | `client.easyanticheat.net`, `download.eac-cdn.com`, `download-alt.easyanticheat.net` | User-mode + kernel components. HTTP/HTTPS communication. |
| **Riot Vanguard** | Riot Games | Valorant, League of Legends | (uses Riot's own network) | Kernel-level, always-on at boot. |
| **Tencent ACE** | Tencent | PUBG Mobile, Arena of Valor, Wuthering Waves, NIKKE, Tower of Fantasy | Tencent backend | Kernel-level (PC); deep hooks (mobile). |
| **HoYoKProtect/mhyprot2** | miHoYo | Genshin Impact, Honkai: Star Rail, ZZZ | (uses game's own connection) | Kernel-mode driver. CVE-2020-36603. |
| **Blizzard Warden** | Blizzard | OW2, D4, WoW, StarCraft | (uses Battle.net connection) | User-mode (OW2 added kernel component). |
| **EA Anti-Cheat (EAAC)** | EA | EA Sports FC, Battlefield, Madden, F1 | (uses EA's own network) | Kernel-level since 2022. 28M+ players protected. |
| **Nexon Game Security (NGS)** | Nexon | MapleStory, other Nexon titles | (uses game's own connection) | User-mode with rootkit-like behavior. DLL: `NGClient.dll`. |

**Research tasks:**
1. For BattlEye: Capture the `0x42 0x45` RCon protocol header and verify it's detectable
2. For EAC: Document all `*.easyanticheat.net` subdomains
3. Assess: Should anti-cheat traffic be its own protocol or sub-classified under the game?

### 4.2 Voice Chat Middleware

| System | Owner | Used By | Detection Status |
|---|---|---|---|
| **Vivox** | Unity | Valorant, LoL, PUBG, R6 Siege, Fortnite, Lost Ark, New World | Already detected (`vivox.com`) but hostname-only |
| **Discord** | Discord Inc. | Many games use Discord overlay/voice | Already detected as separate protocol |

**Research tasks:**
1. Expand Vivox domain coverage — document all `*.vivox.com` subdomains
2. Determine if Vivox UDP traffic has identifiable signatures for DPI-level detection

### 4.3 Game Networking Libraries

| Library | Used By | Detection in nDPI |
|---|---|---|
| **RakNet** | Minecraft Bedrock, many Unity games | Already detected (`raknet.c`). Magic: `0x00ffff00fefefefefdfdfdfd12345678` |
| **Source Engine** | CS2, TF2, Apex (derivative), many Valve games | Already detected (`source_engine.c`) |
| **CryNetwork** | Hunt: Showdown, Crysis series | Already detected (`crynet.c`) |
| **Yojimbo** | Various indie games | Already detected (`yojimbo.c`) |

**No additional research needed** for these unless specific games are missed.

---

## Part 5: Detection Gaps in Existing Protocols

### 5.1 Protocols with Thin Domain Coverage

These detected protocols have very few domains and may miss traffic:

| Protocol | Current Domains | Likely Missing | Action |
|---|---|---|---|
| ElectronicArts | ea.com, origin-a.akamaihd.net | `*.respawn.com`, `*.easports.com`?, `ea-api.arkoselabs.com`? | Research and expand |
| Dota2 | dota2.com | Uses Steam infrastructure — may need more domains | Research |
| Vivox | vivox.com | All subdomains used by Vivox SDK | Research |
| NetEaseGames | easebar.com | `*.163.com` game subdomains? | Research |
| CoD_Mobile | codmwest.com | Other regional domains? | Research |
| Blacknut | blacknut.com | `blacknut.biz` (B2B), CDN/streaming endpoints | Research and expand |
| Boosteroid | boosteroid.com | `cloud.boosteroid.com`, `*.cloud.boosteroid.com`, `help.boosteroid.com` | Research and expand |
| GeForceNow | 9 domains listed | `play.geforcenow.com`, `*.gdn.nvidia.com`, `*.sdk.nvidia.com` | Research and expand |
| Activision | activision.com | `callofduty.com` (currently category-only!), `*.activision.com` subdomains | Fix: move callofduty.com to Activision protocol |

### 5.2 Hostname-Only Protocols (Risk: Missed if No SNI)

These protocols have NO DPI dissector — if a connection uses IP-only (no SNI/hostname), it will be **completely missed**:

| Protocol | Has Dissector? | Risk Level | Recommendation |
|---|---|---|---|
| ElectronicArts | No | HIGH | Need dissector or IP ranges |
| Dota2 | No | MEDIUM | Covered by Steam dissector for gameplay |
| Vivox | No (has IP ranges) | LOW | IP ranges help |
| RockstarGames | No | HIGH | Need IP ranges (AS46555) |
| GeForceNow | No | HIGH | Need IP ranges or streaming protocol fingerprint |
| Blacknut | No | MEDIUM | Need streaming protocol fingerprint |
| Boosteroid | No | MEDIUM | Need streaming protocol fingerprint |
| WorldOfWarcraft | No | LOW | Covered by Blizzard dissector |
| TES_Online | No | MEDIUM | Need dissector or IP ranges |

---

## Part 6: Implementation Priority Matrix

After research is complete, implement in this order:

### P0 — Immediate Fixes (No Research Needed)

1. Reclassify GeForce Now, Blacknut, Boosteroid to `CLOUD_GAMING` QoE
2. Move `callofduty.com` from category-only to Activision protocol

### P1 — High Priority (Research + Implement)

| # | Protocol | Type | Est. MAU | Rationale |
|---|---|---|---|---|
| 1 | Xbox Cloud Gaming (xCloud) | Cloud | 20M+ | Must distinguish from Xbox Live |
| 2 | PlayStation Cloud Streaming | Cloud | Subset of 46M | Must distinguish from PSN |
| 3 | Amazon Luna | Cloud | Unknown | Major platform, zero detection |
| 4 | Ubisoft Connect | Online | 100M+ | Major publisher, zero detection |
| 5 | PUBG / PUBG Mobile | Online | 150M+ combined | Massive MAU, zero detection |
| 6 | Supercell (CoC/BS/CR) | Online | 200M | Only category-tagged |

### P2 — Medium Priority

| # | Protocol | Type | Est. MAU |
|---|---|---|---|
| 7 | Shadow PC | Cloud | 100K+ |
| 8 | Parsec | Cloud | Millions |
| 9 | Steam Remote Play | Cloud | Part of 130M |
| 10 | Minecraft | Online | 225M |
| 11 | Final Fantasy XIV | Online | 1-3M |
| 12 | Garena Free Fire | Online | 110-130M |
| 13 | Valorant domain expansion | Online | 25-35M |
| 14 | HoYoverse expansion | Online | 25-40M |
| 15 | GTA Online DPI | Online | 18M |
| 16 | Destiny 2 | Online | 5-10M |

### P3 — Low Priority

| # | Protocol | Type | Est. MAU |
|---|---|---|---|
| 17 | Moonlight/Sunshine | Cloud | OSS community |
| 18 | Antstream Arcade | Cloud | 200K |
| 19 | Loudplay | Cloud | Unknown |
| 20 | NetBoom | Cloud | Unknown |
| 21 | Escape from Tarkov | Online | 2-4M |
| 22 | Lost Ark / New World | Online | 1-2M |
| 23 | Mobile Legends | Online | 25-37M |
| 24 | Rocket League domain check | Online | 90-100M |
| 25 | Wuthering Waves | Online | 5-10M |
| 26 | Arena of Valor | Online | 10-15M |

---

## Part 7: Key ASN Reference

These ASNs are associated with gaming companies and should be investigated for IP range-based detection:

| Entity | ASN | Notable Ranges | Notes |
|---|---|---|---|
| Riot Games | AS6507, AS62830 | 104.160.128.0/19 | Well-documented |
| Blizzard | AS57976, AS32163 | 24.105.0.0/18, 37.244.0.0/18, 137.221.64.0/18, 5.42.160.0/19, 158.115.192.0/19 | Extensive |
| Take-Two/Rockstar | AS46555 | 104.255.105.0/24, 104.255.106.0/24, 192.81.241.0/24 | Small ranges |
| NVIDIA | AS11414 | Various | GeForce Now streaming servers |
| Square Enix | (own ranges) | 202.67.48.0/20, 219.117.144.0/20 | Japan-based |
| Microsoft/Azure | AS8075 | (very large) | xCloud runs on Azure |
| Amazon/AWS | AS16509, AS14618 | (very large — use ip-ranges.json) | Luna, Lost Ark, New World |
| HoYoverse/Alibaba | (Alibaba Cloud) | 47.245.x.x, 8.211.x.x | Genshin, HSR, ZZZ |
| Tencent Cloud | (various) | 162.62.x.x (observed for PUBG Mobile) | Many Tencent games |
| Reliance Jio | AS55836 | — | Jio Cloud Gaming |
| Supercell | (hosted on AWS) | No dedicated ASN | Use domain detection |

---

## Part 8: How to Capture PCAPs

### Equipment Needed
- PC with Wireshark or tcpdump
- Mobile device on WiFi (for mobile games)
- Accounts on the gaming services to test
- VPN access to different regions (some services are region-locked)

### Capture Procedure
1. Start capture on the network interface
2. Launch the game/service and perform a full session:
   - Login/authentication
   - Matchmaking/lobby
   - Active gameplay (minimum 2 minutes)
   - Voice chat (if supported)
   - Logout/disconnect
3. Stop capture
4. Filter out non-game traffic (optional, but helpful)
5. Save as `.pcap` or `.pcapng`

### Naming Convention
```
<service_name>_<date>_<platform>.pcap
```
Examples:
- `amazon_luna_20260306_chrome.pcap`
- `pubg_mobile_20260306_android_wifi.pcap`
- `xcloud_20260306_edge_browser.pcap`

### What to Document Per PCAP
- Date and time of capture
- Platform (PC/mobile/browser)
- Geographic region
- Network type (WiFi/LAN/5G)
- Game mode played
- Duration of session
- Any notable observations (e.g., "used UDP port X for all gameplay")

---

## Appendix: nDPI Implementation Checklist (For Developers After Research)

For each new or corrected protocol, the implementation requires:

1. **Protocol ID** — Add to `src/include/ndpi_protocol_ids.h` (new protocols only)
2. **Protocol defaults** — Add `ndpi_set_proto_defaults()` in `src/lib/ndpi_main.c` with correct:
   - Category: `NDPI_PROTOCOL_CATEGORY_GAME`
   - QoE: `NDPI_PROTOCOL_QOE_CATEGORY_CLOUD_GAMING` or `ONLINE_GAMING`
3. **Domain patterns** — Add to `src/lib/ndpi_content_match.c.inc`
4. **IP ranges** — Add to `src/lib/ndpi_content_match.c.inc` (if known dedicated ranges)
5. **DPI dissector** — Create `src/lib/protocols/<name>.c` (if protocol-level detection possible)
6. **TLS patterns** — Add to TLS certificate match table if applicable
7. **Documentation** — Add entry to `doc/protocols.rst`
8. **Test PCAP** — Add to `tests/pcap/` with expected output in `tests/cfgs/default/result/`

### Build & Verify
```bash
./autogen.sh && ./configure && make
cd tests && ./do.sh
```
