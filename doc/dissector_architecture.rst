Dissector Architecture and Internals
======================================

This document describes the internal architecture of nDPI's packet processing
and protocol classification engine. It is aimed at developers who want to
understand how classification works, or who want to write new protocol
dissectors.

Overview
========

Every captured packet passes through a multi-stage pipeline before nDPI
produces a classification result. The stages are:

.. code-block:: text

    Raw Packet (from pcap / DPDK / PF_RING)
             |
             v
    +--------------------+
    | Link-Layer Decode  |  example/reader_util.c
    | DLT dispatch,      |  ndpi_workflow_process_packet()
    | VLAN/MPLS strip,   |
    | tunnel decap       |
    +--------------------+
             |
             |  Extracted: IP header pointer + offset
             v
    +--------------------+
    | Flow Lookup /      |  example/reader_util.c
    | Creation           |  get_ndpi_flow_info()
    +--------------------+
             |
             |  ndpi_flow_struct allocated or found
             v
    +--------------------+
    | Core Detection     |  src/lib/ndpi_main.c
    | Engine             |  ndpi_detection_process_packet()
    |  - Packet parsing  |
    |  - Conn tracking   |
    |  - Port guess      |
    |  - Dissector call  |
    +--------------------+
             |
             |  detected_protocol_stack[0..1]
             v
    +--------------------+
    | Post-Processing    |  Category, breed, risks
    +--------------------+
             |
             v
    Classification Result (ndpi_protocol)

The link-layer decoder and flow table live in the **example application**
(``example/reader_util.c``), not in the library itself. Applications that
integrate nDPI replace these with their own implementations. The library
boundary is ``ndpi_detection_process_packet()``, which accepts a raw IP packet
and returns a classification.


Link-Layer Decoding
===================

The link-layer (LL) decoder takes a raw captured frame and strips away
data-link headers to expose the IP packet underneath. The reference
implementation lives in ``ndpi_workflow_process_packet()``
(``example/reader_util.c:2175``).

Supported DLT Types
--------------------

The function ``ndpi_is_datalink_supported()`` (``example/reader_util.c:2037``)
lists the link types the decoder can handle:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - DLT Constant
     - Header Size
     - Description
   * - ``DLT_EN10MB``
     - 14 bytes
     - Standard Ethernet (IEEE 802.3 / DIX)
   * - ``DLT_LINUX_SLL``
     - 16 bytes
     - Linux cooked capture v1
   * - ``LINKTYPE_LINUX_SLL2``
     - 20 bytes
     - Linux cooked capture v2
   * - ``DLT_NULL``
     - 4 bytes
     - BSD loopback (address family field)
   * - ``DLT_RAW``
     - 0 bytes
     - Raw IP; version detected from first nibble
   * - ``DLT_PPP``
     - 4 bytes
     - Point-to-Point Protocol
   * - ``DLT_PPP_SERIAL``
     - 4 bytes
     - Cisco PPP in HDLC-like framing
   * - ``DLT_C_HDLC``
     - 4 bytes
     - Cisco HDLC
   * - ``DLT_IEEE802_11_RADIO``
     - Variable
     - WiFi with Radiotap header
   * - ``DLT_PPI``
     - Variable
     - Per-Packet Information wrapper
   * - ``DLT_IPV4`` / ``DLT_IPV6``
     - 0 bytes
     - Raw IPv4 or IPv6 (no link header)

To add a new DLT type, add a ``case`` to both ``ndpi_is_datalink_supported()``
and the DLT switch inside ``ndpi_workflow_process_packet()``. The comment in
the source says *"Keep in sync"* -- both must list the same types.

The Goto-Based State Machine
-----------------------------

The decoder uses three ``goto`` labels as re-entry points. This allows
arbitrary nesting of layers (for example, Ethernet inside VXLAN inside UDP
inside IP inside Ethernet) without recursive function calls.

.. code-block:: text

    datalink_check:         <--- re-enter here for tunnels wrapping a full frame
        |                        (VXLAN, TZSP, PPI, GRE-with-Ethernet)
        |
        DLT_* switch
        Extracts: type (ethertype) and ip_offset
        |
        v
    ether_type_check:       <--- re-enter here for stacked L2 tags
        |                        (nested VLANs, MPLS labels, PPPoE)
        |
        Ethertype switch
        0x8100 VLAN, 0x8847 MPLS, 0x8864 PPPoE,
        0x0800 IPv4, 0x86DD IPv6
        |
        v
    iph_check:              <--- re-enter here for IP-in-IP and tunnel payloads
        |                        (GTP-U, GRE-with-IP, CAPWAP, IP-in-IP)
        |
        Validate IP header
        Detect and decapsulate tunnels
        |
        v
    packet_processing()  -->  ndpi_detection_process_packet()

Every DLT handler must set two variables before falling through:

- ``type`` -- the ethertype (e.g. ``0x0800`` for IPv4, ``0x86DD`` for IPv6)
- ``ip_offset`` -- byte offset where the IP header begins

VLAN, MPLS, and PPPoE Stripping
---------------------------------

After the DLT handler extracts an ethertype, the ``ether_type_check`` label
dispatches on it. Some ethertypes are *not terminal* -- they wrap another layer
that must be peeled off:

**VLAN (802.1Q, ethertype 0x8100):** Read the 12-bit VLAN ID, advance
``ip_offset`` by 4 bytes, read the next ethertype, and loop back to
``ether_type_check``. A ``while`` loop handles QinQ (double-tagged) frames.

**MPLS (ethertype 0x8847/0x8848):** Walk the label stack (each label is 4
bytes). The bottom-of-stack bit (S=1) marks the last label. Advance
``ip_offset`` past all labels, assume IPv4, and loop back.

**PPPoE (ethertype 0x8864):** Skip the 8-byte PPPoE header, assume IPv4, and
loop back.

Tunnel Decapsulation
---------------------

After IP header validation at the ``iph_check`` label, the decoder checks for
tunnel protocols if ``workflow->prefs.decode_tunnels`` is enabled:

.. list-table::
   :header-rows: 1
   :widths: 20 20 20 40

   * - Tunnel
     - Detection
     - Re-entry Label
     - Description
   * - GTP-U
     - UDP port 2152
     - ``iph_check``
     - GPRS Tunneling; inner IP extracted
   * - VXLAN
     - UDP port 4789 + I-flag
     - ``datalink_check``
     - Inner Ethernet frame; full LL decode restarts
   * - GRE
     - IP protocol 47
     - ``iph_check`` or ``datalink_check``
     - Depends on GRE payload type (IP vs Ethernet)
   * - CAPWAP
     - UDP port 5247
     - ``iph_check``
     - Wireless AP tunneling with 802.11 header
   * - TZSP
     - UDP port 37008
     - ``datalink_check``
     - Tethered sniffer protocol; inner frame
   * - IP-in-IP
     - IP protocol 4 or 41
     - ``iph_check``
     - IPv4-in-IPv4 or IPv6-in-IPv4

The ``tunnel_type`` variable (an ``ndpi_packet_tunnel`` enum) records which
tunnel was detected and is passed through to the flow record.


Flow Management
===============

Flow Table Structure
---------------------

The example application maintains a **hash-of-binary-trees**: 512 buckets
(configurable via ``workflow->prefs.num_roots``), each containing a binary
search tree. The flow key is a 5-tuple:

- Source IP, Destination IP
- Source Port, Destination Port
- L4 Protocol (TCP / UDP / ICMP / ...)
- VLAN ID (optionally ignored)

The hash is a simple sum:
``protocol + ntohl(src_ip) + ntohl(dst_ip) + ntohs(src_port) + ntohs(dst_port)``.
The bucket index is ``hashval % num_roots``.

Flows are **bidirectional**: if a lookup with (src, dst) fails, the function
swaps source and destination and tries again. Both directions of a connection
share a single ``ndpi_flow_info`` and a single ``ndpi_flow_struct``.

Per-Flow Statistics
--------------------

Before calling the detection engine, ``packet_processing()``
(``example/reader_util.c:1764``) updates per-flow counters on every packet:

- Byte and packet counts per direction (``src2dst_packets``, ``dst2src_bytes``, etc.)
- Goodput bytes (payload only, excluding headers)
- TCP flag histogram (SYN, FIN, RST, ACK counts per direction)
- TCP initial window sizes (from SYN and SYN-ACK)
- Inter-arrival time (IAT) per direction and per flow
- Payload length distribution histogram
- Byte entropy and mean/variance of byte values
- SPLT (Sequence of Packet Lengths and Times) for ML classification

Calling the Detection Engine
-----------------------------

The application calls ``ndpi_detection_process_packet()`` for each packet
while ``flow->detection_completed == 0``. It passes the raw IP packet (pointer
to the IP header, not the Ethernet frame) along with the packet length and a
millisecond-precision timestamp.

When the packet limit is reached (configurable per TCP and UDP) and the flow
is still unclassified, the application calls ``ndpi_detection_giveup()`` to
force a best-effort classification.

After classification completes, ``process_ndpi_collected_info()``
(``example/reader_util.c:1282``) extracts protocol-specific metadata from the
internal flow structure (DNS records, TLS certificates, HTTP URLs, SSH
fingerprints, etc.) into the application-facing ``ndpi_flow_info``.


Core Detection Engine
=====================

The core detection engine lives entirely in ``src/lib/ndpi_main.c``. The
public entry point is ``ndpi_detection_process_packet()`` (line 10540), which
delegates to ``ndpi_internal_detection_process_packet()`` (line 10292).

Packet Parsing: ndpi_init_packet()
-----------------------------------

``ndpi_init_packet()`` (line 7958) populates the ``ndpi_struct->packet``
structure from the raw IP buffer:

- Validates the IP header (minimum 20 bytes, version 4 or 6)
- Extracts the L4 header (TCP, UDP, or ICMP) via ``ndpi_detection_get_l4_internal()``
- Sets ``packet->payload`` and ``packet->payload_packet_len`` to point past L4 headers
- For TCP: computes ``tcp_header_len`` from the data offset field, optionally
  performs TCP fingerprinting
- For UDP: payload starts 8 bytes after the UDP header
- Stores results in ``ndpi_struct->packet`` for all dissectors to read

Connection Tracking
--------------------

``connection_tracking()`` (line 8397) runs after packet parsing:

- **Direction detection**: Determines which end is the client. Heuristics:
  TCP SYN without ACK comes from the client; otherwise the lower IP is
  assumed to be the client. Applications can override this via ``input_info``.
- **TCP state tracking**: Records SYN/SYN-ACK/ACK handshake, tracks sequence
  numbers, detects retransmissions.
- **Scan detection**: Flags TCP NULL scan (no flags) and XMAS scan
  (FIN+PSH+URG) as ``NDPI_TCP_ISSUES`` risks.
- **Packet counters**: Increments ``packet_counter``, ``all_packets_counter``,
  and per-direction counters.

Selection Bitmask Construction
-------------------------------

Before calling dissectors, the engine builds a bitmask describing the current
packet's properties:

.. code-block:: c

    ndpi_selection_packet = NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
    if(packet->iph)    |= ..._IP;
    if(packet->tcp)    |= ..._INT_TCP;
    if(packet->udp)    |= ..._INT_UDP;
    if(tcp || udp)     |= ..._INT_TCP_OR_UDP;
    if(payload_len)    |= ..._HAS_PAYLOAD;
    if(!tcp_retrans)   |= ..._NO_TCP_RETRANSMISSION;
    if(ipv6)           |= ..._IPV6;
    if(ipv4 || ipv6)   |= ..._IPV4_OR_IPV6;

Each dissector declares its own bitmask at registration time (e.g.
*"I need TCP + payload + no retransmission + IPv4 or IPv6"*). A dissector is
only invoked when **all** its required bits are present in the packet bitmask.

Port-Based Pre-Seeding: do_guess()
------------------------------------

On the **first packet** of a flow, ``do_guess()`` (line 9994) uses the
port-to-protocol mapping table to pre-seed ``flow->guessed_protocol_id``.
This drives the fast-path in the dispatch algorithm: the dissector for the
guessed protocol runs first, before any linear scan.

Dissector Dispatch: ndpi_check_flow_func()
-------------------------------------------

``ndpi_check_flow_func()`` (line 8767) routes the packet to the correct
L4-specific callback buffer. See the dedicated section below for the full
dispatch algorithm.

Post-Detection Processing
--------------------------

After dissectors return, the engine performs:

- ``fill_protocol_category_and_breed()``: assigns traffic category
  (e.g. ``NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK``) and breed
  (e.g. ``NDPI_PROTOCOL_FUN``)
- ``check_proto_on_non_std_port_risk()``: flags protocols running on
  non-standard ports
- IP reputation check against Patricia trees
- Fully-encrypted heuristic (first packet only): detects obfuscated traffic
- ``ndpi_search_portable_executable()``, ``ndpi_search_elf()``,
  ``ndpi_search_shellscript()``: detects binary transfers
- Entropy computation and entropy-to-risk mapping
- First Packet Classification (FPC) evaluation


Dissector Dispatch Algorithm
============================

The dispatch algorithm lives in ``check_ndpi_detection_func()``
(``src/lib/ndpi_main.c:8669``).

Two-Phase Dispatch
-------------------

.. code-block:: text

    ndpi_check_flow_func()
         |
         +-- TCP packet? --> check_ndpi_tcp_flow_func()
         |                       |
         |                       +-- has payload? --> callback_buffer_tcp_payload
         |                       +-- no payload?  --> callback_buffer_tcp_no_payload
         |
         +-- UDP packet? --> check_ndpi_udp_flow_func()
         |                       |
         |                       +--> callback_buffer_udp
         |
         +-- other?      --> check_ndpi_other_flow_func()
                                 |
                                 +--> callback_buffer_non_tcp_udp
                                          |
                                          v
                           check_ndpi_detection_func(buffer, size)
                                          |
            +-----------------------------+-----------------------------+
            |                                                           |
            v                                                           |
        PHASE 1: Fast Callback                                          |
        protocol = fast_callback_id ?: guessed_id (from port guess)     |
        idx = proto_defaults[protocol].dissector_idx                    |
            |                                                           |
            +-- bitmask match + not excluded? --> CALL dissector         |
            |                                       |                   |
            |                              detected? --> DONE           |
            |                                                           |
            v                                                           |
        PHASE 2: Linear Scan (registration order)                       |
        for a = 0 to callback_buffer_size:                              |
            |                                                           |
            +-- skip if same func as Phase 1                            |
            +-- skip if bitmask mismatch                                |
            +-- skip if in excluded_dissectors_bitmask                  |
            |                                                           |
            +-- CALL dissector                                          |
            |     |                                                     |
            |     +-- detected? --> BREAK (first match wins)            |
            |                                                           |
            v                                                           |
        PHASE 3: Subprotocol refinement  <------------------------------+
        check_ndpi_subprotocols() for stack[0] and stack[1]

**Phase 1 (fast callback)** runs a single dissector -- the one associated with
the port-based protocol guess. This is the fast path: common protocols on
well-known ports classify in one call.

**Phase 2 (linear scan)** iterates the remaining dissectors in
**registration order** (the order they were added in ``dissectors_init()``).
**First match wins** -- the loop breaks as soon as any dissector sets
``detected_protocol_stack[0]``.

**Phase 3 (subprotocol refinement)** runs after main detection. It checks
whether the detected protocol has registered subprotocol dissectors (e.g.
TLS -> Google, HTTP -> Netflix) and calls them.

The Four Callback Buffers
--------------------------

During ``ndpi_finalize_initialization()``, the main ``callback_buffer`` is
split into four L4-specific buffers. Each buffer is a filtered copy preserving
the original registration order:

.. list-table::
   :header-rows: 1
   :widths: 35 30 35

   * - Buffer
     - Routed When
     - Includes Dissectors With
   * - ``callback_buffer_tcp_payload``
     - TCP + payload present
     - ``INT_TCP`` or ``INT_TCP_OR_UDP`` or ``COMPLETE_TRAFFIC`` in bitmask
   * - ``callback_buffer_tcp_no_payload``
     - TCP + no payload (ACK, FIN, etc.)
     - Same as above, but ``HAS_PAYLOAD`` must NOT be in bitmask
   * - ``callback_buffer_udp``
     - UDP
     - ``INT_UDP`` or ``INT_TCP_OR_UDP`` or ``COMPLETE_TRAFFIC`` in bitmask
   * - ``callback_buffer_non_tcp_udp``
     - Neither TCP nor UDP (GRE, ICMP, etc.)
     - No ``INT_TCP``, ``INT_UDP``, or ``INT_TCP_OR_UDP``; or ``COMPLETE_TRAFFIC``

Excluded Dissectors Bitmask
----------------------------

Each flow carries an ``excluded_dissectors_bitmask`` -- a per-flow bitmask
tracking which dissectors have ruled themselves out. When a dissector
determines that the flow cannot be its protocol, it calls
``NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow)`` which sets the bit for the
current dissector index. On subsequent packets, that dissector is skipped
during the linear scan, reducing CPU cost as the flow ages.

Subprotocol Refinement
-----------------------

After the main detection loop, ``check_ndpi_subprotocols()`` is called for
both entries in the protocol stack. This allows a second-level classification:
for example, after detecting TLS, a subprotocol dissector may examine the SNI
to determine that the traffic is Facebook or Google.


Dissector Registration
======================

dissectors_init() and Registration Order
------------------------------------------

``dissectors_init()`` (``src/lib/ndpi_main.c:6669``) calls approximately 256
``init_*_dissector()`` functions in a fixed order. The first 114 entries are
normal-priority protocols. Starting at position 115 (marked by the comment
*"Put false-positive sensitive protocols at the end"*), protocols that are
prone to false positives are registered last.

Registration order matters because the Phase 2 linear scan tries dissectors in
this order and stops on the first match. Protocols registered earlier
short-circuit the scan and prevent later, less specific dissectors from
matching.

The first few registrations (highest priority in the linear scan):

1. HTTP
2. Blizzard
3. TLS+DTLS
4. RTP
5. RTSP
6. RDP
7. STUN
8. SIP
9. ...

Examples of false-positive sensitive protocols (lowest priority):

115. Viber
116. BitTorrent
117. WhatsApp
118. Ookla
119. AMQP
120. ...

The register_dissector() Function
----------------------------------

Each ``init_*_dissector()`` function calls ``register_dissector()``
(``src/lib/ndpi_main.c:6602``):

.. code-block:: c

    register_dissector(
        "ProtocolName",        /* display name (max 15 chars)              */
        ndpi_struct,           /* detection module                         */
        ndpi_search_func,      /* the dissector function pointer           */
        NDPI_SELECTION_BITMASK_PROTOCOL_...,  /* packet type requirements */
        num_protocol_ids,      /* how many protocol IDs follow             */
        NDPI_PROTOCOL_XXX      /* protocol ID(s) this dissector handles    */
        /* , NDPI_PROTOCOL_YYY  -- additional IDs if num > 1              */
    );

This stores the function pointer and bitmask in ``callback_buffer[idx]`` and
records the dissector index in ``proto_defaults[protocol_id].dissector_idx``
for fast-callback lookup.

Selection Bitmask Reference
----------------------------

Base bits (from ``src/include/ndpi_private.h:589``):

.. list-table::
   :header-rows: 1
   :widths: 55 10 35

   * - Constant
     - Bit
     - Meaning
   * - ``NDPI_SELECTION_BITMASK_PROTOCOL_IP``
     - 1<<0
     - IPv4
   * - ``..._INT_TCP``
     - 1<<1
     - TCP
   * - ``..._INT_UDP``
     - 1<<2
     - UDP
   * - ``..._INT_TCP_OR_UDP``
     - 1<<3
     - TCP or UDP
   * - ``..._HAS_PAYLOAD``
     - 1<<4
     - L7 payload present
   * - ``..._NO_TCP_RETRANSMISSION``
     - 1<<5
     - Not a TCP retransmission
   * - ``..._IPV6``
     - 1<<6
     - IPv6
   * - ``..._IPV4_OR_IPV6``
     - 1<<7
     - IPv4 or IPv6
   * - ``..._COMPLETE_TRAFFIC``
     - 1<<8
     - Any traffic (always set)

Common composite bitmasks used by dissectors:

.. list-table::
   :header-rows: 1
   :widths: 60 10 30

   * - Composite Bitmask
     - Dissectors
     - Traffic Type
   * - ``..._V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION``
     - 100
     - TCP only, needs payload
   * - ``..._V4_V6_UDP_WITH_PAYLOAD``
     - 88
     - UDP only, needs payload
   * - ``..._V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION``
     - 56
     - TCP or UDP, needs payload
   * - ``..._UDP_WITH_PAYLOAD``
     - 6
     - UDP, IPv4 only
   * - ``..._V6_UDP_WITH_PAYLOAD``
     - 2
     - UDP, IPv6 only
   * - ``..._TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION``
     - 2
     - TCP or UDP, IPv4 only
   * - ``..._TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION``
     - 1
     - TCP, IPv4 only
   * - ``..._IPV4_OR_IPV6``
     - 1
     - Any IP (non-TCP/UDP)


Anatomy of a Dissector
======================

File Structure and Conventions
-------------------------------

Every dissector file follows the same boilerplate:

.. code-block:: c

    #include "ndpi_protocol_ids.h"

    #define NDPI_CURRENT_PROTO NDPI_PROTOCOL_XXX

    #include "ndpi_api.h"
    #include "ndpi_private.h"

``NDPI_CURRENT_PROTO`` must be defined **before** including the headers. It
controls which protocol's debug logging is active for this file.

Naming conventions:

- Search function: ``ndpi_search_<protocol>()``
- Connection helper: ``ndpi_int_<protocol>_add_connection()``
- Init function: ``init_<protocol>_dissector()``
- Source file: ``src/lib/protocols/<protocol>.c``

Accessing the Packet
---------------------

Dissectors do not receive the packet as a parameter. Instead, they read from
``ndpi_struct->packet``, which was populated by ``ndpi_init_packet()``:

.. code-block:: c

    struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

    /* L7 payload (past TCP/UDP header) */
    packet->payload              /* pointer to first payload byte */
    packet->payload_packet_len   /* payload length in bytes       */

    /* L4 headers (NULL if not applicable) */
    packet->tcp                  /* struct ndpi_tcphdr *           */
    packet->udp                  /* struct ndpi_udphdr *           */

    /* L3 headers (one is always non-NULL) */
    packet->iph                  /* struct ndpi_iphdr * (IPv4)     */
    packet->iphv6                /* struct ndpi_ipv6hdr * (IPv6)   */

    /* Port access */
    ntohs(packet->tcp->source)   /* TCP source port               */
    ntohs(packet->udp->dest)     /* UDP destination port           */

    /* Safe multi-byte reads from payload */
    get_u_int16_t(packet->payload, offset)
    get_u_int32_t(packet->payload, offset)

Always check ``packet->payload_packet_len`` before accessing payload bytes to
avoid buffer overreads on truncated captures.

Reporting Detection
--------------------

When a dissector positively identifies the protocol, it calls:

.. code-block:: c

    ndpi_set_detected_protocol(ndpi_struct, flow,
        NDPI_PROTOCOL_XXX,        /* upper (application) protocol  */
        NDPI_PROTOCOL_UNKNOWN,    /* lower (master) protocol       */
        NDPI_CONFIDENCE_DPI);     /* confidence level               */

The two protocol slots support layered classification. For example, HTTPS is
reported as:

.. code-block:: c

    ndpi_set_detected_protocol(ndpi_struct, flow,
        NDPI_PROTOCOL_GOOGLE,     /* application: Google            */
        NDPI_PROTOCOL_TLS,        /* master: TLS                    */
        NDPI_CONFIDENCE_DPI);

A common pattern is to wrap this in a helper:

.. code-block:: c

    static void ndpi_int_zug_add_connection(
        struct ndpi_detection_module_struct * const ndpi_struct,
        struct ndpi_flow_struct * const flow)
    {
        NDPI_LOG_INFO(ndpi_struct, "found ZUG\n");
        ndpi_set_detected_protocol(ndpi_struct, flow,
            NDPI_PROTOCOL_ZUG, NDPI_PROTOCOL_UNKNOWN,
            NDPI_CONFIDENCE_DPI);
    }

Self-Exclusion
---------------

When a dissector determines that the flow is definitively **not** its
protocol, it should exclude itself so it is not called again on subsequent
packets of the same flow:

.. code-block:: c

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;

This sets a bit in ``flow->excluded_dissectors_bitmask`` for the current
dissector. Failing to exclude causes the dissector to be called on every
packet, wasting CPU.

Multi-Packet Analysis
----------------------

Some protocols need multiple packets before classification is certain, or need
to extract metadata from packets after the initial classification. This is
done by setting an *extra packets* callback:

.. code-block:: c

    flow->extra_packets_func = my_follow_up_function;
    flow->max_extra_packets_to_check = 5;

On subsequent packets, the engine calls ``my_follow_up_function(ndpi_struct, flow)``
instead of the normal dissector dispatch. The DNS dissector uses this pattern
to process query and response packets separately.

Complete Example: ZUG Dissector
--------------------------------

The ZUG Consensus Protocol dissector (``src/lib/protocols/zug.c``) is one of
the simplest in the codebase and demonstrates every required piece:

.. code-block:: c

    #include "ndpi_protocol_ids.h"

    #define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ZUG

    #include "ndpi_api.h"
    #include "ndpi_private.h"

    /* Helper: report detection */
    static void ndpi_int_zug_add_connection(
        struct ndpi_detection_module_struct * const ndpi_struct,
        struct ndpi_flow_struct * const flow)
    {
        NDPI_LOG_INFO(ndpi_struct, "found ZUG Consensus Protocol (ZUG)\n");
        ndpi_set_detected_protocol(ndpi_struct, flow,
            NDPI_PROTOCOL_ZUG, NDPI_PROTOCOL_UNKNOWN,
            NDPI_CONFIDENCE_DPI);
    }

    /* Search function: called by the dispatch engine */
    static void ndpi_search_zug(
        struct ndpi_detection_module_struct *ndpi_struct,
        struct ndpi_flow_struct *flow)
    {
        struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

        NDPI_LOG_DBG(ndpi_struct, "search ZUG Consensus Protocol (ZUG)\n");

        /* Guard: minimum payload length */
        if (packet->payload_packet_len < 5) {
            NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
            return;
        }

        /* Match: 4-byte magic + version byte */
        if (ntohl(get_u_int32_t(packet->payload, 0)) == 0x007a5547 &&
            packet->payload[4] == 0x10)
        {
            ndpi_int_zug_add_connection(ndpi_struct, flow);
            return;
        }

        /* No match: exclude this dissector for the flow */
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    }

    /* Init function: register with the dispatch engine */
    void init_zug_dissector(
        struct ndpi_detection_module_struct *ndpi_struct)
    {
        register_dissector("ZUG", ndpi_struct,
            ndpi_search_zug,
            NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
            1, NDPI_PROTOCOL_ZUG);
    }

The dissector has three possible outcomes per packet:

1. **Payload too short** -> ``NDPI_EXCLUDE_DISSECTOR`` (never call again)
2. **Magic matches** -> ``ndpi_set_detected_protocol`` (classified)
3. **Magic doesn't match** -> ``NDPI_EXCLUDE_DISSECTOR`` (not this protocol)


Classification and Confidence
==============================

Every classification carries a confidence level indicating how it was
determined. Defined in ``src/include/ndpi_typedefs.h:1044``:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Confidence Level
     - Meaning
   * - ``NDPI_CONFIDENCE_UNKNOWN``
     - No classification attempted
   * - ``NDPI_CONFIDENCE_MATCH_BY_PORT``
     - Guessed from well-known port number only
   * - ``NDPI_CONFIDENCE_NBPF``
     - Matched a user-defined nBPF custom rule
   * - ``NDPI_CONFIDENCE_DPI_PARTIAL``
     - Partial payload inspection (inconclusive)
   * - ``NDPI_CONFIDENCE_DPI_PARTIAL_CACHE``
     - Matched via LRU cache from a related flow
   * - ``NDPI_CONFIDENCE_DPI_CACHE``
     - Matched via LRU cache (session correlation)
   * - ``NDPI_CONFIDENCE_DPI``
     - Full deep packet inspection (standard confidence)
   * - ``NDPI_CONFIDENCE_MATCH_BY_IP``
     - Matched by IP address (e.g. known CDN ranges)
   * - ``NDPI_CONFIDENCE_DPI_AGGRESSIVE``
     - Aggressive heuristic match (may false-positive)
   * - ``NDPI_CONFIDENCE_CUSTOM_RULE``
     - Matched a user-defined custom rule


The Giveup Cascade
==================

When the detection engine has processed the maximum number of packets for a
flow without reaching ``NDPI_STATE_CLASSIFIED``, it invokes
``ndpi_internal_detection_giveup()`` (``src/lib/ndpi_main.c:9414``). This
function tries progressively weaker classification methods:

.. code-block:: text

    ndpi_internal_detection_giveup()
         |
         v
    Already classified? --------YES---------> return
         |NO
         v
    Partial from fast callback? --YES-------> NDPI_CONFIDENCE_DPI_PARTIAL
         |
         v
    BitTorrent cache hit? -------YES-------> NDPI_CONFIDENCE_DPI_PARTIAL_CACHE
         |
         v
    Mining cache hit? -----------YES-------> NDPI_CONFIDENCE_DPI_PARTIAL_CACHE
         |
         v
    Ookla cache hit? ------------YES-------> NDPI_CONFIDENCE_DPI_PARTIAL_CACHE
         |
         v
    First packet encrypted? -----YES-------> Set NDPI_OBFUSCATED_TRAFFIC risk
         |
         v
    Guess by IP? ----------------YES-------> NDPI_CONFIDENCE_MATCH_BY_IP
         |
         v
    Guess by port? --------------YES-------> NDPI_CONFIDENCE_MATCH_BY_PORT
         |
         v
    return (may still be UNKNOWN)

The order of IP-vs-port guessing is controlled by the
``dpi.guess_ip_before_port`` configuration parameter. The
``dpi.guess_on_giveup`` bitmask controls which fallback methods are enabled.


How to Add a New Dissector
==========================

Step 1: Reserve a Protocol ID
-------------------------------

Add an entry to ``src/include/ndpi_protocol_ids.h``:

.. code-block:: c

    NDPI_PROTOCOL_MY_PROTOCOL = <next_available_id>,

Step 2: Create the Source File
-------------------------------

Create ``src/lib/protocols/my_protocol.c`` with the standard boilerplate:

.. code-block:: c

    #include "ndpi_protocol_ids.h"

    #define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MY_PROTOCOL

    #include "ndpi_api.h"
    #include "ndpi_private.h"

Step 3: Write the Init Function
--------------------------------

.. code-block:: c

    void init_my_protocol_dissector(
        struct ndpi_detection_module_struct *ndpi_struct)
    {
        register_dissector("MyProtocol", ndpi_struct,
            ndpi_search_my_protocol,
            NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
            1, NDPI_PROTOCOL_MY_PROTOCOL);
    }

Choose the selection bitmask that matches your protocol's transport:

- TCP only: ``..._V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION``
- UDP only: ``..._V4_V6_UDP_WITH_PAYLOAD``
- Both: ``..._V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION``

Step 4: Write the Search Function
-----------------------------------

.. code-block:: c

    static void ndpi_search_my_protocol(
        struct ndpi_detection_module_struct *ndpi_struct,
        struct ndpi_flow_struct *flow)
    {
        struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

        /* Check minimum payload */
        if (packet->payload_packet_len < MIN_SIZE) {
            NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
            return;
        }

        /* Match protocol signature */
        if (/* magic bytes or pattern match */) {
            NDPI_LOG_INFO(ndpi_struct, "found MyProtocol\n");
            ndpi_set_detected_protocol(ndpi_struct, flow,
                NDPI_PROTOCOL_MY_PROTOCOL, NDPI_PROTOCOL_UNKNOWN,
                NDPI_CONFIDENCE_DPI);
            return;
        }

        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    }

Step 5: Register in dissectors_init()
---------------------------------------

Add the init call to ``dissectors_init()`` in ``src/lib/ndpi_main.c``.
Place it before the *"Put false-positive sensitive protocols at the end"*
comment unless your dissector's pattern matching is generic enough to produce
false positives:

.. code-block:: c

    /* MyProtocol */
    init_my_protocol_dissector(ndpi_str);

Step 6: Add to the Build System
---------------------------------

Add the source file to ``src/lib/Makefile.in`` in the ``NDPI_SRCS`` list.

Step 7: Add Test Coverage
--------------------------

- Place a pcap capture file in ``tests/pcap/``
- Add expected detection output to the appropriate file under ``tests/cfgs/``
- Run the test suite with ``ndpiReader`` to verify

Common Pitfalls
----------------

- **Forgetting NDPI_EXCLUDE_DISSECTOR**: Without exclusion, the dissector runs
  on every packet of unclassified flows, wasting CPU.
- **Wrong selection bitmask**: If you register a TCP dissector with a UDP-only
  bitmask, it will never fire. If you omit ``HAS_PAYLOAD``, the dissector may
  be called on TCP ACK packets with no data.
- **Not checking payload length**: Accessing ``packet->payload[n]`` without
  verifying ``packet->payload_packet_len > n`` causes buffer overreads on
  truncated captures.
- **Registering too early**: If your pattern is generic (e.g. matching a common
  byte sequence), registering early in ``dissectors_init()`` means it will
  match before more specific dissectors get a chance. Place generic matchers
  in the false-positive-sensitive section.
- **Not handling both directions**: The first packet may come from either the
  client or the server. A dissector that only checks for request patterns will
  miss flows where the capture starts mid-connection.
