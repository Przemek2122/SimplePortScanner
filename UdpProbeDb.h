#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

/**
 * Defines a UDP probe payload and response validator for a specific service.
 * Each probe contains the raw bytes to send and a function to verify whether
 * the response matches the expected protocol format.
 */
struct UdpProbe {
  std::string serviceName;
  std::vector<uint8_t> payload;
  /** Returns true if the response data matches the expected service format */
  std::function<bool(const uint8_t *data, size_t len)> validateResponse;
};

/**
 * Database of well-known UDP service probes.
 * Provides protocol-correct payloads that elicit responses from real services,
 * dramatically reducing false positives compared to generic probing.
 */
class UdpProbeDb {
public:
  /** Returns the best probe for a given port, or a generic fallback */
  static const UdpProbe &getProbeForPort(int port) {
    static const auto &db = getDatabase();
    auto it = db.find(port);
    if (it != db.end()) {
      return it->second;
    }
    static const UdpProbe generic = makeGenericProbe();
    return generic;
  }

  /** Checks if we have a known service probe for this port */
  static bool hasProbeForPort(int port) {
    static const auto &db = getDatabase();
    return db.find(port) != db.end();
  }

  /**
   * Attempts to identify the service from a UDP response regardless of port.
   * Returns service name or empty string if unrecognized.
   */
  static std::string identifyFromResponse(const uint8_t *data, size_t len) {
    if (len == 0 || data == nullptr) {
      return "";
    }

    // DNS response: starts with query ID, flags byte has QR bit set (0x80+)
    if (len >= 12 && (data[2] & 0x80)) {
      return "dns";
    }

    // NTP response: version 2-4, mode 4 (server) or mode 6 (control)
    if (len >= 48) {
      uint8_t mode = data[0] & 0x07;
      uint8_t version = (data[0] >> 3) & 0x07;
      if (version >= 2 && version <= 4 && (mode == 4 || mode == 6)) {
        return "ntp";
      }
    }

    // SNMP response: ASN.1 SEQUENCE tag (0x30), then response PDU
    if (len >= 8 && data[0] == 0x30) {
      // Look for GetResponse PDU tag (0xA2)
      for (size_t i = 2; i < std::min(len, static_cast<size_t>(20)); ++i) {
        if (data[i] == 0xA2) {
          return "snmp";
        }
      }
    }

    // STUN response: starts with 0x01 0x01 (Binding Success)
    if (len >= 20 && data[0] == 0x01 && data[1] == 0x01) {
      // Magic cookie check
      if (data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42) {
        return "stun";
      }
    }

    // NetBIOS Name Service response
    if (len >= 12) {
      uint8_t flags = data[2];
      uint8_t opcode = (flags >> 3) & 0x0F;
      bool isResponse = (flags & 0x80) != 0;
      if (isResponse && opcode == 0) {
        // Could be NetBIOS — check ANCOUNT
        uint16_t ancount = (static_cast<uint16_t>(data[6]) << 8) | data[7];
        if (ancount > 0 && ancount < 100) {
          return "netbios-ns";
        }
      }
    }

    // SIP response: starts with "SIP/2.0"
    if (len >= 7 && std::memcmp(data, "SIP/2.0", 7) == 0) {
      return "sip";
    }

    // SSDP response: starts with "HTTP/1.1"
    if (len >= 8 && std::memcmp(data, "HTTP/1.1", 8) == 0) {
      return "ssdp";
    }

    // mDNS response (same format as DNS)
    if (len >= 12 && (data[2] & 0x80)) {
      return "mdns";
    }

    // Memcached: response contains "STAT " or "END"
    if (len >= 5) {
      std::string prefix(reinterpret_cast<const char *>(data), std::min(len, static_cast<size_t>(64)));
      if (prefix.find("STAT ") != std::string::npos || prefix.find("END") != std::string::npos) {
        return "memcached";
      }
    }

    return "";
  }

  /**
   * Extracts a human-readable info string from a UDP response.
   * Returns empty string if no meaningful info can be extracted.
   */
  static std::string extractUdpBanner(int port, const uint8_t *data, size_t len) {
    if (len == 0 || data == nullptr) {
      return "";
    }

    // NTP: extract reference timestamp or stratum info
    if (port == 123 && len >= 48) {
      uint8_t stratum = data[1];
      uint8_t version = (data[0] >> 3) & 0x07;
      return "NTPv" + std::to_string(version) + " stratum=" + std::to_string(stratum);
    }

    // SNMP: just note we got a response
    if (port == 161 && len >= 8 && data[0] == 0x30) {
      return "SNMP agent responding";
    }

    // SIP: extract first line
    if (port == 5060 && len >= 7 && std::memcmp(data, "SIP/2.0", 7) == 0) {
      std::string response(reinterpret_cast<const char *>(data),
                           std::min(len, static_cast<size_t>(80)));
      size_t lineEnd = response.find("\r\n");
      if (lineEnd != std::string::npos) {
        return response.substr(0, lineEnd);
      }
      return response;
    }

    // SSDP: extract SERVER header
    if (port == 1900 && len >= 8) {
      std::string response(reinterpret_cast<const char *>(data),
                           std::min(len, static_cast<size_t>(512)));
      size_t serverPos = response.find("SERVER:");
      if (serverPos == std::string::npos) {
        serverPos = response.find("Server:");
      }
      if (serverPos != std::string::npos) {
        size_t lineEnd = response.find("\r\n", serverPos);
        if (lineEnd != std::string::npos) {
          return response.substr(serverPos, lineEnd - serverPos);
        }
      }
    }

    // Generic: if response looks like ASCII text, return first line
    bool isAscii = true;
    for (size_t i = 0; i < std::min(len, static_cast<size_t>(64)); ++i) {
      if (data[i] != '\r' && data[i] != '\n' && data[i] != '\t' &&
          (data[i] < 0x20 || data[i] > 0x7E)) {
        isAscii = false;
        break;
      }
    }
    if (isAscii && len > 0) {
      std::string text(reinterpret_cast<const char *>(data),
                       std::min(len, static_cast<size_t>(60)));
      size_t lineEnd = text.find('\n');
      if (lineEnd != std::string::npos) {
        text = text.substr(0, lineEnd);
      }
      // Trim trailing whitespace
      while (!text.empty() && (text.back() == '\r' || text.back() == ' ')) {
        text.pop_back();
      }
      return text;
    }

    return "";
  }

private:
  static const std::unordered_map<int, UdpProbe> &getDatabase() {
    static const std::unordered_map<int, UdpProbe> db = buildDatabase();
    return db;
  }

  static std::unordered_map<int, UdpProbe> buildDatabase() {
    std::unordered_map<int, UdpProbe> db;

    // ---- DNS (port 53) ----
    // Standard query for "version.bind" TXT CH
    db[53] = {
        "dns",
        {0x00, 0x01, // Transaction ID
         0x01, 0x00, // Flags: Standard query
         0x00, 0x01, // Questions: 1
         0x00, 0x00, // Answer RRs: 0
         0x00, 0x00, // Authority RRs: 0
         0x00, 0x00, // Additional RRs: 0
         // QNAME: version.bind
         0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00,
         0x00, 0x10, // QTYPE: TXT
         0x00, 0x03  // QCLASS: CH (Chaos)
        },
        [](const uint8_t *data, size_t len) {
          // DNS response: QR bit set, at least 12 bytes header
          return len >= 12 && (data[2] & 0x80);
        }};

    // ---- NTP (port 123) ----
    // NTPv3 Client mode request (mode 3)
    {
      std::vector<uint8_t> ntpPayload(48, 0);
      ntpPayload[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
      db[123] = {
          "ntp",
          std::move(ntpPayload),
          [](const uint8_t *data, size_t len) {
            if (len < 48)
              return false;
            uint8_t mode = data[0] & 0x07;
            return mode == 4; // Server response
          }};
    }

    // ---- SNMP v1 (port 161) ----
    // GetRequest with community "public"
    db[161] = {
        "snmp",
        {0x30, 0x26,                                     // SEQUENCE, length 38
         0x02, 0x01, 0x00,                               // INTEGER: version (SNMPv1)
         0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',      // OCTET STRING: community "public"
         0xA0, 0x19,                                      // GetRequest PDU
         0x02, 0x04, 0x00, 0x00, 0x00, 0x01,              // request-id: 1
         0x02, 0x01, 0x00,                                // error-status: 0
         0x02, 0x01, 0x00,                                // error-index: 0
         0x30, 0x0B,                                      // varbind list
         0x30, 0x09,                                      // varbind
         0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01,       // OID: 1.3.6.1.2.1 (system)
         0x05, 0x00                                       // NULL value
        },
        [](const uint8_t *data, size_t len) {
          if (len < 8 || data[0] != 0x30)
            return false;
          // Look for GetResponse PDU tag (0xA2)
          for (size_t i = 2; i < std::min(len, static_cast<size_t>(20)); ++i) {
            if (data[i] == 0xA2)
              return true;
          }
          return false;
        }};

    // SNMP Trap (port 162) — same probe as 161
    db[162] = db[161];
    db[162].serviceName = "snmptrap";

    // ---- NetBIOS Name Service (port 137) ----
    // Node Status Request for wildcard name "*"
    db[137] = {
        "netbios-ns",
        {0x80, 0x01, // Transaction ID
         0x00, 0x00, // Flags: query
         0x00, 0x01, // Questions: 1
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         // Encoded NetBIOS name "*" (wildcard)
         0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
         0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
         0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
         0x00,
         0x00, 0x21, // NBSTAT
         0x00, 0x01  // IN class
        },
        [](const uint8_t *data, size_t len) {
          if (len < 12)
            return false;
          return (data[2] & 0x80) != 0; // Response flag set
        }};

    // ---- NetBIOS Datagram (port 138) ----
    db[138] = {
        "netbios-dgm",
        {0x11,       // Direct unique datagram
         0x02,       // Flags: first fragment
         0x00, 0x01, // DGM ID
         0x00, 0x00, 0x00, 0x00, // Source IP (placeholder)
         0x00, 0x89, // Source port
         0x00, 0x00, // DGM length
         0x00, 0x00  // Packet offset
        },
        [](const uint8_t *data, size_t len) {
          (void)data;
          return len >= 10;
        }};

    // ---- TFTP (port 69) ----
    // Read Request for a nonexistent file
    db[69] = {
        "tftp",
        {0x00, 0x01,                                  // Opcode: RRQ
         't', 'e', 's', 't', '.', 't', 'x', 't', 0x00, // Filename
         'o', 'c', 't', 'e', 't', 0x00                  // Mode
        },
        [](const uint8_t *data, size_t len) {
          if (len < 4)
            return false;
          uint16_t opcode = (static_cast<uint16_t>(data[0]) << 8) | data[1];
          // DATA (3), ACK (4), or ERROR (5) are all valid TFTP responses
          return opcode >= 3 && opcode <= 5;
        }};

    // ---- DHCP Server (port 67) ----
    // Minimal DHCP Discover
    {
      std::vector<uint8_t> dhcp(244, 0);
      dhcp[0] = 0x01;  // BOOTREQUEST
      dhcp[1] = 0x01;  // Hardware type: Ethernet
      dhcp[2] = 0x06;  // Hardware address length
      dhcp[3] = 0x00;  // Hops
      dhcp[4] = 0x39;  // Transaction ID (random)
      dhcp[5] = 0x03;
      dhcp[6] = 0xF3;
      dhcp[7] = 0x26;
      // Magic cookie
      dhcp[236] = 0x63;
      dhcp[237] = 0x82;
      dhcp[238] = 0x53;
      dhcp[239] = 0x63;
      // DHCP Discover option
      dhcp[240] = 0x35; // Option 53: DHCP message type
      dhcp[241] = 0x01; // Length: 1
      dhcp[242] = 0x01; // Discover
      dhcp[243] = 0xFF; // End

      db[67] = {
          "dhcp",
          std::move(dhcp),
          [](const uint8_t *data, size_t len) {
            if (len < 240)
              return false;
            // Check DHCP magic cookie
            return data[236] == 0x63 && data[237] == 0x82 &&
                   data[238] == 0x53 && data[239] == 0x63;
          }};
    }

    // ---- SSDP (port 1900) ----
    {
      std::string ssdpSearch =
          "M-SEARCH * HTTP/1.1\r\n"
          "HOST: 239.255.255.250:1900\r\n"
          "MAN: \"ssdp:discover\"\r\n"
          "MX: 1\r\n"
          "ST: ssdp:all\r\n"
          "\r\n";
      db[1900] = {
          "ssdp",
          std::vector<uint8_t>(ssdpSearch.begin(), ssdpSearch.end()),
          [](const uint8_t *data, size_t len) {
            return len >= 8 && std::memcmp(data, "HTTP/1.1", 8) == 0;
          }};
    }

    // ---- mDNS (port 5353) ----
    // Query for _services._dns-sd._udp.local
    db[5353] = {
        "mdns",
        {0x00, 0x00, // Transaction ID (0 for mDNS)
         0x00, 0x00, // Flags: standard query
         0x00, 0x01, // Questions: 1
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         // _services._dns-sd._udp.local
         0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
         0x07, '_', 'd', 'n', 's', '-', 's', 'd',
         0x04, '_', 'u', 'd', 'p',
         0x05, 'l', 'o', 'c', 'a', 'l',
         0x00,
         0x00, 0x0C, // QTYPE: PTR
         0x00, 0x01  // QCLASS: IN
        },
        [](const uint8_t *data, size_t len) {
          return len >= 12 && (data[2] & 0x80);
        }};

    // ---- SIP (port 5060) ----
    {
      std::string sipOptions =
          "OPTIONS sip:nm SIP/2.0\r\n"
          "Via: SIP/2.0/UDP nm;branch=z9hG4bK.probe\r\n"
          "From: <sip:nm@nm>;tag=probe\r\n"
          "To: <sip:nm@nm>\r\n"
          "Call-ID: probe@scanner\r\n"
          "CSeq: 1 OPTIONS\r\n"
          "Content-Length: 0\r\n"
          "\r\n";
      db[5060] = {
          "sip",
          std::vector<uint8_t>(sipOptions.begin(), sipOptions.end()),
          [](const uint8_t *data, size_t len) {
            return len >= 7 && std::memcmp(data, "SIP/2.0", 7) == 0;
          }};
    }

    // ---- OpenVPN (port 1194) ----
    // P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7, key_id 0)
    {
      std::vector<uint8_t> ovpn(14, 0);
      ovpn[0] = 0x38; // (opcode 7 << 3) | key_id 0
      // 8 bytes session ID (random)
      ovpn[1] = 0x01;
      ovpn[2] = 0x02;
      ovpn[3] = 0x03;
      ovpn[4] = 0x04;
      ovpn[5] = 0x05;
      ovpn[6] = 0x06;
      ovpn[7] = 0x07;
      ovpn[8] = 0x08;
      // Packet ID ack array length
      ovpn[9] = 0x00;
      // Packet ID
      ovpn[10] = 0x00;
      ovpn[11] = 0x00;
      ovpn[12] = 0x00;
      ovpn[13] = 0x01;

      db[1194] = {
          "openvpn",
          std::move(ovpn),
          [](const uint8_t *data, size_t len) {
            if (len < 14)
              return false;
            // Response should be P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8)
            uint8_t opcode = (data[0] >> 3);
            return opcode == 8;
          }};
    }

    // ---- STUN (port 3478) ----
    // Binding Request
    {
      std::vector<uint8_t> stun = {
          0x00, 0x01, // Type: Binding Request
          0x00, 0x00, // Length: 0 (no attributes)
          // Magic Cookie
          0x21, 0x12, 0xA4, 0x42,
          // Transaction ID (12 bytes)
          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
      db[3478] = {
          "stun",
          std::move(stun),
          [](const uint8_t *data, size_t len) {
            if (len < 20)
              return false;
            // Binding Success Response
            return data[0] == 0x01 && data[1] == 0x01 &&
                   data[4] == 0x21 && data[5] == 0x12;
          }};
    }

    // ---- Memcached (port 11211) ----
    {
      std::string stats = "stats\r\n";
      db[11211] = {
          "memcached",
          std::vector<uint8_t>(stats.begin(), stats.end()),
          [](const uint8_t *data, size_t len) {
            if (len < 4)
              return false;
            std::string resp(reinterpret_cast<const char *>(data),
                             std::min(len, static_cast<size_t>(64)));
            return resp.find("STAT ") != std::string::npos ||
                   resp.find("END") != std::string::npos ||
                   resp.find("ERROR") != std::string::npos;
          }};
    }

    // ---- RDP/UDP (port 3389) ----
    // DTLS ClientHello-like probe
    {
      std::vector<uint8_t> rdp = {
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      db[3389] = {
          "rdp-udp",
          std::move(rdp),
          [](const uint8_t *data, size_t len) {
            (void)data;
            return len >= 4; // Any response suggests service is there
          }};
    }

    // ---- Radius (port 1812/1813) ----
    // Access-Request with minimal attributes
    {
      std::vector<uint8_t> radius = {
          0x01,       // Code: Access-Request
          0x00,       // Packet Identifier
          0x00, 0x14, // Length: 20
          // Authenticator (16 bytes, random)
          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
      db[1812] = {
          "radius",
          radius,
          [](const uint8_t *data, size_t len) {
            if (len < 20)
              return false;
            // Access-Accept(2), Access-Reject(3), or Access-Challenge(11)
            return data[0] == 2 || data[0] == 3 || data[0] == 11;
          }};
      db[1813] = {
          "radius-acct",
          std::move(radius),
          [](const uint8_t *data, size_t len) {
            if (len < 20)
              return false;
            return data[0] == 5; // Accounting-Response
          }};
    }

    // ---- Syslog (port 514) ----
    {
      std::string syslogMsg = "<14>1 probe";
      db[514] = {
          "syslog",
          std::vector<uint8_t>(syslogMsg.begin(), syslogMsg.end()),
          [](const uint8_t *data, size_t len) {
            (void)data;
            // Syslog rarely responds, but if it does, any data counts
            return len > 0;
          }};
    }

    return db;
  }

  static UdpProbe makeGenericProbe() {
    return {"unknown",
            {0x00}, // Minimal single null byte
            [](const uint8_t *data, size_t len) {
              (void)data;
              // Any response to a generic probe means something is listening
              return len > 0;
            }};
  }
};
