#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

#include "SQRLLIniObject.h"

/** Represents protocol types */
enum class Protocol { TCP, UDP };

/** Holds metadata for a scanned port */
struct PortScanResult {
  int port;
  Protocol protocol;
  bool isOpen;
  std::string serviceName;
  std::string banner;
};

/** Holds configuration parameters for the port scanner */
struct ScannerConfig {
  std::string targetIp = "127.0.0.1"; // Target IPv4 address to scan
  int startPort = 1;                  // First port in the scanning range
  int endPort = 1024;                 // Last port in the scanning range
  int tcpTimeoutMs = 200;             // Connection timeout for TCP probes in milliseconds
  int udpTimeoutMs = 500;             // Response wait time for UDP probes in milliseconds
  bool scanTcp = true;                // Flag enabling TCP protocol scanning
  bool scanUdp = false;               // Flag enabling UDP protocol scanning
};

/** RAII wrapper ensuring socket resources are released */
class SocketHandle {
public:
  explicit SocketHandle(const int fd) : fd_(fd) {}

  ~SocketHandle() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  [[nodiscard]] int get() const { return fd_; }

  SocketHandle(const SocketHandle &) = delete;
  SocketHandle &operator=(const SocketHandle &) = delete;

private:
  int fd_;
};

/** Parses configuration from an INI file using SQRLLIniObject */
inline ScannerConfig loadConfigFromIni(const std::string &iniPath) {
  ScannerConfig config;

  try {
    SQRLLIniObject ini(iniPath);
    ini.LoadIni();

    auto cleanValue = [](std::string val) {
      if (val.size() >= 2 && ((val.front() == '"' && val.back() == '"') ||
                              (val.front() == '\'' && val.back() == '\''))) {
        val = val.substr(1, val.size() - 2);
      }
      return val;
    };

    auto getStringField = [&](const std::vector<std::string> &keys, const std::string &defaultVal) {
      for (const auto &key : keys) {
        if (ini.ContainsFieldByName(key)) {
          SQRLLIniField field = ini.FindFieldByName(key);
          if (field.IsValid()) {
            return cleanValue(field.GetValueAsString());
          }
        }
      }
      return defaultVal;
    };

    auto getIntField = [&](const std::vector<std::string> &keys, int defaultVal) {
      for (const auto &key : keys) {
        if (ini.ContainsFieldByName(key)) {
          SQRLLIniField field = ini.FindFieldByName(key);
          if (field.IsValid()) {
            try {
              std::string str = cleanValue(field.GetValueAsString());
              return std::stoi(str);
            } catch (...) {
              return field.GetValueAsInt();
            }
          }
        }
      }
      return defaultVal;
    };

    auto getBoolField = [&](const std::vector<std::string> &keys, bool defaultVal) {
      for (const auto &key : keys) {
        if (ini.ContainsFieldByName(key)) {
          SQRLLIniField field = ini.FindFieldByName(key);
          if (field.IsValid()) {
            return field.GetValueAsBool();
          }
        }
      }
      return defaultVal;
    };

    config.targetIp = getStringField({"targetIp", "target_ip", "TargetIp", "IP", "ip"}, config.targetIp);
    config.startPort = getIntField({"startPort", "start_port", "StartPort", "startport"}, config.startPort);
    config.endPort = getIntField({"endPort", "end_port", "EndPort", "endport"}, config.endPort);
    config.tcpTimeoutMs = getIntField({"tcpTimeoutMs", "tcp_timeout_ms", "TcpTimeoutMs", "tcpTimeout", "tcp_timeout", "TCP_TIME"}, config.tcpTimeoutMs);
    config.udpTimeoutMs = getIntField({"udpTimeoutMs", "udp_timeout_ms", "UdpTimeoutMs", "udpTimeout", "udp_timeout", "UDP_TIME"}, config.udpTimeoutMs);
    config.scanTcp = getBoolField({"scanTcp", "scan_tcp", "ScanTcp", "tcp", "TCP"}, config.scanTcp);
    config.scanUdp = getBoolField({"scanUdp", "scan_udp", "ScanUdp", "udp", "UDP"}, config.scanUdp);

  } catch (const std::exception &e) {
    std::cerr << "Note: Could not load configuration from '" << iniPath 
              << "' (" << e.what() << "). Using default settings.\n";
  } catch (...) {
    std::cerr << "Note: Could not load configuration from '" << iniPath 
              << "'. Using default settings.\n";
  }

  return config;
}