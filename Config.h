#pragma once

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

#include "SQRLLIniObject.h"

/** Represents protocol types */
enum class Protocol { TCP, UDP };

/** Represents the determined status of a scanned port */
enum class ScanStatus {
  OPEN,           // Confirmed open (service responded with valid data)
  OPEN_FILTERED,  // No response received — could be open or filtered by firewall
  CLOSED,         // Port explicitly refused connection (ICMP unreachable / RST)
  FILTERED        // Firewall is silently dropping packets
};

/** Holds metadata for a scanned port */
struct PortScanResult {
  int port;
  Protocol protocol;
  bool isOpen;
  ScanStatus status = ScanStatus::OPEN;
  std::string serviceName;
  std::string banner;
};

/** Holds configuration parameters for the port scanner */
struct ScannerConfig {
  std::string targetIp = "127.0.0.1"; // Target IPv4 address to scan
  int startPort = 1;                  // First port in the scanning range
  int endPort = 1024;                 // Last port in the scanning range
  int tcpTimeoutMs = 200;             // Connection timeout for TCP probes in milliseconds
  int udpTimeoutMs = 1500;            // Response wait time for UDP probes in milliseconds
  int udpRetries = 2;                 // Number of retry attempts for UDP probes
  int maxInFlight = 1024;             // Maximum concurrent in-flight probes per worker thread
  bool scanTcp = true;                // Flag enabling TCP protocol scanning
  bool scanUdp = false;               // Flag enabling UDP protocol scanning
  bool showProgress = true;           // Flag enabling periodic progress output
  int progressInterval = 2000;        // Print progress every N completed probes

  // Custom payloads loaded from Probes.ini (arrays of payload variants)
  std::unordered_map<int, std::vector<std::vector<uint8_t>>> tcpPayloads;
  std::unordered_map<int, std::vector<std::vector<uint8_t>>> udpPayloads;
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

/**
 * Retrieves the absolute directory path of the current executable
 * Relies on Linux procfs for accurate resolution regardless of invocation method
 */
std::filesystem::path getExecutableDir()
{
  std::error_code ec;

  // Read the system symlink that always points to the running binary
  const std::filesystem::path exePath = std::filesystem::read_symlink("/proc/self/exe", ec);

  // Fallback to current working directory if procfs is unavailable
  if (ec)
  {
    return std::filesystem::current_path();
  }

  // Extract just the directory part, removing the executable name
  return exePath.parent_path();
}

/** Constructs the full path to a file located next to the executable */
std::string getAdjacentFilePath(const std::string& filename)
{
  std::filesystem::path exeDir = getExecutableDir();
  std::filesystem::path targetPath = exeDir / filename;

  return targetPath.string();
}

/** Helper to unescape \xHH, \r, \n sequences from INI strings */
inline std::vector<uint8_t> unescapePayloadString(const std::string& input) {
  std::vector<uint8_t> output;
  output.reserve(input.size());

  for (size_t i = 0; i < input.size(); ++i) {
    if (input[i] == '\\' && i + 1 < input.size()) {
      char next = input[i + 1];
      if (next == 'r') {
        output.push_back('\r');
        i++;
      } else if (next == 'n') {
        output.push_back('\n');
        i++;
      } else if (next == 'x' && i + 3 < input.size()) {
        std::string hex = input.substr(i + 2, 2);
        try {
          int val = std::stoi(hex, nullptr, 16);
          output.push_back(static_cast<uint8_t>(val));
          i += 3;
        } catch (...) {
          output.push_back('\\');
        }
      } else if (next == '\\') {
        output.push_back('\\');
        i++;
      } else {
        output.push_back('\\');
      }
    } else {
      output.push_back(static_cast<uint8_t>(input[i]));
    }
  }
  return output;
}

/** Parses configuration from an INI file using SQRLLIniObject */
inline ScannerConfig loadConfigFromIni(const std::string &iniFileName) {
  ScannerConfig config;
  const std::string iniFilePath = getAdjacentFilePath(iniFileName);
  const std::string probesFilePath = getAdjacentFilePath("Probes.ini");

  try {
    SQRLLIniObject ini(iniFilePath);
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
    config.udpRetries = getIntField({"udpRetries", "udp_retries", "UdpRetries", "udp_retry"}, config.udpRetries);
    config.maxInFlight = getIntField({"maxInFlight", "max_in_flight", "MaxInFlight", "max_inflight"}, config.maxInFlight);
    config.scanTcp = getBoolField({"scanTcp", "scan_tcp", "ScanTcp", "tcp", "TCP"}, config.scanTcp);
    config.scanUdp = getBoolField({"scanUdp", "scan_udp", "ScanUdp", "udp", "UDP"}, config.scanUdp);
    config.showProgress = getBoolField({"showProgress", "show_progress", "ShowProgress", "progress"}, config.showProgress);
    config.progressInterval = getIntField({"progressInterval", "progress_interval", "ProgressInterval"}, config.progressInterval);

  } catch (const std::exception &e) {
    std::cerr << "Note: Could not load configuration from '" << iniFilePath
              << "' (" << e.what() << "). Using default settings.\n";
  } catch (...) {
    std::cerr << "Note: Could not load configuration from '" << iniFilePath
              << "'. Using default settings.\n";
  }

  // Load Probes.ini
  try {
    SQRLLIniObject probesIni(probesFilePath);
    probesIni.LoadIni();

    auto cleanValue = [](std::string val) {
      if (val.size() >= 2 && ((val.front() == '"' && val.back() == '"') ||
                              (val.front() == '\'' && val.back() == '\''))) {
        val = val.substr(1, val.size() - 2);
      }
      return val;
    };

    // Iterate through all possible ports to bypass private map limitation
    for (int port = 1; port <= 65535; ++port) {
      // Allow up to 10 payloads per port: TCP_80, TCP_80_1, TCP_80_2 ...
      for (int i = 0; i < 10; ++i) {
        std::string tcpKey = (i == 0) ? "TCP_" + std::to_string(port) : "TCP_" + std::to_string(port) + "_" + std::to_string(i);
        if (probesIni.ContainsFieldByName(tcpKey)) {
          SQRLLIniField field = probesIni.FindFieldByName(tcpKey);
          if (field.IsValid()) {
            std::string rawStr = cleanValue(field.GetValueAsString());
            config.tcpPayloads[port].push_back(unescapePayloadString(rawStr));
          }
        }

        std::string udpKey = (i == 0) ? "UDP_" + std::to_string(port) : "UDP_" + std::to_string(port) + "_" + std::to_string(i);
        if (probesIni.ContainsFieldByName(udpKey)) {
          SQRLLIniField field = probesIni.FindFieldByName(udpKey);
          if (field.IsValid()) {
            std::string rawStr = cleanValue(field.GetValueAsString());
            config.udpPayloads[port].push_back(unescapePayloadString(rawStr));
          }
        }
      }
    }
    
    if (!config.tcpPayloads.empty() || !config.udpPayloads.empty()) {
        std::cout << "[INFO] Loaded custom payloads from Probes.ini (TCP: " 
                  << config.tcpPayloads.size() << ", UDP: " << config.udpPayloads.size() << ")\n";
    }

  } catch (...) {
    // Probes.ini might not exist or failed to load, which is fine
  }

  return config;
}