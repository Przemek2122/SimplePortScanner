
#include <iostream>
#include <string>
#include <vector>

#include "Config.h"
#include "PortScanner.h"

/** Overrides configuration based on command line arguments */
void parseArguments(int argc, char **argv, ScannerConfig &config) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg.find("-IP:") == 0) {
      config.targetIp = arg.substr(4);
    } else if (arg == "-TCP") {
      config.scanTcp = true;
    } else if (arg == "-UDP") {
      config.scanUdp = true;
    } else if (arg.find("-TCP_TIME=") == 0) {
      try {
        config.tcpTimeoutMs = std::stoi(arg.substr(10));
      } catch (const std::exception &) {
        std::cerr << "Invalid TCP_TIME value.\n";
      }
    } else if (arg.find("-UDP_TIME=") == 0) {
      try {
        config.udpTimeoutMs = std::stoi(arg.substr(10));
      } catch (const std::exception &) {
        std::cerr << "Invalid UDP_TIME value.\n";
      }
    }
  }
}

int main(int argc, char **argv) {
  // Load defaults (eventually from SQRLL_INI_Reader)
  ScannerConfig config = loadConfigFromIni("scanner.ini");

  // Override with command line arguments
  parseArguments(argc, argv, config);

  std::cout << "Starting scan on " << config.targetIp << "...\n";
  std::cout << "Protocols: " << (config.scanTcp ? "TCP " : "")
            << (config.scanUdp ? "UDP" : "") << "\n";
  std::cout << "Timeouts: TCP=" << config.tcpTimeoutMs
            << "ms, UDP=" << config.udpTimeoutMs << "ms\n";

  PortScanner scanner(config);
  std::vector<PortScanResult> results = scanner.run();

  for (const auto &pr : results) {
    std::string protoStr = (pr.protocol == Protocol::TCP) ? "TCP" : "UDP";
    std::cout << "[+] Port " << pr.port << "/" << protoStr
              << " is OPEN|FILTERED (" << pr.serviceName << ")";

    if (!pr.banner.empty()) {
      std::cout << " -> Banner: [" << pr.banner << "]";
    }

    std::cout << "\n";
  }

  return 0;
}