#pragma once

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "Config.h"
#include "ServiceAnalyzer.h"

/** Orchestrates multithreaded network inspection */
class PortScanner {
public:
  explicit PortScanner(const ScannerConfig &config)
      : config_(config), currentPort_(config.startPort) {}

  /** Distributes the workload across hardware threads */
  std::vector<PortScanResult> run() {
    unsigned int cpuCores = std::thread::hardware_concurrency();
    unsigned int numThreads = (cpuCores > 0) ? cpuCores : 4;

    std::vector<std::jthread> threads;

    for (unsigned int i = 0; i < numThreads; ++i) {
      threads.emplace_back(&PortScanner::worker, this);
    }

    for (auto &thread : threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }

    std::sort(openPorts_.begin(), openPorts_.end(),
              [](const PortScanResult &a, const PortScanResult &b) {
                if (a.port == b.port) {
                  return a.protocol < b.protocol;
                }
                return a.port < b.port;
              });

    return openPorts_;
  }

private:
  ScannerConfig config_;
  std::atomic<int> currentPort_;
  std::vector<PortScanResult> openPorts_;
  std::mutex resultsMutex_;

  void worker(std::stop_token stoken) {
    while (!stoken.stop_requested()) {
      int port = currentPort_.fetch_add(1, std::memory_order_relaxed);

      if (port > config_.endPort) {
        break;
      }

      if (config_.scanTcp) {
        PortScanResult tcpResult = scanTcp(port);
        if (tcpResult.isOpen) {
          std::lock_guard<std::mutex> lock(resultsMutex_);
          openPorts_.push_back(tcpResult);
        }
      }

      if (config_.scanUdp) {
        PortScanResult udpResult = scanUdp(port);
        if (udpResult.isOpen) {
          std::lock_guard<std::mutex> lock(resultsMutex_);
          openPorts_.push_back(udpResult);
        }
      }
    }
  }

  PortScanResult scanTcp(int port) {
    PortScanResult result{port, Protocol::TCP, false, "unknown", ""};

    SocketHandle sock(socket(AF_INET, SOCK_STREAM, 0));

    if (sock.get() < 0) {
      return result;
    }

    int flags = fcntl(sock.get(), F_GETFL, 0);
    fcntl(sock.get(), F_SETFL, flags | O_NONBLOCK);

    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, config_.targetIp.c_str(), &targetAddr.sin_addr) <=
        0) {
      return result;
    }

    int connectResult =
        connect(sock.get(), reinterpret_cast<struct sockaddr *>(&targetAddr),
                sizeof(targetAddr));

    if (connectResult < 0) {
      if (errno == EINPROGRESS) {
        struct pollfd pfd{};
        pfd.fd = sock.get();
        pfd.events = POLLOUT;

        int pollResult = poll(&pfd, 1, config_.tcpTimeoutMs);

        if (pollResult > 0) {
          int soError = 0;
          socklen_t len = sizeof(soError);
          getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &soError, &len);

          if (soError == 0) {
            result.isOpen = true;
          }
        }
      }
    } else if (connectResult == 0) {
      result.isOpen = true;
    }

    if (result.isOpen) {
      result.serviceName =
          ServiceAnalyzer::lookupServiceName(port, Protocol::TCP);
      result.banner =
          ServiceAnalyzer::grabTcpBanner(sock.get(), config_.tcpTimeoutMs);
    }

    return result;
  }

  PortScanResult scanUdp(int port) {
    PortScanResult result{port, Protocol::UDP, false, "unknown", ""};

    SocketHandle sock(socket(AF_INET, SOCK_DGRAM, 0));

    if (sock.get() < 0) {
      return result;
    }

    int flags = fcntl(sock.get(), F_GETFL, 0);
    fcntl(sock.get(), F_SETFL, flags | O_NONBLOCK);

    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(port);
    inet_pton(AF_INET, config_.targetIp.c_str(), &targetAddr.sin_addr);

    connect(sock.get(), reinterpret_cast<struct sockaddr *>(&targetAddr),
            sizeof(targetAddr));

    const char probe = '\n';
    send(sock.get(), &probe, 1, 0);

    struct pollfd pfd{};
    pfd.fd = sock.get();
    pfd.events = POLLIN;

    int pollResult = poll(&pfd, 1, config_.udpTimeoutMs);

    if (pollResult < 0) {
      return result;
    }

    if (pollResult > 0) {
      int soError = 0;
      socklen_t len = sizeof(soError);
      getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &soError, &len);

      if (soError == ECONNREFUSED) {
        result.isOpen = false;
      } else {
        result.isOpen = true;
      }
    } else {
      result.isOpen = true;
    }

    if (result.isOpen) {
      result.serviceName =
          ServiceAnalyzer::lookupServiceName(port, Protocol::UDP);
    }

    return result;
  }
};