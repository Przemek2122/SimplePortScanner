#pragma once

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <iostream>
#include <mutex>
#include <queue>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "Config.h"
#include "ServiceAnalyzer.h"
#include "UdpProbeDb.h"

/** Thread-safe printer that immediately outputs open ports from a dedicated thread */
class SafeOutputPrinter {
public:
  SafeOutputPrinter() : done_(false), worker_(&SafeOutputPrinter::run, this) {}

  ~SafeOutputPrinter() {
    stop();
  }

  void push(const PortScanResult &result) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      queue_.push(result);
    }
    cv_.notify_one();
  }

  void stop() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (done_) {
        return;
      }
      done_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
      worker_.join();
    }
  }

private:
  std::queue<PortScanResult> queue_;
  std::mutex mutex_;
  std::condition_variable cv_;
  bool done_;
  std::jthread worker_;

  void run() {
    while (true) {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait(lock, [this] { return !queue_.empty() || done_; });

      while (!queue_.empty()) {
        PortScanResult pr = std::move(queue_.front());
        queue_.pop();
        lock.unlock();

        printResult(pr);

        lock.lock();
      }

      if (done_ && queue_.empty()) {
        break;
      }
    }
  }

  static const char *statusToString(ScanStatus status) {
    switch (status) {
    case ScanStatus::OPEN:
      return "OPEN";
    case ScanStatus::OPEN_FILTERED:
      return "OPEN|FILTERED";
    case ScanStatus::CLOSED:
      return "CLOSED";
    case ScanStatus::FILTERED:
      return "FILTERED";
    default:
      return "UNKNOWN";
    }
  }

  static void printResult(const PortScanResult &pr) {
    std::string protoStr = (pr.protocol == Protocol::TCP) ? "TCP" : "UDP";
    std::cout << "[+] Port " << pr.port << "/" << protoStr
              << " is " << statusToString(pr.status)
              << " (" << pr.serviceName << ")";

    if (!pr.banner.empty()) {
      std::cout << " -> Banner: [" << pr.banner << "]";
    }

    std::cout << "\n" << std::flush;
  }
};

/** Orchestrates multithreaded network inspection with asynchronous I/O multiplexing */
class PortScanner {
public:
  explicit PortScanner(const ScannerConfig &config)
      : config_(config), nextTaskIndex_(0) {
    size_t protosCount = (config_.scanTcp ? 1 : 0) + (config_.scanUdp ? 1 : 0);
    size_t totalPorts = (config_.endPort >= config_.startPort)
                            ? static_cast<size_t>(config_.endPort - config_.startPort + 1)
                            : 0;
    totalTasks_ = totalPorts * protosCount;
  }

  /** Distributes the workload across hardware threads using asynchronous epoll multiplexing */
  std::vector<PortScanResult> run() {
    if (totalTasks_ == 0) {
      outputPrinter_.stop();
      return openPorts_;
    }

    unsigned int cpuCores = std::thread::hardware_concurrency();
    unsigned int numThreads = (cpuCores > 0) ? cpuCores : 4;

    std::vector<std::jthread> threads;
    threads.reserve(numThreads);

    for (unsigned int i = 0; i < numThreads; ++i) {
      threads.emplace_back(&PortScanner::worker, this);
    }

    for (auto &thread : threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }

    outputPrinter_.stop();

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
  // Helper struct for TCP checksum pseudo-header
  struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
  };

  /** Calculate Internet Checksum for raw packets */
  static unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    short answer = 0;
    while (nbytes > 1) {
      sum += *ptr++;
      nbytes -= 2;
    }
    if (nbytes == 1) {
      sum += *(unsigned char *)ptr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = static_cast<short>(~sum);
    return static_cast<unsigned short>(answer);
  }

  struct ScanTask {
    int port;
    Protocol protocol;
  };

  struct InFlightProbe {
    int fd;
    int port;
    Protocol protocol;
    std::chrono::steady_clock::time_point startTime;
    int retriesLeft;  // How many more retry attempts remain for UDP
  };

  ScannerConfig config_;
  size_t totalTasks_;
  std::atomic<size_t> nextTaskIndex_;
  std::atomic<size_t> completedTasks_{0};
  std::vector<PortScanResult> openPorts_;
  std::mutex resultsMutex_;
  std::mutex progressMutex_;
  SafeOutputPrinter outputPrinter_;

  bool getNextTask(ScanTask &task) {
    size_t idx = nextTaskIndex_.fetch_add(1, std::memory_order_relaxed);
    if (idx >= totalTasks_) {
      return false;
    }

    size_t protosCount = (config_.scanTcp ? 1 : 0) + (config_.scanUdp ? 1 : 0);
    int portOffset = static_cast<int>(idx / protosCount);
    int protoIdx = static_cast<int>(idx % protosCount);

    task.port = config_.startPort + portOffset;
    if (config_.scanTcp && config_.scanUdp) {
      task.protocol = (protoIdx == 0) ? Protocol::TCP : Protocol::UDP;
    } else if (config_.scanTcp) {
      task.protocol = Protocol::TCP;
    } else {
      task.protocol = Protocol::UDP;
    }

    return true;
  }

  void handleOpenPort(int sock, int port, Protocol proto, ScanStatus status = ScanStatus::OPEN,
                      const std::string &detectedService = "",
                      const std::string &udpBanner = "") {
    PortScanResult result{port, proto, true, status, "unknown", ""};

    // Use detected service name if available, otherwise fall back to system lookup
    if (!detectedService.empty()) {
      result.serviceName = detectedService;
    } else {
      result.serviceName = ServiceAnalyzer::lookupServiceName(port, proto);
    }

    if (proto == Protocol::TCP && sock >= 0) {
      result.banner = ServiceAnalyzer::grabTcpBanner(sock, config_.tcpTimeoutMs);
    } else if (proto == Protocol::UDP && !udpBanner.empty()) {
      result.banner = udpBanner;
    }

    {
      std::lock_guard<std::mutex> lock(resultsMutex_);
      openPorts_.push_back(result);
    }

    outputPrinter_.push(result);
  }

  /** Increments the completed counter and prints progress if enabled and interval reached */
  void reportProgress(Protocol proto) {
    (void)proto;
    if (!config_.showProgress || config_.progressInterval <= 0) {
      return;
    }

    size_t completed = completedTasks_.fetch_add(1, std::memory_order_relaxed) + 1;

    if (completed % static_cast<size_t>(config_.progressInterval) == 0 ||
        completed == totalTasks_) {
      std::string protoStr;
      if (config_.scanTcp && config_.scanUdp) {
        protoStr = "TCP+UDP";
      } else if (config_.scanTcp) {
        protoStr = "TCP";
      } else {
        protoStr = "UDP";
      }

      std::lock_guard<std::mutex> lock(progressMutex_);
      std::cout << "[Progress] " << completed << "/" << totalTasks_
                << " (" << protoStr << ")\n" << std::flush;
    }
  }

  void worker(std::stop_token stoken) {
    int epollFd = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd < 0) {
      return;
    }

    // One global raw socket per worker thread for TCP listening
    int rawRecvSock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    bool canUseRaw = (rawRecvSock >= 0);
    if (canUseRaw) {
      // Set to non-blocking
      int flags = fcntl(rawRecvSock, F_GETFL, 0);
      fcntl(rawRecvSock, F_SETFL, flags | O_NONBLOCK);

      struct epoll_event ev{};
      ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
      ev.data.fd = rawRecvSock;
      epoll_ctl(epollFd, EPOLL_CTL_ADD, rawRecvSock, &ev);
    }

    std::unordered_map<int, InFlightProbe> activeSockets;
    // Track sent SYN probes: map of Port -> InFlightProbe (we use negative port as dummy fd)
    std::unordered_map<int, InFlightProbe> synProbes;
    
    const size_t maxInFlight = static_cast<size_t>(config_.maxInFlight);
    constexpr int MAX_EVENTS = 64;
    struct epoll_event events[MAX_EVENTS];

    sockaddr_in targetAddr{};
    targetAddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, config_.targetIp.c_str(), &targetAddr.sin_addr) <= 0) {
      close(epollFd);
      if (canUseRaw) close(rawRecvSock);
      return;
    }

    // Find local IP for raw sockets
    uint32_t sourceIp = 0;
    int probeSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (probeSock >= 0) {
      sockaddr_in serv{};
      serv.sin_family = AF_INET;
      serv.sin_port = htons(53);
      inet_pton(AF_INET, "8.8.8.8", &serv.sin_addr);
      if (connect(probeSock, (const sockaddr*)&serv, sizeof(serv)) == 0) {
        sockaddr_in name{};
        socklen_t namelen = sizeof(name);
        if (getsockname(probeSock, (sockaddr*)&name, &namelen) == 0) {
          sourceIp = name.sin_addr.s_addr;
        }
      }
      close(probeSock);
    }
    if (sourceIp == 0) {
      inet_pton(AF_INET, "127.0.0.1", &sourceIp);
    }

    while (!stoken.stop_requested()) {
      // 1. Fill active sockets up to MAX_IN_FLIGHT concurrently
      while (activeSockets.size() < maxInFlight && !stoken.stop_requested()) {
        ScanTask task{};
        if (!getNextTask(task)) {
          break;
        }

        targetAddr.sin_port = htons(static_cast<uint16_t>(task.port));

        if (task.protocol == Protocol::TCP) {
          if (canUseRaw) {
             // We do RAW SYN SCAN in a different flow
             // Setup IP_HDRINCL to forge headers
             int one = 1;
             setsockopt(rawRecvSock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

             char datagram[128];
             memset(datagram, 0, 128);

             struct iphdr *iph = (struct iphdr *)datagram;
             struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
             struct pseudo_header psh;

             // Build IP Header
             iph->ihl = 5;
             iph->version = 4;
             iph->tos = 0;
             iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
             iph->id = htons(54321); 
             iph->frag_off = 0;
             iph->ttl = 255;
             iph->protocol = IPPROTO_TCP;
             iph->check = 0;      
             iph->saddr = sourceIp;
             iph->daddr = targetAddr.sin_addr.s_addr;
             iph->check = csum((unsigned short *)datagram, iph->tot_len);

             uint16_t srcPort = 12345 + (task.port % 10000);

             // Build TCP Header
             tcph->source = htons(srcPort);
             tcph->dest = targetAddr.sin_port;
             tcph->seq = 0;
             tcph->ack_seq = 0;
             tcph->doff = 5;  // tcp header size
             tcph->fin = 0;
             tcph->syn = 1;   // ONLY SYN
             tcph->rst = 0;
             tcph->psh = 0;
             tcph->ack = 0;
             tcph->urg = 0;
             tcph->window = htons(5840); // max window size
             tcph->check = 0; 
             tcph->urg_ptr = 0;

             // TCP Checksum pseudo-header
             psh.source_address = sourceIp;
             psh.dest_address = targetAddr.sin_addr.s_addr;
             psh.placeholder = 0;
             psh.protocol = IPPROTO_TCP;
             psh.tcp_length = htons(sizeof(struct tcphdr));

             int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
             char *pseudogram = new char[psize];
             memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
             memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

             tcph->check = csum((unsigned short *)pseudogram, psize);
             delete[] pseudogram;

             // Send the raw SYN packet
             sendto(rawRecvSock, datagram, iph->tot_len, 0, 
                   (struct sockaddr *)&targetAddr, sizeof(targetAddr));

             // Track SYN timeout manually
             synProbes[task.port] = InFlightProbe{
                  -task.port, task.port, Protocol::TCP, std::chrono::steady_clock::now(), 0};

             continue;
          }
          
          // Non-root fallback or simplified connect() scan wrapper
          int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
          if (sock < 0) {
            continue;
          }

          int connectResult =
              connect(sock, reinterpret_cast<struct sockaddr *>(&targetAddr), sizeof(targetAddr));

          if (connectResult == 0) {
            // Immediate connection established
            handleOpenPort(sock, task.port, Protocol::TCP);
            reportProgress(Protocol::TCP);
            close(sock);
          } else if (connectResult < 0 && errno == EINPROGRESS) {
            struct epoll_event ev{};
            ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP | EPOLLONESHOT;
            ev.data.fd = sock;

            if (epoll_ctl(epollFd, EPOLL_CTL_ADD, sock, &ev) == 0) {
              activeSockets[sock] = InFlightProbe{
                  sock, task.port, Protocol::TCP, std::chrono::steady_clock::now(), 0};
            } else {
              close(sock);
            }
          } else {
            close(sock);
          }
        } else { // Protocol::UDP
          int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
          if (sock < 0) {
            continue;
          }

          connect(sock, reinterpret_cast<struct sockaddr *>(&targetAddr), sizeof(targetAddr));

          // Send service-specific probe
          // 1. Check if we have custom payloads from Probes.ini
          auto customIt = config_.udpPayloads.find(task.port);
          if (customIt != config_.udpPayloads.end()) {
             for (const auto& p : customIt->second) {
                 send(sock, p.data(), p.size(), MSG_NOSIGNAL);
             }
          } else {
             // 2. Fallback to built-in UdpProbeDb
             const UdpProbe &udpProbe = UdpProbeDb::getProbeForPort(task.port);
             send(sock, udpProbe.payload.data(), udpProbe.payload.size(), MSG_NOSIGNAL);
          }

          struct epoll_event ev{};
          ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT;
          ev.data.fd = sock;

          if (epoll_ctl(epollFd, EPOLL_CTL_ADD, sock, &ev) == 0) {
            activeSockets[sock] = InFlightProbe{
                sock, task.port, Protocol::UDP, std::chrono::steady_clock::now(),
                config_.udpRetries};
          } else {
            close(sock);
          }
        }
      }

      if (activeSockets.empty() && synProbes.empty()) {
        break;
      }

      // 2. Poll events with epoll_wait (short timeout to handle socket timeouts accurately)
      int numEvents = epoll_wait(epollFd, events, MAX_EVENTS, 10);

      for (int i = 0; i < numEvents; ++i) {
        int fd = events[i].data.fd;

        // Handle raw receiving logic
        if (canUseRaw && fd == rawRecvSock) {
           char buf[4096];
           sockaddr_in saddr{};
           socklen_t saddr_len = sizeof(saddr);
           int recvBytes = recvfrom(rawRecvSock, buf, sizeof(buf), 0, (struct sockaddr*)&saddr, &saddr_len);
           
           if (recvBytes > 0) {
              struct iphdr *iph = (struct iphdr*)buf;
              if (iph->protocol == IPPROTO_TCP) {
                 struct tcphdr *tcph = (struct tcphdr*)(buf + (iph->ihl * 4));
                 int targetPort = ntohs(tcph->source);
                 
                 // If targeted IP matches our scan and it's a port we scanned
                 if (saddr.sin_addr.s_addr == targetAddr.sin_addr.s_addr && synProbes.count(targetPort)) {
                     // Check SYN-ACK flags
                     if (tcph->syn && tcph->ack) {
                         // Post-process to send custom payload if defined
                         auto payloadIt = config_.tcpPayloads.find(targetPort);
                         if (payloadIt != config_.tcpPayloads.end()) {
                             // Fallback to normal connect to send payload
                             int pSock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                             if (pSock >= 0) {
                                sockaddr_in pAddr{};
                                pAddr.sin_family = AF_INET;
                                pAddr.sin_addr.s_addr = targetAddr.sin_addr.s_addr;
                                pAddr.sin_port = htons(targetPort);

                                int pRes = connect(pSock, (struct sockaddr*)&pAddr, sizeof(pAddr));
                                if (pRes == 0) {
                                   for (const auto& p : payloadIt->second) {
                                       send(pSock, p.data(), p.size(), MSG_NOSIGNAL);
                                   }
                                   handleOpenPort(pSock, targetPort, Protocol::TCP);
                                   reportProgress(Protocol::TCP);
                                   close(pSock);
                                } else if (pRes < 0 && errno == EINPROGRESS) {
                                   // Just store it as standard SYN probe wrapper in activeSockets
                                   struct epoll_event evP{};
                                   evP.events = EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP | EPOLLONESHOT;
                                   evP.data.fd = pSock;
                                   if (epoll_ctl(epollFd, EPOLL_CTL_ADD, pSock, &evP) == 0) {
                                       // Needs payload dispatch mode
                                       activeSockets[pSock] = InFlightProbe{
                                          pSock, targetPort, Protocol::TCP, std::chrono::steady_clock::now(), -1}; // use -1 as payload flag
                                   } else { close(pSock); }
                                } else { close(pSock); }
                             }
                         } else {
                            // No custom payload needed, port is simply OPEN
                            handleOpenPort(-1, targetPort, Protocol::TCP);
                         }
                         reportProgress(Protocol::TCP);
                         synProbes.erase(targetPort);
                     } else if (tcph->rst) {
                         // Port is CLOSED
                         reportProgress(Protocol::TCP);
                         synProbes.erase(targetPort);
                     }
                 }
              }
           }
           continue;
        }

        auto it = activeSockets.find(fd);
        if (it == activeSockets.end()) {
          continue;
        }

        InFlightProbe probe = it->second;
        epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr);
        activeSockets.erase(it);

        if (probe.protocol == Protocol::TCP) {
          int soError = 0;
          socklen_t len = sizeof(soError);
          getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len);

          if (probe.retriesLeft == -1) {
              // This is a Payload connection probe
              if (soError == 0 && !(events[i].events & (EPOLLERR | EPOLLHUP))) {
                  // Connection established, send payload!
                  auto payloadIt = config_.tcpPayloads.find(probe.port);
                  if (payloadIt != config_.tcpPayloads.end()) {
                      for (const auto& p : payloadIt->second) {
                          send(fd, p.data(), p.size(), MSG_NOSIGNAL);
                      }
                      struct epoll_event evR{};
                      evR.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT;
                      evR.data.fd = fd;
                      epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &evR);
                      
                      // Change state so next epoll hit is the banner grab
                      probe.retriesLeft = -2; 
                      activeSockets[fd] = probe;
                      continue; // keep alive
                  }
              }
          } else if (probe.retriesLeft == -2) {
              // Target has replied to payload! Banner Grabbing.
              handleOpenPort(fd, probe.port, Protocol::TCP);
              close(fd);
              continue;
          }

          if (soError == 0 && !(events[i].events & (EPOLLERR | EPOLLHUP))) {
            // TCP full connect fallback success
            auto payloadIt = config_.tcpPayloads.find(probe.port);
            if (payloadIt != config_.tcpPayloads.end()) {
               for (const auto& p : payloadIt->second) {
                   send(fd, p.data(), p.size(), MSG_NOSIGNAL);
               }
               handleOpenPort(fd, probe.port, Protocol::TCP);
            } else {
               handleOpenPort(fd, probe.port, Protocol::TCP);
            }
          }
          reportProgress(Protocol::TCP);
        } else { // UDP
          int soError = 0;
          socklen_t len = sizeof(soError);
          getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len);

          if (soError == ECONNREFUSED) {
            // ICMP Port Unreachable received — port is definitively closed
            // No action needed, port is closed
          } else if (events[i].events & EPOLLIN) {
            // We got actual data back — read and validate the response
            uint8_t recvBuf[2048];
            ssize_t n = recv(fd, recvBuf, sizeof(recvBuf), 0);

            if (n > 0) {
              const auto *responseData = recvBuf;
              auto responseLen = static_cast<size_t>(n);

              // Try to validate with the port-specific probe first
              const UdpProbe &udpProbe = UdpProbeDb::getProbeForPort(probe.port);
              bool validated = udpProbe.validateResponse(responseData, responseLen);

              // Identify the service from response content
              std::string detectedService = UdpProbeDb::identifyFromResponse(
                  responseData, responseLen);
              if (detectedService.empty()) {
                detectedService = udpProbe.serviceName;
              }

              // Extract banner info
              std::string banner = UdpProbeDb::extractUdpBanner(
                  probe.port, responseData, responseLen);

              ScanStatus status = validated ? ScanStatus::OPEN : ScanStatus::OPEN_FILTERED;
              handleOpenPort(fd, probe.port, Protocol::UDP, status,
                             detectedService, banner);
            }
          } else if (events[i].events & EPOLLERR) {
            // Error event without ECONNREFUSED — likely filtered
            // Do not report as open
          }
          reportProgress(Protocol::UDP);
        }

        close(fd);
      }

      // 3. Check for timed out sockets
      auto now = std::chrono::steady_clock::now();
      for (auto it = activeSockets.begin(); it != activeSockets.end();) {
        const auto &probe = it->second;
        int timeoutMs = (probe.protocol == Protocol::TCP) ? config_.tcpTimeoutMs
                                                           : config_.udpTimeoutMs;
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - probe.startTime)
                             .count();

        if (elapsedMs >= timeoutMs) {
          if (probe.protocol == Protocol::UDP && probe.retriesLeft > 0) {
            // Retry: re-send the probe and reset the timer
            auto customIt = config_.udpPayloads.find(probe.port);
            if (customIt != config_.udpPayloads.end()) {
               for (const auto& p : customIt->second) {
                   send(probe.fd, p.data(), p.size(), MSG_NOSIGNAL);
               }
            } else {
               const UdpProbe &udpProbe = UdpProbeDb::getProbeForPort(probe.port);
               send(probe.fd, udpProbe.payload.data(), udpProbe.payload.size(), MSG_NOSIGNAL);
            }

            // Re-arm epoll for this socket
            struct epoll_event ev{};
            ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT;
            ev.data.fd = probe.fd;
            epoll_ctl(epollFd, EPOLL_CTL_MOD, probe.fd, &ev);

            it->second.startTime = now;
            it->second.retriesLeft--;
            ++it;
            continue;
          }

          epoll_ctl(epollFd, EPOLL_CTL_DEL, probe.fd, nullptr);
          if (probe.protocol == Protocol::UDP && UdpProbeDb::hasProbeForPort(probe.port)) {
            // Only report open|filtered for ports with known probes
            // Generic-probed ports that timeout are likely just filtered
            handleOpenPort(probe.fd, probe.port, Protocol::UDP,
                           ScanStatus::OPEN_FILTERED);
          }
          reportProgress(Protocol::UDP);
          close(probe.fd);
          it = activeSockets.erase(it);
        } else {
          ++it;
        }
      }

      // Check timeouts for SYN Probes
      for (auto synIt = synProbes.begin(); synIt != synProbes.end();) {
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - synIt->second.startTime).count();
        if (elapsedMs >= config_.tcpTimeoutMs) {
            reportProgress(Protocol::TCP);
            synIt = synProbes.erase(synIt);
        } else {
            ++synIt;
        }
      }
    }

    // Cleanup lingering connections
    for (const auto &[fd, probe] : activeSockets) {
      epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr);
      if (fd >= 0) close(fd);
    }
    close(epollFd);
  }
};