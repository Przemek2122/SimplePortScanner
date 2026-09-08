#pragma once

#include <algorithm>
#include <cctype>
#include <mutex>
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>

#include "Config.h"

/** Handles service resolution and payload analysis */
class ServiceAnalyzer {
public:
  /** Resolves standard service names from local system mapping */
  static std::string lookupServiceName(int port, Protocol proto) {
    std::lock_guard<std::mutex> lock(lookupMutex_);
    const char *protoStr = (proto == Protocol::TCP) ? "tcp" : "udp";
    struct servent *service = getservbyport(htons(port), protoStr);

    if (service != nullptr) {
      return service->s_name;
    }

    return "unknown";
  }

  /** Attempts to extract application banners from TCP streams */
  static std::string grabTcpBanner(int sockfd, int timeoutMs) {
    std::string banner = readFromSocket(sockfd, timeoutMs);

    if (banner.empty()) {
      sendHttpProbe(sockfd);
      banner = readFromSocket(sockfd, timeoutMs);
    }

    return cleanBannerString(banner);
  }

private:
  inline static std::mutex lookupMutex_;

  static std::string readFromSocket(int sockfd, int timeoutMs) {
    struct pollfd pfd{};
    pfd.fd = sockfd;
    pfd.events = POLLIN;

    int pollResult = poll(&pfd, 1, timeoutMs);

    if (pollResult > 0 && (pfd.revents & POLLIN)) {
      char buffer[1024];
      ssize_t bytesRead = recv(sockfd, buffer, sizeof(buffer) - 1, 0);

      if (bytesRead > 0) {
        buffer[bytesRead] = '\0';
        return std::string(buffer);
      }
    }

    return "";
  }

  static void sendHttpProbe(int sockfd) {
    std::string probe = "HEAD / HTTP/1.0\r\n\r\n";
    send(sockfd, probe.c_str(), probe.length(), 0);
  }

  static std::string cleanBannerString(const std::string &raw) {
    if (raw.empty()) {
      return "";
    }

    std::string clean = raw;

    std::replace(clean.begin(), clean.end(), '\n', ' ');
    std::replace(clean.begin(), clean.end(), '\r', ' ');

    clean.erase(
        std::remove_if(clean.begin(), clean.end(),
                       [](unsigned char c) { return !std::isprint(c); }),
        clean.end());

    if (clean.length() > 60) {
      clean = clean.substr(0, 57) + "...";
    }

    return clean;
  }
};