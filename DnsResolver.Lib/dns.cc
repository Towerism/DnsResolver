// File: dns.cc
// Martin Fracker
// CSCE 463-500 Spring 2017
#include "libraries.h"
#include "dns.h"
#include <cstdlib>
#include <cstdio>
#include <cmath>

void dns::LookUp(char* host, char* dnsIp)
{
  printf("Lookup  : %s\n", host);

  WSADATA wsaData;

  WORD wVersionRequested = MAKEWORD(2, 2);
  if (WSAStartup(wVersionRequested, &wsaData) != 0) {
    printf("WSAStartup error %d\n", WSAGetLastError());
    WSACleanup();
    std::exit(EXIT_FAILURE);
  }
  // plus 2 takes into account the empty 0 after host and the first number before host
  int size = sizeof(FixedDNSheader) + strlen(host) + 2 + sizeof(QueryHeader);
  char *pkt = new char[size];
  // if hostIp is not INADDR_NONE then we do type-A (1) lookup, otherwise we do PTR (2) lookup
  DWORD hostIp = inet_addr(host);
  if (hostIp == INADDR_NONE) // A
  {
    USHORT ID = rand();
    printf("Query   : %s, type 1, TXID 0x%.4X\n", host, ID);

    FixedDNSheader* dnsHeader = reinterpret_cast<FixedDNSheader*>(pkt);
    dnsHeader->ID = ID;
    dnsHeader->nQuestions = htons(1);
    dnsHeader->flags = RECURSIVE_FLAG;
    QueryHeader* queryHeader = reinterpret_cast<QueryHeader*>(pkt + size - sizeof(QueryHeader));
    queryHeader->_type = TYPE_A;
    queryHeader->_class = CLASS_INET;
    MakeDNSquestion(reinterpret_cast<char*>(dnsHeader + 1), host);
  } else // PTR
  {
    
  }

  printf("Server  : %s\n", dnsIp);
  printf("********************************\n");
  SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) {
    printf("socket() generated error %d\n", WSAGetLastError());
    WSACleanup();
    std::exit(EXIT_FAILURE);
  }
  struct sockaddr_in local;
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_port = htons(0);
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR) {
    printf("bind() failed with error %d\n", WSAGetLastError());
    WSACleanup();
    std::exit(EXIT_FAILURE);
  }
  struct sockaddr_in remote;
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(dnsIp); //server's IP
  remote.sin_port = htons(53); //DNS port on server

  int attempts = 0;
  int replySize = 0;
  char buffer[MAX_PACKET_SIZE + 1];
  memset(buffer, 0, MAX_PACKET_SIZE + 1);
  while (true)
  {
    if (attempts == MAX_ATTEMPTS)
      break;
    printf("Attempt %d with %d bytes... ", attempts, size);
    DWORD t = timeGetTime();
    if (sendto(sock, pkt, size, 0, reinterpret_cast<struct sockaddr*>(&remote), sizeof(remote)) == SOCKET_ERROR)
    {
      printf("sendto() failed with error %d\n", WSAGetLastError());
      WSACleanup();
      std::exit(EXIT_FAILURE);
    }
    fd_set readers;
    FD_ZERO(&readers);
    FD_SET(sock, &readers);
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    if (select(sock, &readers, nullptr, nullptr, &timeout) > 0)
    {
      struct sockaddr_in senderAddr;
      int senderAddrSize = sizeof(senderAddr);
      replySize = recvfrom(sock, buffer, MAX_PACKET_SIZE, 0, reinterpret_cast<struct sockaddr*>(&senderAddr), &senderAddrSize);
      if (replySize == SOCKET_ERROR)
      {
        printf("recvfrom() failed with error %d\n", WSAGetLastError());
        WSACleanup();
        std::exit(EXIT_FAILURE);
      }
      printf("response in %d ms with %d bytes\n", (timeGetTime() - t), replySize);
      break;
    }
    printf("timeout in %d ms\n", timeGetTime() - t);
    attempts += 1;
  }
  for (int i = 0; i < replySize; i++) {
    printf("packet[%d]: 0x%x\n", i, buffer[i]);
  }

  WSACleanup();
}

void dns::MakeDNSquestion(char* packet, char* host)
{
  // reject a host without at least one period
  if (strchr(host, '.') == nullptr)
    return;
  strcpy(packet + 1, host);
  packet[strlen(host) + 1] = 0;
  char* position = packet;
  char* period = nullptr;
  while (true) {
    period = strchr(position + 1, '.');
    if (period == nullptr)
      period = packet + strlen(host) + 1;
    *position = period - position - 1;
    position = period;
    if (*period == 0)
      break;
  }
}
