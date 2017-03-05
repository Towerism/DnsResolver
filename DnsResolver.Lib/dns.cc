// File: dns.cc
// Martin Fracker
// CSCE 463-500 Spring 2017
#include "libraries.h"
#include "dns.h"
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <sstream>

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
  size_t size = sizeof(FixedDNSheader) + 2 + sizeof(QueryHeader);
  DWORD hostIp = inet_addr(host);
  if (hostIp == INADDR_NONE) // A
  {
    size += strlen(host);
  } else // PTR
  {
    size += strlen(host) + strlen(".in-addr.arpa");
  }
  // plus 2 takes into account the empty 0 after host and the first number before host
  char *pkt = new char[size];
  memset(pkt, 0, size);
  srand(time(0));
  USHORT ID = rand();
  FixedDNSheader* dnsHeader = reinterpret_cast<FixedDNSheader*>(pkt);
  QueryHeader* queryHeader = reinterpret_cast<QueryHeader*>(pkt + size - sizeof(QueryHeader));
  dnsHeader->ID = htons(ID);
  dnsHeader->nQuestions = htons(1);
  dnsHeader->flags = htons(FLAG_RECURSIVE | FLAG_QUERY | FLAG_STDQUERY);
  queryHeader->_class = htons(CLASS_INET);
  // if hostIp is not INADDR_NONE then we do type-A (1) lookup, otherwise we do PTR (2) lookup
  if (hostIp == INADDR_NONE) // A
  {
    printf("Query   : %s, type 1, TXID 0x%.4X\n", host, ID);
    queryHeader->_type = htons(TYPE_A);
    MakeDNSquestion(reinterpret_cast<char*>(dnsHeader + 1), host);
  } else // PTR
  {
    queryHeader->_type = htons(TYPE_PTR);
    char* reverseLookupHost = MakeHostReverseIpLookup(host);
    printf("Query   : %s, type 12, TXID 0x%.4X\n", reverseLookupHost, ID);
    MakeDNSquestion(reinterpret_cast<char*>(dnsHeader + 1), reverseLookupHost);
    delete[] reverseLookupHost;
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
    if (select(sock, &readers, nullptr, nullptr, &timeout) > 0u)
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
      if (memcmp(&senderAddr.sin_addr, &remote.sin_addr, sizeof(DWORD)) || senderAddr.sin_port != senderAddr.sin_port)
      {
        printf("mismatch on server ip or port\n");
        WSACleanup();
        std::exit(EXIT_FAILURE);
      }
      printf("response in %d ms with %d bytes\n", (timeGetTime() - t), replySize);
      FixedDNSheader replyHeader(buffer);
      printf("  TXID 0x%.4X flags 0x%hu questions %hu answers %hu authority %hu additional %hu\n",
        replyHeader.ID, replyHeader.flags, replyHeader.nQuestions, replyHeader.nAnswers, replyHeader.nAuthority, replyHeader.nAdditional);
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

char* dns::MakeHostReverseIpLookup(char* host)
{
  size_t reverseIpLookupLength = strlen(host) + strlen(".in-addr.arpa") + 1;
  char* reverseIpLookup = new char[reverseIpLookupLength];
  memset(reverseIpLookup, 0, reverseIpLookupLength);
  USHORT w, x, y, z;
  sscanf(host, "%hu.%hu.%hu.%hu", &w, &x, &y, &z);
  snprintf(reverseIpLookup, reverseIpLookupLength, "%hu.%hu.%hu.%hu.in-addr.arpa", z, y, x, w);
  return reverseIpLookup;
}

void dns::MakeDNSquestion(char* packet, char* host)
{
  // reject a host without at least one period
  if (strchr(host, '.') == nullptr)
    return;
  strcpy(packet + 1, host);
  size_t len = strlen(host);
  packet[len + 1] = 0;
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
