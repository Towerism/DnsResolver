// File: dns.cc
// Martin Fracker
// CSCE 463-500 Spring 2017
#include "libraries.h"
#include "dns.h"
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <sstream>
#include <deque>


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
  size_t size = sizeof(FixedDNSheader) + 2 + sizeof(QueryHeader);
  DWORD hostIp = inet_addr(host);
  if (hostIp == INADDR_NONE) // A
  {
    size += strlen(host);
  } else // PTR
  {
    size += strlen(host) + strlen(".in-addr.arpa");
  }
  char *pkt = new char[size];
  memset(pkt, 0, size);
  srand(time(0));
  USHORT ID = rand();
  FixedDNSheader* dnsHeader = (FixedDNSheader*)(pkt);
  QueryHeader* queryHeader = (QueryHeader*)(pkt + size - sizeof(QueryHeader));
  dnsHeader->ID = htons(ID);
  dnsHeader->nQuestions = htons(1);
  dnsHeader->flags = htons(FLAG_RECURSIVE | FLAG_QUERY | FLAG_STDQUERY);
  queryHeader->_class = htons(CLASS_INET);
  // if hostIp is not INADDR_NONE then we do type-A (1) lookup, otherwise we do PTR (2) lookup
  if (hostIp == INADDR_NONE) // A
  {
    printf("Query   : %s, type 1, TXID 0x%.4X\n", host, ID);
    queryHeader->_type = htons(TYPE_A);
    MakeDNSquestion((char*)(dnsHeader + 1), host);
  } else // PTR
  {
    queryHeader->_type = htons(TYPE_PTR);
    char* reverseLookupHost = MakeHostReverseIpLookup(host);
    printf("Query   : %s, type 12, TXID 0x%.4X\n", reverseLookupHost, ID);
    MakeDNSquestion((char*)(dnsHeader + 1), reverseLookupHost);
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
  if (bind(sock, (struct sockaddr*)(&local), sizeof(local)) == SOCKET_ERROR) {
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
  size_t replySize = 0;
  char buffer[MAX_PACKET_SIZE + 1];
  memset(buffer, 0, MAX_PACKET_SIZE + 1);
  while (true)
  {
    if (attempts == MAX_ATTEMPTS)
      break;
    printf("Attempt %d with %d bytes... ", attempts, size);
    DWORD t = timeGetTime();
    if (sendto(sock, pkt, size, 0, (struct sockaddr*)(&remote), sizeof(remote)) == SOCKET_ERROR)
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
      replySize = recvfrom(sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr*)(&senderAddr), &senderAddrSize);
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
      WSACleanup();
      auto replyHeader = new dns::FixedDNSheader(buffer);
      printf("response in %d ms with %d bytes\n", (timeGetTime() - t), replySize);
      ParseDnsReply(buffer, replyHeader);

      return;
    }
    printf("timeout in %d ms\n", timeGetTime() - t);
    attempts += 1;
  }
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

void dns::ParseDnsReply(char buffer[513], FixedDNSheader* replyHeader)
{
  printf("  TXID 0x%.4X flags 0x%hu questions %hu answers %hu authority %hu additional %hu\n",
         replyHeader->ID, replyHeader->flags, replyHeader->nQuestions, replyHeader->nAnswers, replyHeader->nAuthority, replyHeader->nAdditional);
  USHORT returnCode = replyHeader->flags & MASK_FLAG_RETURNCODE;
  if (returnCode == 0)
    printf("  succeeded with Rcode = 0\n");
  else
    printf("  failed with Rcode = %hu\n", returnCode);
  char* question = (char*)(buffer + sizeof(FixedDNSheader));
  size_t position = 0;
  if (replyHeader->nQuestions > 0)
    printf("   ------------ [questions] ----------\n");
  for (int i = 0; i < replyHeader->nQuestions; ++i)
  {
    printf("        ");
    int labelLength;
    do
    {
      labelLength = question[position];
      printf("%.*s", labelLength, question + position + 1);
      position += labelLength + 1;
      if (question[position] != 0)
        printf(".");
    } while (labelLength != 0);
    QueryHeader* query = new QueryHeader(question + position);
    printf(" type %hu class %hu\n", query->_type, query->_class);

    position += sizeof(QueryHeader);
  }
  UCHAR* cursor = (UCHAR*)(question + position);
  UCHAR* returnCursor = nullptr;
  int ttl = TTL_NULL;
  USHORT type = TYPE_NULL;
  UINT answers = replyHeader->nAnswers;
  std::deque<UCHAR*> returnCursors;
  if (answers == 0)
    return;
  printf("   ------------ [answers] ----------\n");
  for (int i = 0; i < answers << 1; ++i)
  {
    // if i is even we are printing the answer,
    // otherwise we are printing the question
    bool printingAnswer = i % 2 == 0;
    if (printingAnswer)
    {
      printf("        ");
    }
    do 
    {
      USHORT jumpIdentifier = ntohs(*(USHORT*)cursor);
      USHORT offset = jumpIdentifier & MASK_JUMP_OFFSET; // offset from buffer
      if (jumpIdentifier >= MASK_JUMP_START) 
      {
        returnCursors.push_back(cursor + 2);
        cursor = (UCHAR*)(buffer + offset);
      } else
      {
        USHORT labelLength = 0;
        do 
        {
          labelLength = *cursor;
          // jump mid answer
          if (labelLength == IDENTIFIER_JUMP_START) {
            break;
          }
          if (type != TYPE_A) {
            printf("%.*s", labelLength, (char*)(cursor + 1));
          } else
          {
            PrintIp(ntohl(*(UINT*)(cursor)));
            cursor += sizeof(UINT);
            break;
          }
          if (*cursor != 0)
            cursor += labelLength + 1;
          if (*cursor != 0)
            printf(".");
        } while (labelLength != 0);
      }
    } while (*cursor != 0);
    if (!returnCursors.empty())
    {
      // always return to the point after the original jump
      cursor = returnCursors.front();
      returnCursors.clear();
    }
    if (printingAnswer) 
    {
      DNSanswerHeader* answer = new DNSanswerHeader(cursor);
      type = answer->PrintType();
      ttl = answer->_ttl;
      cursor += sizeof(DNSanswerHeader);
    } else
    {
      printf(" TTL = %d \n", ttl);
      // don't advance cursor if we have to jump again
      if (*cursor != IDENTIFIER_JUMP_START)
      {
        cursor += 1;
      }
    }
  }
}

void dns::PrintIp(UINT binary)
{
  printf("%u.", (binary >> 0x18) & 0xFF);
  printf("%u.", (binary >> 0x10) & 0xFF);
  printf("%u.", (binary >> 0x08) & 0xFF);
  printf("%u", binary & 0xFF);
}
