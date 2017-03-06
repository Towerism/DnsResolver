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
  size_t size;
  char* pkt;
  USHORT txid = MakePacket(host, size, pkt);

  printf("Server  : %s\n", dnsIp);
  printf("********************************\n");
  SOCKET sock;
  sockaddr_in remote;
  if (SetupSocket(dnsIp, sock, remote)) return;

  SendPacketUnreliablyAndParseReply(size, pkt, sock, remote, txid);
}

USHORT dns::MakePacket(char* host, size_t& size, char*& pkt)
{
  size = sizeof(FixedDNSheader) + 2 + sizeof(QueryHeader);
  DWORD hostIp = inet_addr(host);
  if (hostIp == INADDR_NONE) // A
  {
    size += strlen(host);
  } else // PTR
  {
    size += strlen(host) + strlen(".in-addr.arpa");
  }
  pkt = new char[size];
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
  return ID;
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

bool dns::SetupSocket(char* dnsIp, SOCKET& sock, sockaddr_in& remote)
{
  sock = socket(AF_INET, SOCK_DGRAM, 0);
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
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(dnsIp); //server's IP
  remote.sin_port = htons(53); //DNS port on server
  return false;
}

void dns::SendPacketUnreliablyAndParseReply(size_t size, char* pkt, SOCKET sock, sockaddr_in remote, USHORT txid)
{
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
    SendPacket(size, pkt, sock, remote);
    if (AttemptToReceiveAndParseReply(sock, remote, replySize, buffer, t, txid)) return;
    printf("timeout in %d ms\n", timeGetTime() - t);
    attempts += 1;
  }
}

void dns::SendPacket(size_t size, char* pkt, SOCKET sock, sockaddr_in remote)
{
  if (sendto(sock, pkt, size, 0, (struct sockaddr*)(&remote), sizeof(remote)) == SOCKET_ERROR)
  {
    printf("sendto() failed with error %d\n", WSAGetLastError());
    WSACleanup();
    std::exit(EXIT_FAILURE);
  }
}

bool dns::AttemptToReceiveAndParseReply(SOCKET sock, sockaddr_in remote, size_t replySize, char buffer[513], DWORD t, USHORT txid)
{
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
    PrintAnyReceptionErrors(remote, replySize, senderAddr);
    printf("response in %d ms with %zu bytes\n", (timeGetTime() - t), replySize);
    dns::ParseDnsReply(buffer, replySize, txid);

    return true;
  }
  return false;
}

void dns::PrintAnyReceptionErrors(sockaddr_in remote, size_t replySize, sockaddr_in senderAddr)
{
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
}

void dns::ParseDnsReply(char buffer[513], size_t replySize, USHORT txid)
{
  auto replyHeader = new FixedDNSheader(buffer);
  printf("  TXID 0x%.4X flags 0x%hu questions %hu answers %hu authority %hu additional %hu\n",
         replyHeader->ID, replyHeader->flags, replyHeader->nQuestions, replyHeader->nAnswers, replyHeader->nAuthority, replyHeader->nAdditional);
  if (replySize < sizeof(FixedDNSheader))
    PrintInvalidMessage("reply", "smaller than fixed header");
  if (replyHeader->ID != txid)
    PrintInvalidMessage("reply", "TXID mismatch, sent 0x%.4X, received 0x%.4X", txid, replyHeader->ID);
  USHORT returnCode = replyHeader->flags & MASK_FLAG_RETURNCODE;
  if (returnCode == 0)
    printf("  succeeded with Rcode = 0\n");
  else {
    printf("  failed with Rcode = %hu\n", returnCode);
    return;
  }
  char* question = (char*)(buffer + sizeof(FixedDNSheader));
  size_t position = 0;
  ParseQuestions(replyHeader, question, position);
  UCHAR* cursor = (UCHAR*)(question + position);
  ParseResourceRecords("answers", buffer, replySize, cursor, replyHeader->nAnswers);
  ParseResourceRecords("authority", buffer, replySize, cursor, replyHeader->nAuthority);
  ParseResourceRecords("additional", buffer, replySize, cursor, replyHeader->nAdditional);
}

void dns::PrintInvalidMessage(const char* invalidType, const char* messageFormat, ...)
{
  printf("\n  ++ invalid %s: ", invalidType);
  va_list args;
  va_start(args, messageFormat);
  vprintf(messageFormat, args);
  va_end(args);
  printf("\n");
  std::exit(EXIT_FAILURE);
}

void dns::ParseQuestions(FixedDNSheader* replyHeader, char* question, size_t& position)
{
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
}

bool CursorOverflowed(char* buffer, size_t replySize, UCHAR* cursor)
{
  return (char*)cursor >= buffer + replySize;
}

void dns::ParseResourceRecords(const char* heading, char* buffer, size_t replySize, UCHAR*& cursor, UINT answers)
{
  size_t parsedAnswers = 0;
  USHORT type = TYPE_NULL;
  UINT ttl = TTL_NULL;
  std::deque<UCHAR*> returnCursors;
  if (answers == 0)
    return;
  printf("   ------------ [%s] ----------\n", heading);
  DNSanswerHeader* answer = nullptr;
  for (int i = 0; i < answers << 1; ++i)
  {
    // if i is even we are printing the question,
    // otherwise we are printing the answer
    bool printingQuestion = i % 2 == 0;
    if (printingQuestion)
    {
      printf("        ");
    }
    size_t nRecursiveJumps = 0;
    std::ostringstream oss;
    do 
    {
      if (CursorOverflowed(buffer, replySize, cursor + 1))
        PrintInvalidMessage("record", "truncated jump offset");
      USHORT jumpIdentifier = ntohs(*(USHORT*)cursor);
      USHORT offset = jumpIdentifier & MASK_JUMP_OFFSET; // offset from buffer
      if (jumpIdentifier >= MASK_JUMP_START && type != TYPE_A) 
      {
        if ((char*)cursor >= buffer + replySize)
          PrintInvalidMessage("record", "jump beyond packet boundary");
        if (offset < sizeof(FixedDNSheader))
          PrintInvalidMessage("record", "jump into fixed header");
        returnCursors.push_back(cursor + 2);
        cursor = (UCHAR*)(buffer + offset);
      } else
      {
        USHORT labelLength = 0;
        do 
        {
          if (CursorOverflowed(buffer, replySize, cursor + 0))
            PrintInvalidMessage("record", "truncated name");
          labelLength = *cursor;
          // jump mid answer
          if (labelLength == IDENTIFIER_JUMP_START) {
            ++nRecursiveJumps;
            if (nRecursiveJumps > replySize)
              PrintInvalidMessage("record", "jump loop");
            break;
          }
          if (type != TYPE_A) {
            if (labelLength > 0 && CursorOverflowed(buffer, replySize, cursor + 1))
              PrintInvalidMessage("record", "truncated name");
            char* label = new char[labelLength + 1];
            memset(label, 0, labelLength + 1);
            sprintf(label, "%.*s", labelLength, (char*)(cursor + 1));
            oss << std::string(label);
          } else
          {
            type = TYPE_LIMBO;
            oss << GetIp(ntohl(*(UINT*)(cursor)));
            cursor += sizeof(UINT);
            break;
          }
          if ((char*)cursor < buffer + replySize && *cursor != 0)
            cursor += labelLength + 1;
          if ((char*)cursor < buffer + replySize && *cursor != 0)
            oss << '.';
        } while (labelLength != 0);
      }
    } while ((char*)cursor < buffer + replySize && *cursor != 0 && type != TYPE_LIMBO);
    if (!returnCursors.empty())
    {
      // always return to the point after the original jump
      cursor = returnCursors.front();
      returnCursors.clear();
    }
    if (printingQuestion) {
      if (CursorOverflowed(buffer, replySize, cursor))
        PrintInvalidMessage("record", "truncated fixed RR header");
      if (*(USHORT*)cursor == 0)
        ++cursor;
      answer = new DNSanswerHeader(cursor);
    }
    if (answer != nullptr)
    {
      if (answer->TypeIsSupported())
      {
        printf("%s", std::string(oss.str()).c_str());
        oss.clear();
      } else {
        ++parsedAnswers;
        ++i;
        continue;
      }
    }
    if (printingQuestion) 
    {
      type = answer->PrintType();
      ttl = answer->_ttl;
      cursor += sizeof(DNSanswerHeader);
      if (CursorOverflowed(buffer, replySize, cursor + answer->_len - 1))
        PrintInvalidMessage("record", "RR value length beyond packet");
    } else
    {
      ++parsedAnswers;
      type = TYPE_NULL;
      answer = nullptr;
      printf(" TTL = %d \n", ttl);
      // don't advance cursor if we have to jump again
      if (*cursor != IDENTIFIER_JUMP_START)
      {
        cursor += 1;
      }
    }
  }
  if (parsedAnswers < answers)
    PrintInvalidMessage("record", "not enough records");
}

std::string dns::GetIp(UINT binary)
{
  std::ostringstream oss;
  oss << ((binary >> 0x18) & 0xFF) << ".";
  oss << ((binary >> 0x10) & 0xFF) << ".";
  oss << ((binary >> 0x08) & 0xFF) << ".";
  oss << (binary & 0xFF);
  return std::string(oss.str());
}
