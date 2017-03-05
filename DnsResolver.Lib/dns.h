// File: dns.h
// Martin Fracker
// CSCE 463-500 Spring 2017
#pragma once

#include <Windows.h>
#include <memory>

namespace dns {

#define FLAG_RECURSIVE 1 << 8
#define FLAG_QUERY (0 << 15)
#define FLAG_STDQUERY (0 << 11)

#define TYPE_A 1
#define TYPE_PTR 12

#define CLASS_INET 1

#define MAX_PACKET_SIZE 512
#define MAX_ATTEMPTS 3

#pragma pack(push,1)
  struct FixedDNSheader {
    FixedDNSheader() = default;
    FixedDNSheader(char* buffer)
    {
      auto header = reinterpret_cast<FixedDNSheader*>(buffer);
      ID = ntohs(header->ID);
      flags = ntohs(header->flags);
      nQuestions = ntohs(header->nQuestions);
      nAnswers = ntohs(header->nAnswers);
      nAuthority = ntohs(header->nAuthority);
      nAdditional = ntohs(header->nAdditional);
    }
    USHORT ID = htons(0);
    USHORT flags = htons(0);
    USHORT nQuestions = htons(0);
    USHORT nAnswers = htons(0);
    USHORT nAuthority = htons(0);
    USHORT nAdditional = htons(0);
  };
  struct QueryHeader {
    USHORT _type = htons(0);
    USHORT _class = htons(0);
  };
  struct DNSanswerHeader {
    USHORT _type = htons(0);
    USHORT _class = htons(0);
    UINT _ttl = htons(0);
    USHORT _len = htons(0);
  };
#pragma pack(pop)

  void LookUp(char* host, char* dnsIp);
  void MakeDNSquestion(char* packet, char* host);
  char* MakeHostReverseIpLookup(char* host);
}
