// File: dns.h
// Martin Fracker
// CSCE 463-500 Spring 2017
#pragma once

#include <Windows.h>

namespace dns {

#define RECURSIVE_FLAG 1 << 8
#define TYPE_A 1
#define TYPE_PTR 12
#define CLASS_INET 1
#define MAX_PACKET_SIZE 512
#define MAX_ATTEMPTS 3

#pragma pack(push,1)
  struct FixedDNSheader {
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
}
