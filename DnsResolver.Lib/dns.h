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
#define MASK_FLAG_RETURNCODE 0x000F

#define IDENTIFIER_JUMP_START 0xC0
#define MASK_JUMP_START (IDENTIFIER_JUMP_START << 8)
#define MASK_JUMP_OFFSET 0x3FFF

#define TYPE_LIMBO 0xFF // not null but also not a type
#define TYPE_NULL 0
#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_PTR 12

#define CLASS_INET 1

#define MAX_PACKET_SIZE 512
#define MAX_ATTEMPTS 3
#define TTL_NULL -1

#pragma pack(push,1)
  struct FixedDNSheader {
    FixedDNSheader(char* buffer)
    {
      auto header = (FixedDNSheader*)(buffer);
      ID = ntohs(header->ID);
      flags = ntohs(header->flags);
      nQuestions = ntohs(header->nQuestions);
      nAnswers = ntohs(header->nAnswers);
      nAuthority = ntohs(header->nAuthority);
      nAdditional = ntohs(header->nAdditional);
    }
    USHORT ID = 0;
    USHORT flags = 0;
    USHORT nQuestions = 0;
    USHORT nAnswers = 0;
    USHORT nAuthority = 0;
    USHORT nAdditional = 0;
  };
  struct QueryHeader {
    QueryHeader(char* buffer)
    {
      auto header = (QueryHeader*)(buffer);
      _type = ntohs(header->_type);
      _class = ntohs(header->_class);
    }
    USHORT _type = 0;
    USHORT _class = 0;
  };
  struct DNSanswerHeader {
    DNSanswerHeader(UCHAR* buffer)
    {
      auto header = (DNSanswerHeader*)buffer;
      _type = ntohs(header->_type);
      _class = ntohs(header->_class);
      _ttl = ntohl(header->_ttl);
      _len = ntohs(header->_len);
    }
    USHORT _type = 0;
    USHORT _class = 0;
    UINT _ttl = 0;
    USHORT _len = 0;
    USHORT PrintType() const
    {
      if (_type == TYPE_A)
      {
        printf(" A ");
      } else if (_type == TYPE_NS)
      {
        printf(" NS ");
      } else if (_type == TYPE_CNAME)
      {
        printf(" CNAME ");
      } else if (_type == TYPE_PTR)
      {
        printf(" PTR ");
      } else
      {
        printf(" UNSUPPORTED TYPE\n");
      }
      return _type;
    }
  };
#pragma pack(pop)

  void LookUp(char* host, char* dnsIp);
  void MakeDNSquestion(char* packet, char* host);
  char* MakeHostReverseIpLookup(char* host);
  void ParseDnsReply(char buffer[513], FixedDNSheader* replyHeader, size_t replySize);
  void PrintIp(UINT binary);
}
