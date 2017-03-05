// File: ArgumentParser.cc
// Martin Fracker
// CSCE 463-500 Spring 2017
#include "ArgumentParser.h"

Arguments ArgumentParser::Parse() const
{
  Arguments args;
  if (argc != 3) {
    args.Valid = false;
    return args;
  }
  args.Host = argv[1];
  args.DnsIp = argv[2];
  return args;
}
