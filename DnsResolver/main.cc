// File: main.cc
// Martin Fracker
// CSCE 463-500 Spring 2017

#include <libraries.h>
#include <iostream>

#include <ArgumentParser.h>
#include <dns.h>

void printUsage(char* programName)
{
  printf("Usage: %s <host> <dns ip>\n", programName);
  std::exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
  ArgumentParser argParser(argc, argv);
  auto args = argParser.Parse();
  if (!args.Valid)
    printUsage(argv[0]);
  dns::LookUp(args.Host, args.DnsIp);
}
