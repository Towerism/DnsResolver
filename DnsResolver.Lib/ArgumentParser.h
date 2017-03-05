// File: ArgumentParser.h
// Martin Fracker
// CSCE 463-500 Spring 2017
#pragma once

struct Arguments
{
  char* Host = nullptr;
  char* DnsIp = nullptr;
  bool Valid = true;
};

class ArgumentParser
{
public:
  ArgumentParser(int argc, char** argv) : argc(argc), argv(argv) {}

  Arguments Parse() const;
private:
  int argc;
  char** argv;
};
