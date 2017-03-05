// File: test_make_reverse_lookup_question.cc
// Martin Fracker
// CSCE 463-500 Spring 2017

#include <gtest/gtest.h>

#include "dns.h"

TEST(MakeReverseLookupQuestionTests, ReplacesAllPeriodOccurencesForReverseLookup) {
  char question[100];
  memset(question, 0xFF, 100);
  char* host = "123.456.789.12";
  auto reverseLookup = dns::MakeHostReverseIpLookup(host);
  dns::MakeDNSquestion(question, reverseLookup.get());
  EXPECT_EQ("\x02""12\x03""789\x03""456\x03""123\x07""in-addr\x04""arpa", std::string(question));
}
