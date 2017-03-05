// File: test_make_dns_question.cc
// Martin Fracker
// CSCE 463-500 Spring 2017

#include <gtest/gtest.h>

#include "dns.h"

class MakeDnsQuestionTests : public ::testing::Test {
public:
  MakeDnsQuestionTests() {
    memset(question, 0xFF, 100);

    dns::MakeDNSquestion(question, host);
  }
  char question[100];
  char* host = "www.cs.whatever.blaah.blaaah.tamu.edu";
};

TEST_F(MakeDnsQuestionTests, AddsBeginningLengthByte) {
  EXPECT_EQ(3, question[0]);
}

TEST_F(MakeDnsQuestionTests, AddsNullTerminator) {
  EXPECT_EQ(0, question[strlen(host) + 1]);
}

TEST_F(MakeDnsQuestionTests, ReplacesFirstPeriodOccurence) {
  EXPECT_EQ(2, question[4]);
}

TEST_F(MakeDnsQuestionTests, ReplacesAllPeriodOccurences) {
  EXPECT_EQ("\x03""www\x02""cs\x08""whatever\x05""blaah\x06""blaaah\x04""tamu\x03""edu", std::string(question));
}
