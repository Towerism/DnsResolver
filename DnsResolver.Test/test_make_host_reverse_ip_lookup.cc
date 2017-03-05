// File: test_make_host_reverse_ip_lookup.cc
// Martin Fracker
// CSCE 463-500 Spring 2017
#include <gtest/gtest.h>
#include <dns.h>

class MakeHostReverseIpLookupTests : public ::testing::Test
{
public:
  // test fixture if needed
};

TEST_F(MakeHostReverseIpLookupTests, ReturnsReverseIpLookupFromHost)
{
  char* host = "123.456.789.12";
  auto reverseLookup = dns::MakeHostReverseIpLookup(host);
  EXPECT_EQ("12.789.456.123.in-addr.arpa", std::string(reverseLookup.get()));
}