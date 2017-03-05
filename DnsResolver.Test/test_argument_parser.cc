// File: test_argument_parser.cc
// Martin Fracker
// CSCE 463-500 Spring 2017

#include <gtest/gtest.h>

#include <ArgumentParser.h>

class ArgumentParserTests : public ::testing::Test
{
public:
  // Any necessary text fixture stuff goes here
};

TEST_F(ArgumentParserTests, IncorrectNumberOfArgumentsReturnsInvalid)
{
  ArgumentParser argsParser(2, nullptr);
  auto args = argsParser.Parse();
  EXPECT_FALSE(args.Valid);
}

TEST_F(ArgumentParserTests, CorrectNumberOfArgumentsReturnsArguments)
{
  char* rawArgs[] = { "program", "www", "com" };
  ArgumentParser argsParser(3, rawArgs);
  auto args = argsParser.Parse();
  EXPECT_TRUE(args.Valid);
  EXPECT_EQ(rawArgs[1], args.Host);
  EXPECT_EQ(rawArgs[2], args.DnsIp);
}
