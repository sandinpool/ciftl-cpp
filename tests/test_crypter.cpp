#include <vector>
#include <gtest/gtest.h>
#include <ciftl/encoding/encoding.h>
#include <ciftl/crypter/crypter.h>
#include "test.h"


TEST(TestCrypter, TestMockCipherAlgorithm)
{
    ciftl::StreamGenerator<ciftl::MockCipherAlgorithm> sg(nullptr, 16, nullptr, 16, ciftl::StreamGeneratorMode::Short);
    ciftl::ByteVector buffer(32);
    EXPECT_TRUE(sg.generate(buffer).is_ok());
    // 测试StringCrypter
    ciftl::StringCrypter<ciftl::MockCipherAlgorithm> sc;
    auto encrypted_result = sc.encrypt("123456", "123456").unwrap();
    GTEST_LOG_(INFO) << fmt::format("Encrypted Result: {}", encrypted_result);
    auto decrypted_result = sc.decrypt("w8Erj4lT9jI24N3gVVjVqcs8eAx8f355eHs=", "123456").unwrap();
    EXPECT_EQ("123456", decrypted_result);
    GTEST_LOG_(INFO) << fmt::format("Decrypted Result: {}", decrypted_result);
}

TEST(TestCrypter, TestChaCha20)
{
    // 测试StreamGenerator
    ciftl::StreamGenerator<ciftl::ChaCha20CipherAlgorithm> sg((const ciftl::byte *) "AAAAAAAAAAAA", 12,
                                                              (const ciftl::byte *) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                                              32,
                                                              ciftl::StreamGeneratorMode::Short);
    ciftl::ByteVector chacha20_cipher_buffer(32);
    sg.generate(chacha20_cipher_buffer);
    // 测试StringCrypter
    ciftl::StringCrypter<ciftl::ChaCha20CipherAlgorithm> sc;
    auto encrypted_result = sc.encrypt("123456", "123456").unwrap();
    GTEST_LOG_(INFO) << fmt::format("Encrypted Result: {}", encrypted_result);
    auto decrypted_result = sc.decrypt("e2fT1ou13uSN0TMXyVtS19nAC82sRV1R5Ktk", "123456").unwrap();
    EXPECT_EQ("ABCDEFGHIJK", decrypted_result);
    GTEST_LOG_(INFO) << fmt::format("Decrypted Result: {}", decrypted_result);
    EXPECT_TRUE(sc.decrypt("e2fT1ou13uSN1TMXyVtS19nAC82sRV1R5Ktk", "123456").is_err());
}

TEST(TestCrypter, TestAES128)
{
    // 测试StringCrypter
    ciftl::StringCrypter<ciftl::OpenSSLAES128OFBCipherAlgorithm> sc;
    auto encrypted_result = sc.encrypt("123456", "123456").unwrap();
    GTEST_LOG_(INFO) << fmt::format("Encrypted Result: {}", encrypted_result);
    auto decrypted_result = sc.decrypt("iYW3Juua4HKBTwcdP643U0bYm7UySIvmH52W3ukzjQ==", "123456").unwrap();
    EXPECT_EQ("ABCDEFGHIJK", decrypted_result);
    GTEST_LOG_(INFO) << fmt::format("Decrypted Result: {}", decrypted_result);
    EXPECT_TRUE(sc.decrypt("iYW3Juua5HKBTwcdP643U0bYm7UySIvmH52W3ukzjQ==", "123456").is_err());
}

TEST(TestCrypter, TestAES192)
{
    // 测试StringCrypter
    ciftl::StringCrypter<ciftl::OpenSSLAES192OFBCipherAlgorithm> sc;
    auto encrypted_result = sc.encrypt("123456", "123456").unwrap();
    GTEST_LOG_(INFO) << fmt::format("Encrypted Result: {}", encrypted_result);
    auto decrypted_result = sc.decrypt("ZlgK0r/HgOAkZn/KS9EuWM1mTRk0WqPbX+yWeMFo3Q==", "123456").unwrap();
    EXPECT_EQ("ABCDEFGHIJK", decrypted_result);
    GTEST_LOG_(INFO) << fmt::format("Decrypted Result: {}", decrypted_result);
    EXPECT_TRUE(sc.decrypt("ZlgK0r/Hg1AkZn/KS9EuWM1mTRk0WqPbX+yWeMFo3Q==", "123456").is_err());
}

TEST(TestCrypter, TestAES256)
{
    // 测试StringCrypter
    ciftl::StringCrypter<ciftl::OpenSSLAES256OFBCipherAlgorithm> sc;
    auto encrypted_result = sc.encrypt("123456", "123456").unwrap();
    GTEST_LOG_(INFO) << fmt::format("Encrypted Result: {}", encrypted_result);
    auto decrypted_result = sc.decrypt("Q0izd0rYEQcd7FWMZxqGjNctTzpABGbd1RJZQ9BZ2Q==", "123456").unwrap();
    EXPECT_EQ("ABCDEFGHIJK", decrypted_result);
    GTEST_LOG_(INFO) << fmt::format("Decrypted Result: {}", decrypted_result);
    EXPECT_TRUE(sc.decrypt("Q0izd0rYEQcd7EWMZxqGjNctTzpABGbd1RJZQ9BZ2Q==", "123456").is_err());
}

TEST(TestCrypter, TestSM4)
{
    // 测试StringCrypter
    ciftl::StringCrypter<ciftl::OpenSSLSM4OFBCipherAlgorithm> sc;
    auto encrypted_result = sc.encrypt("123456", "123456").unwrap();
    GTEST_LOG_(INFO) << fmt::format("Encrypted Result: {}", encrypted_result);
    auto decrypted_result = sc.decrypt("9PL2/F6R7XjwFLDHhZpbA+I7+vtwJ8GmgcvaaWgK6g==", "123456").unwrap();
    EXPECT_EQ("ABCDEFGHIJK", decrypted_result);
    GTEST_LOG_(INFO) << fmt::format("Decrypted Result: {}", decrypted_result);
    EXPECT_TRUE(sc.decrypt("9PL2/F6R7XjwFLDHhZpbA+17+vtwJ8GmgcvaaWgK6g==", "123456").is_err());
}
