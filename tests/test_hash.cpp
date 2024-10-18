#include <vector>
#include <gtest/gtest.h>
#include <ciftl/encoding/encoding.h>
#include <ciftl/crypter/crypter.h>
#include <ciftl/hash/hash.h>
#include "test.h"

using namespace ciftl;

TEST(TestHash, TestHasher)
{
    MD5Hasher md5;
    md5.update("123");
    md5.update("456");
    ByteVector res = md5.finalize();
    HexEncoding he;
    auto str = he.encode(res);
    ASSERT_EQ(str, "E10ADC3949BA59ABBE56E057F20F883E");
}
