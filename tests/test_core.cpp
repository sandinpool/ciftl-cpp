#include <gtest/gtest.h>
#include <ciftl/encoding/encoding.h>
#include <ciftl/crypter/crypter.h>
#include "test.h"

using namespace ciftl;

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
