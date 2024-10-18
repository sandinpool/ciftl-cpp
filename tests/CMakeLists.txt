project(test_ciftl)

find_package(GTest CONFIG REQUIRED)
find_package(fmt REQUIRED)

include_directories(${CIFTL_INCLUDE_PATH})

add_executable(test_ciftl 
    test.h 
    test_encoding.cpp 
    test_crypter.cpp 
    test_hash.cpp 
    test.cpp
)

target_link_libraries(test_ciftl PRIVATE
    GTest::gtest
    GTest::gtest_main
    fmt::fmt
    ciftl)

add_test(NAME TestEncoding COMMAND test_ciftl)
add_test(NAME TestCrypter COMMAND test_ciftl)
add_test(NAME TestHash COMMAND test_ciftl)
add_test(NAME TestCore COMMAND test_ciftl)
