project(test_ciftl)

find_package(GTest CONFIG REQUIRED)
find_package(fmt REQUIRED)

include_directories(${CIFTL_INCLUDE_PATH})

link_directories(${LIBRARY_OUTPUT_PATH})

add_executable(${PROJECT_NAME}
        test.h
        test_encoding.cpp
        test_crypter.cpp
        test_hash.cpp
        test.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Crc32c::crc32c
        ciftl
        GTest::gtest
        GTest::gtest_main
        fmt::fmt
)

add_test(NAME TestEncoding COMMAND ${PROJECT_NAME})
add_test(NAME TestCrypter COMMAND ${PROJECT_NAME})
add_test(NAME TestHash COMMAND ${PROJECT_NAME})
add_test(NAME TestCore COMMAND ${PROJECT_NAME})
