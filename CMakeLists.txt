# 设置 CMake 最低版本要求
cmake_minimum_required(VERSION 3.20)

# 设置项目名称
project(ciftl VERSION 0.1.0 LANGUAGES CXX)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 选择编译器
set(GCC_OR_CLANG ((CMAKE_CXX_COMPILER_ID MATCHES "Clang") OR CMAKE_COMPILER_IS_GNUCXX))

# 设置编译输出目录
set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

# 设置构建类型
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build, options are: Debug Release." FORCE)
endif ()

# 根据构建类型设置编译器选项
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Build type: Debug")
    set(LIBRARY_OUTPUT_PATH "${LIBRARY_OUTPUT_PATH}/Debug")
    set(EXECUTABLE_OUTPUT_PATH "${EXECUTABLE_OUTPUT_PATH}/Debug")
    if (MSVC)
        # Visual Studio 编译器的 Debug 选项
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Od /Zi /D_DEBUG")
    else ()
        # GCC 编译器的 Debug 选项
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")
    endif ()
else ()
    message(STATUS "Build type: Release")
    set(LIBRARY_OUTPUT_PATH "${LIBRARY_OUTPUT_PATH}/Release")
    set(EXECUTABLE_OUTPUT_PATH "${EXECUTABLE_OUTPUT_PATH}/Release")
    if (MSVC)
        # Visual Studio 编译器的 Release 选项
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2 /Oi /Gy /DNDEBUG")
    else ()
        # GCC 编译器的 Release 选项
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG")
    endif ()
endif ()

# 对MSVC的特殊支持
if (MSVC)
    # 对于MSVC需要支持utf-8
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /utf-8")
    # 编译选项
    set(CMAKE_CONFIGURATION_TYPES "Debug;Release")
    # Debug生成的后缀
    set(CMAKE_DEBUG_POSTFIX D)
    # windows系统动态库生成lib文件的命令
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif (MSVC)

# 设置相关头文件路径
set(CIFTL_HOME_INCLUDE_PATH "${PROJECT_SOURCE_DIR}/include/")
set(CIFTL_INCLUDE_PATH "${CIFTL_HOME_INCLUDE_PATH}/ciftl/")
set(CIFTL_ENCODING_INCLUDE_PATH "${CIFTL_INCLUDE_PATH}/encoding/")
set(CIFTL_ETC_INCLUDE_PATH "${CIFTL_INCLUDE_PATH}/etc/")
set(CIFTL_HASH_INCLUDE_PATH "${CIFTL_INCLUDE_PATH}/hash/")
set(CIFTL_CRYPTER_INCLUDE_PATH "${CIFTL_INCLUDE_PATH}/crypter/")
# 设置相关源文件路径
set(CIFTL_SOURCE_PATH "${PROJECT_SOURCE_DIR}/src/")
set(CIFTL_ENCODING_SOURCE_PATH "${CIFTL_SOURCE_PATH}/encoding/")
set(CIFTL_ETC_SOURCE_PATH "${CIFTL_SOURCE_PATH}/etc/")
set(CIFTL_HASH_SOURCE_PATH "${CIFTL_SOURCE_PATH}/hash/")
set(CIFTL_CRYPTER_SOURCE_PATH "${CIFTL_SOURCE_PATH}/crypter/")
# 添加头文件
file(GLOB CIFTL_ENCODING_HEADER "${CIFTL_ENCODING_INCLUDE_PATH}/*.h")
file(GLOB CIFTL_ETC_HEADER "${CIFTL_ETC_INCLUDE_PATH}/*.h")
file(GLOB CIFTL_HASH_HEADER "${CIFTL_HASH_INCLUDE_PATH}/*.h")
file(GLOB CIFTL_CRYPTER_HEADER "${CIFTL_CRYPTER_INCLUDE_PATH}/*.h")
# 添加源文件
file(GLOB CIFTL_ENCODING_SOURCE "${CIFTL_ENCODING_SOURCE_PATH}/*.cpp")
file(GLOB CIFTL_ETC_SOURCE "${CIFTL_ETC_SOURCE_PATH}/*.cpp")
file(GLOB CIFTL_HASH_SOURCE "${CIFTL_HASH_SOURCE_PATH}/*.cpp")
file(GLOB CIFTL_CRYPTER_SOURCE "${CIFTL_CRYPTER_SOURCE_PATH}/*.cpp")

# 添加搜寻目录
include_directories(${CIFTL_HOME_INCLUDE_PATH})

find_package(OpenSSL REQUIRED)
find_package(Crc32c CONFIG REQUIRED)

# 添加源文件
add_library(${PROJECT_NAME}
        ${CIFTL_ENCODING_HEADER}
        ${CIFTL_ETC_HEADER}
        ${CIFTL_HASH_HEADER}
        ${CIFTL_CRYPTER_HEADER}
        ${CIFTL_ENCODING_SOURCE}
        ${CIFTL_ETC_SOURCE}
        ${CIFTL_HASH_SOURCE}
        ${CIFTL_CRYPTER_SOURCE}
)

target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto Crc32c::crc32c)

# 添加单元测试
enable_testing()
add_subdirectory(tests)
