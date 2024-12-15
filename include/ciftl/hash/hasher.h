#pragma once

#include <string>
#include <openssl/evp.h>
#include <ciftl/encoding/encoding.h>
#include <ciftl/etc/etc.h>

namespace ciftl
{
    enum class HashAlgorithm
    {
        MD5,
        SHA1,
        SHA256,
        SHA512,
        Crc32c
    };

    class IHasher
    {
    public:
        void operator=(const IHasher &) = delete;

        void operator==(const IHasher &) = delete;

        virtual void update(const byte *data, size_t len) = 0;

        virtual void update(const ByteVector &data) = 0;

        virtual void update(const std::string &data) = 0;

        virtual ByteVector finalize() = 0;
    };

    class OpenSSLHasher : public IHasher
    {
    public:
        OpenSSLHasher(const EVP_MD *md);

        ~OpenSSLHasher();

        virtual void update(const byte *data, size_t len);

        virtual void update(const ByteVector &data);

        virtual void update(const std::string &data);

        ByteVector finalize();

    private:
        EVP_MD_CTX *m_ctx;
        const EVP_MD *m_md;
    };

    class MD5Hasher : public OpenSSLHasher
    {
    public:
        MD5Hasher();

        ~MD5Hasher() = default;
    };

    class Sha1Hasher : public OpenSSLHasher
    {
    public:
        Sha1Hasher();

        ~Sha1Hasher() = default;
    };

    class Sha256Hasher : public OpenSSLHasher
    {
    public:
        Sha256Hasher();

        ~Sha256Hasher() = default;
    };

    class Sha512Hasher : public OpenSSLHasher
    {
    public:
        Sha512Hasher();

        ~Sha512Hasher() = default;
    };

    // Crc32c
    class Crc32cHasher : public IHasher
    {
        uint32_t m_crc32c;

    public:
        Crc32cHasher();

        ~Crc32cHasher();

    public:
        virtual void update(const byte *data, size_t len);

        virtual void update(const ByteVector &data);

        virtual void update(const std::string &data);

        ByteVector finalize();
    };
} // namespace ciftl
