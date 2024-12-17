#include <openssl/evp.h>
#include <crc32c/crc32c.h>

#include <ciftl/hash/hasher.h>

namespace ciftl
{
    OpenSSLHasher::OpenSSLHasher(const EVP_MD *md)
        : m_md(md)
    {
        m_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(m_ctx, m_md, nullptr);
    }

    OpenSSLHasher::~OpenSSLHasher()
    {
        EVP_MD_CTX_free(m_ctx);
    }

    void OpenSSLHasher::update(const byte *data, size_t len)
    {
        EVP_DigestUpdate(m_ctx, data, len);
    }

    void OpenSSLHasher::update(const ByteVector &data)
    {
        update(data.data(), data.size());
    }

    void OpenSSLHasher::update(const std::string &data)
    {
        update((byte *) data.c_str(), data.length());
    }

    ByteVector OpenSSLHasher::finalize()
    {
        ByteVector hash(EVP_MD_size(m_md));
        unsigned int hash_len;
        // 需要将上下文拷贝一份，不能直接进行finalize
        auto copied_ctx = EVP_MD_CTX_new();
        EVP_MD_CTX_copy(copied_ctx, m_ctx);
        EVP_DigestFinal_ex(copied_ctx, hash.data(), &hash_len);
        hash.resize(hash_len);
        EVP_MD_CTX_free(copied_ctx);
        return hash;
    }

    MD5Hasher::MD5Hasher()
        : OpenSSLHasher(EVP_md5())
    {
    }

    Sha1Hasher::Sha1Hasher()
        : OpenSSLHasher(EVP_sha1())
    {
    }

    Sha256Hasher::Sha256Hasher()
        : OpenSSLHasher(EVP_sha256())
    {
    }

    Sha512Hasher::Sha512Hasher()
        : OpenSSLHasher(EVP_sha512())
    {
    }

    Crc32cHasher::Crc32cHasher() : m_crc32c(0)
    {
    }

    Crc32cHasher::~Crc32cHasher()
    {
    }

    void Crc32cHasher::update(const byte *data, size_t len)
    {
        m_crc32c = crc32c::Extend(m_crc32c, data, len);
    }

    void Crc32cHasher::update(const ByteVector &data)
    {
        update(data.data(), data.size());
    }

    void Crc32cHasher::update(const std::string &data)
    {
        update((const byte *) data.data(), data.size());
    }

    ByteVector Crc32cHasher::finalize()
    {
        return auto_cast<ByteVector, Crc32Value>(m_crc32c);
    }
} // namespace ciftl
