#pragma once
#include <ciftl/etc/type.h>
#include <ciftl/etc/result.h>
#include <ciftl/etc/error.h>

namespace ciftl
{
    // 数组拼接
    template<class T>
    ByteVector concat(T t)
    {
        ByteVector res;
        size_t t_size = t.size();
        res.resize(t_size);
        memcpy(res.data(), t.data(), t_size);
        return res;
    }

    // 数组拼接
    template<class T, class... ARGS>
    ByteVector concat(T t, ARGS... args)
    {
        ByteVector res;
        size_t t_size = t.size();
        res.resize(t_size);
        memcpy(res.data(), t.data(), t_size);
        ByteVector next_res = concat(args...);
        res.resize(res.size() + next_res.size());
        memcpy(res.data() + t_size, next_res.data(), next_res.size());
        return res;
    }

    /// 内存获取器，用于不断从一块内存中获取数据直到结束
    class MemoryTaker
    {
        const byte *m_mem;
        size_t m_idx;
        size_t m_length;

    public:
        MemoryTaker(const byte *mem, size_t length): m_mem(mem), m_idx(0), m_length(length)
        {
        }

        Result<void> take(ByteVector &dst)
        {
            return take(dst.data(), dst.size());
        }

        template<size_t ARRAY_SIZE>
        Result<void> take(ByteArray<ARRAY_SIZE> &dst)
        {
            return take(dst.data(), dst.size());
        }

        Result<void> take(byte *dst, size_t dst_size)
        {
            if (m_idx + dst_size > m_length) {
                return Result<void>::make_err(MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT);
            }
            memcpy(dst, m_mem + m_idx, dst_size);
            m_idx += dst_size;
            return Result<void>::make_ok();
        }

        Result<ByteVector> take_all()
        {
            if (m_idx >= m_length) {
                return Result<ByteVector>::make_err(MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT);
            }
            ByteVector res(m_length - m_idx);
            memcpy(res.data(), m_mem + m_idx, m_length - m_idx);
            m_idx = m_length;
            return Result<ByteVector>::make_ok(res);
        }
    };
}
