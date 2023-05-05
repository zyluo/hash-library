// //////////////////////////////////////////////////////////
// sha1.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif


namespace
{
    // mix functions for processBlock()
    inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d)
    {
        return d ^ (b & (c ^ d)); // original: f = (b & c) | ((~b) & d);
    }

    inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d)
    {
        return b ^ c ^ d;
    }

    inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d)
    {
        return (b & c) | (b & d) | (c & d);
    }

    inline uint32_t rotate(uint32_t a, uint32_t c)
    {
        return (a << c) | (a >> (32 - c));
    }

    inline uint32_t swap(uint32_t x)
    {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(x);
#endif
#ifdef MSC_VER
        return _byteswap_ulong(x);
#endif

        return (x >> 24) |
            ((x >> 8) & 0x0000FF00) |
            ((x << 8) & 0x00FF0000) |
            (x << 24);
    }
}


/// process 64 bytes
extern "C" void sha1_compress(const uint32_t data[64], uint32_t m_hash[5])
{
    // get last hash
    uint32_t a = m_hash[0];
    uint32_t b = m_hash[1];
    uint32_t c = m_hash[2];
    uint32_t d = m_hash[3];
    uint32_t e = m_hash[4];

    // data represented as 16x 32-bit words
    const uint32_t* input = (uint32_t*)data;
    // convert to big endian
    uint32_t words[80];
    for (int i = 0; i < 16; i++)
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
        words[i] = input[i];
#else
        words[i] = swap(input[i]);
#endif

    // extend to 80 words
    for (int i = 16; i < 80; i++)
        words[i] = rotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);

    // first round
    for (int i = 0; i < 4; i++)
    {
        int offset = 5 * i;
        e += rotate(a, 5) + f1(b, c, d) + words[offset] + 0x5a827999; b = rotate(b, 30);
        d += rotate(e, 5) + f1(a, b, c) + words[offset + 1] + 0x5a827999; a = rotate(a, 30);
        c += rotate(d, 5) + f1(e, a, b) + words[offset + 2] + 0x5a827999; e = rotate(e, 30);
        b += rotate(c, 5) + f1(d, e, a) + words[offset + 3] + 0x5a827999; d = rotate(d, 30);
        a += rotate(b, 5) + f1(c, d, e) + words[offset + 4] + 0x5a827999; c = rotate(c, 30);
    }

    // second round
    for (int i = 4; i < 8; i++)
    {
        int offset = 5 * i;
        e += rotate(a, 5) + f2(b, c, d) + words[offset] + 0x6ed9eba1; b = rotate(b, 30);
        d += rotate(e, 5) + f2(a, b, c) + words[offset + 1] + 0x6ed9eba1; a = rotate(a, 30);
        c += rotate(d, 5) + f2(e, a, b) + words[offset + 2] + 0x6ed9eba1; e = rotate(e, 30);
        b += rotate(c, 5) + f2(d, e, a) + words[offset + 3] + 0x6ed9eba1; d = rotate(d, 30);
        a += rotate(b, 5) + f2(c, d, e) + words[offset + 4] + 0x6ed9eba1; c = rotate(c, 30);
    }

    // third round
    for (int i = 8; i < 12; i++)
    {
        int offset = 5 * i;
        e += rotate(a, 5) + f3(b, c, d) + words[offset] + 0x8f1bbcdc; b = rotate(b, 30);
        d += rotate(e, 5) + f3(a, b, c) + words[offset + 1] + 0x8f1bbcdc; a = rotate(a, 30);
        c += rotate(d, 5) + f3(e, a, b) + words[offset + 2] + 0x8f1bbcdc; e = rotate(e, 30);
        b += rotate(c, 5) + f3(d, e, a) + words[offset + 3] + 0x8f1bbcdc; d = rotate(d, 30);
        a += rotate(b, 5) + f3(c, d, e) + words[offset + 4] + 0x8f1bbcdc; c = rotate(c, 30);
    }

    // fourth round
    for (int i = 12; i < 16; i++)
    {
        int offset = 5 * i;
        e += rotate(a, 5) + f2(b, c, d) + words[offset] + 0xca62c1d6; b = rotate(b, 30);
        d += rotate(e, 5) + f2(a, b, c) + words[offset + 1] + 0xca62c1d6; a = rotate(a, 30);
        c += rotate(d, 5) + f2(e, a, b) + words[offset + 2] + 0xca62c1d6; e = rotate(e, 30);
        b += rotate(c, 5) + f2(d, e, a) + words[offset + 3] + 0xca62c1d6; d = rotate(d, 30);
        a += rotate(b, 5) + f2(c, d, e) + words[offset + 4] + 0xca62c1d6; c = rotate(c, 30);
    }

    // update hash
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
    m_hash[4] += e;
}