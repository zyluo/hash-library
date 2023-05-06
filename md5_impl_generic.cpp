// //////////////////////////////////////////////////////////
// md5_impl_generic.cpp
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
    // mix functions for md5_compress()
    inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d)
    {
        return d ^ (b & (c ^ d)); // original: f = (b & c) | ((~b) & d);
    }

    inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d)
    {
        return c ^ (d & (b ^ c)); // original: f = (b & d) | (c & (~d));
    }

    inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d)
    {
        return b ^ c ^ d;
    }

    inline uint32_t f4(uint32_t b, uint32_t c, uint32_t d)
    {
        return c ^ (b | ~d);
    }

    inline uint32_t rotate(uint32_t a, uint32_t c)
    {
        return (a << c) | (a >> (32 - c));
    }

#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
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
#endif
}


/// process 64 bytes
extern "C" void md5_compress(const uint32_t data[64], uint32_t m_hash[4])
{
    // get last hash
    uint32_t a = m_hash[0];
    uint32_t b = m_hash[1];
    uint32_t c = m_hash[2];
    uint32_t d = m_hash[3];

    // data represented as 16x 32-bit words
    const uint32_t* words = (uint32_t*)data;

    // computations are little endian, swap data if necessary
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
#define LITTLEENDIAN(x) swap(x)
#else
#define LITTLEENDIAN(x) (x)
#endif

  // first round
    uint32_t word0 = LITTLEENDIAN(words[0]);
    a = rotate(a + f1(b, c, d) + word0 + 0xd76aa478, 7) + b;
    uint32_t word1 = LITTLEENDIAN(words[1]);
    d = rotate(d + f1(a, b, c) + word1 + 0xe8c7b756, 12) + a;
    uint32_t word2 = LITTLEENDIAN(words[2]);
    c = rotate(c + f1(d, a, b) + word2 + 0x242070db, 17) + d;
    uint32_t word3 = LITTLEENDIAN(words[3]);
    b = rotate(b + f1(c, d, a) + word3 + 0xc1bdceee, 22) + c;

    uint32_t word4 = LITTLEENDIAN(words[4]);
    a = rotate(a + f1(b, c, d) + word4 + 0xf57c0faf, 7) + b;
    uint32_t word5 = LITTLEENDIAN(words[5]);
    d = rotate(d + f1(a, b, c) + word5 + 0x4787c62a, 12) + a;
    uint32_t word6 = LITTLEENDIAN(words[6]);
    c = rotate(c + f1(d, a, b) + word6 + 0xa8304613, 17) + d;
    uint32_t word7 = LITTLEENDIAN(words[7]);
    b = rotate(b + f1(c, d, a) + word7 + 0xfd469501, 22) + c;

    uint32_t word8 = LITTLEENDIAN(words[8]);
    a = rotate(a + f1(b, c, d) + word8 + 0x698098d8, 7) + b;
    uint32_t word9 = LITTLEENDIAN(words[9]);
    d = rotate(d + f1(a, b, c) + word9 + 0x8b44f7af, 12) + a;
    uint32_t word10 = LITTLEENDIAN(words[10]);
    c = rotate(c + f1(d, a, b) + word10 + 0xffff5bb1, 17) + d;
    uint32_t word11 = LITTLEENDIAN(words[11]);
    b = rotate(b + f1(c, d, a) + word11 + 0x895cd7be, 22) + c;

    uint32_t word12 = LITTLEENDIAN(words[12]);
    a = rotate(a + f1(b, c, d) + word12 + 0x6b901122, 7) + b;
    uint32_t word13 = LITTLEENDIAN(words[13]);
    d = rotate(d + f1(a, b, c) + word13 + 0xfd987193, 12) + a;
    uint32_t word14 = LITTLEENDIAN(words[14]);
    c = rotate(c + f1(d, a, b) + word14 + 0xa679438e, 17) + d;
    uint32_t word15 = LITTLEENDIAN(words[15]);
    b = rotate(b + f1(c, d, a) + word15 + 0x49b40821, 22) + c;

    // second round
    a = rotate(a + f2(b, c, d) + word1 + 0xf61e2562, 5) + b;
    d = rotate(d + f2(a, b, c) + word6 + 0xc040b340, 9) + a;
    c = rotate(c + f2(d, a, b) + word11 + 0x265e5a51, 14) + d;
    b = rotate(b + f2(c, d, a) + word0 + 0xe9b6c7aa, 20) + c;

    a = rotate(a + f2(b, c, d) + word5 + 0xd62f105d, 5) + b;
    d = rotate(d + f2(a, b, c) + word10 + 0x02441453, 9) + a;
    c = rotate(c + f2(d, a, b) + word15 + 0xd8a1e681, 14) + d;
    b = rotate(b + f2(c, d, a) + word4 + 0xe7d3fbc8, 20) + c;

    a = rotate(a + f2(b, c, d) + word9 + 0x21e1cde6, 5) + b;
    d = rotate(d + f2(a, b, c) + word14 + 0xc33707d6, 9) + a;
    c = rotate(c + f2(d, a, b) + word3 + 0xf4d50d87, 14) + d;
    b = rotate(b + f2(c, d, a) + word8 + 0x455a14ed, 20) + c;

    a = rotate(a + f2(b, c, d) + word13 + 0xa9e3e905, 5) + b;
    d = rotate(d + f2(a, b, c) + word2 + 0xfcefa3f8, 9) + a;
    c = rotate(c + f2(d, a, b) + word7 + 0x676f02d9, 14) + d;
    b = rotate(b + f2(c, d, a) + word12 + 0x8d2a4c8a, 20) + c;

    // third round
    a = rotate(a + f3(b, c, d) + word5 + 0xfffa3942, 4) + b;
    d = rotate(d + f3(a, b, c) + word8 + 0x8771f681, 11) + a;
    c = rotate(c + f3(d, a, b) + word11 + 0x6d9d6122, 16) + d;
    b = rotate(b + f3(c, d, a) + word14 + 0xfde5380c, 23) + c;

    a = rotate(a + f3(b, c, d) + word1 + 0xa4beea44, 4) + b;
    d = rotate(d + f3(a, b, c) + word4 + 0x4bdecfa9, 11) + a;
    c = rotate(c + f3(d, a, b) + word7 + 0xf6bb4b60, 16) + d;
    b = rotate(b + f3(c, d, a) + word10 + 0xbebfbc70, 23) + c;

    a = rotate(a + f3(b, c, d) + word13 + 0x289b7ec6, 4) + b;
    d = rotate(d + f3(a, b, c) + word0 + 0xeaa127fa, 11) + a;
    c = rotate(c + f3(d, a, b) + word3 + 0xd4ef3085, 16) + d;
    b = rotate(b + f3(c, d, a) + word6 + 0x04881d05, 23) + c;

    a = rotate(a + f3(b, c, d) + word9 + 0xd9d4d039, 4) + b;
    d = rotate(d + f3(a, b, c) + word12 + 0xe6db99e5, 11) + a;
    c = rotate(c + f3(d, a, b) + word15 + 0x1fa27cf8, 16) + d;
    b = rotate(b + f3(c, d, a) + word2 + 0xc4ac5665, 23) + c;

    // fourth round
    a = rotate(a + f4(b, c, d) + word0 + 0xf4292244, 6) + b;
    d = rotate(d + f4(a, b, c) + word7 + 0x432aff97, 10) + a;
    c = rotate(c + f4(d, a, b) + word14 + 0xab9423a7, 15) + d;
    b = rotate(b + f4(c, d, a) + word5 + 0xfc93a039, 21) + c;

    a = rotate(a + f4(b, c, d) + word12 + 0x655b59c3, 6) + b;
    d = rotate(d + f4(a, b, c) + word3 + 0x8f0ccc92, 10) + a;
    c = rotate(c + f4(d, a, b) + word10 + 0xffeff47d, 15) + d;
    b = rotate(b + f4(c, d, a) + word1 + 0x85845dd1, 21) + c;

    a = rotate(a + f4(b, c, d) + word8 + 0x6fa87e4f, 6) + b;
    d = rotate(d + f4(a, b, c) + word15 + 0xfe2ce6e0, 10) + a;
    c = rotate(c + f4(d, a, b) + word6 + 0xa3014314, 15) + d;
    b = rotate(b + f4(c, d, a) + word13 + 0x4e0811a1, 21) + c;

    a = rotate(a + f4(b, c, d) + word4 + 0xf7537e82, 6) + b;
    d = rotate(d + f4(a, b, c) + word11 + 0xbd3af235, 10) + a;
    c = rotate(c + f4(d, a, b) + word2 + 0x2ad7d2bb, 15) + d;
    b = rotate(b + f4(c, d, a) + word9 + 0xeb86d391, 21) + c;

    // update hash
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
}
