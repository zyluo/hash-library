// //////////////////////////////////////////////////////////
// md5.cpp
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include "md5.h"


/// same as reset()
MD5::MD5()
{
  reset();
}


/// restart
void MD5::reset()
{
  m_numBytes   = 0;
  m_bufferSize = 0;

  // according to RFC 1321
  m_hash[0] = 0x67452301;
  m_hash[1] = 0xefcdab89;
  m_hash[2] = 0x98badcfe;
  m_hash[3] = 0x10325476;
}


/// add arbitrary number of bytes
void MD5::add(const void* data, size_t numBytes)
{
  const uint8_t* current = (const uint8_t*) data;

  if (m_bufferSize > 0)
  {
    while (numBytes > 0 && m_bufferSize < BlockSize)
    {
      m_buffer[m_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (m_bufferSize == BlockSize)
  {
    md5_compress(m_buffer, m_hash);
    m_numBytes  += BlockSize;
    m_bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= BlockSize)
  {
    md5_compress(current, m_hash);
    current    += BlockSize;
    m_numBytes += BlockSize;
    numBytes   -= BlockSize;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0 && m_bufferSize < BlockSize)
  {
    m_buffer[m_bufferSize++] = *current++;
    numBytes--;
  }
}


/// process final block, less than 64 bytes
void MD5::processBuffer()
{
  // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

  // - append "1" bit to message
  // - append "0" bits until message length in bit mod 512 is 448
  // - append length as 64 bit integer

  // number of bits
  size_t paddedLength = m_bufferSize * 8;

  // plus one bit set to 1 (always appended)
  paddedLength++;

  // number of bits must be (numBits % 512) = 448
  size_t lower11Bits = paddedLength & 511;
  if (lower11Bits <= 448)
    paddedLength +=       448 - lower11Bits;
  else
    paddedLength += 512 + 448 - lower11Bits;
  // convert from bits to bytes
  paddedLength /= 8;

  // only needed if additional data flows over into a second block
  unsigned char extra[BlockSize];

  // append a "1" bit, 128 => binary 10000000
  if (m_bufferSize < BlockSize)
    m_buffer[m_bufferSize] = 128;
  else
    extra[0] = 128;

  size_t i;
  for (i = m_bufferSize + 1; i < BlockSize; i++)
    m_buffer[i] = 0;
  for (; i < paddedLength; i++)
    extra[i - BlockSize] = 0;

  // add message length in bits as 64 bit number
  uint64_t msgBits = 8 * (m_numBytes + m_bufferSize);
  // find right position
  unsigned char* addLength;
  if (paddedLength < BlockSize)
    addLength = m_buffer + paddedLength;
  else
    addLength = extra + paddedLength - BlockSize;

  // must be little endian
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF;

  // process blocks
  md5_compress(m_buffer, m_hash);
  // flowed over into a second block ?
  if (paddedLength > BlockSize)
    md5_compress(extra, m_hash);
}


/// return latest hash as 32 hex characters
std::string MD5::getHash()
{
  // compute hash (as raw bytes)
  unsigned char rawHash[HashBytes];
  getHash(rawHash);

  // convert to hex string
  std::string result;
  result.reserve(2 * HashBytes);
  for (int i = 0; i < HashBytes; i++)
  {
    static const char dec2hex[16+1] = "0123456789abcdef";
    result += dec2hex[(rawHash[i] >> 4) & 15];
    result += dec2hex[ rawHash[i]       & 15];
  }

  return result;
}


/// return latest hash as bytes
void MD5::getHash(unsigned char buffer[MD5::HashBytes])
{
  // save old hash if buffer is partially filled
  uint32_t oldHash[HashValues];
  for (int i = 0; i < HashValues; i++)
    oldHash[i] = m_hash[i];

  // process remaining bytes
  processBuffer();

  unsigned char* current = buffer;
  for (int i = 0; i < HashValues; i++)
  {
    *current++ =  m_hash[i]        & 0xFF;
    *current++ = (m_hash[i] >>  8) & 0xFF;
    *current++ = (m_hash[i] >> 16) & 0xFF;
    *current++ = (m_hash[i] >> 24) & 0xFF;

    // restore old hash
    m_hash[i] = oldHash[i];
  }
}


/// compute MD5 of a memory block
std::string MD5::operator()(const void* data, size_t numBytes)
{
  reset();
  add(data, numBytes);
  return getHash();
}


/// compute MD5 of a string, excluding final zero
std::string MD5::operator()(const std::string& text)
{
  reset();
  add(text.c_str(), text.size());
  return getHash();
}
