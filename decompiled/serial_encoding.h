/*
 * Serial Number Encoding - Stars! 2.60j RC3
 * Decompiled from stars.exe
 *
 * See serial_encoding.c for full documentation.
 */

#ifndef SERIAL_ENCODING_H
#define SERIAL_ENCODING_H

#include <stdint.h>

/* Shuffle table at 1020:2870 - permutes 21 decoded bytes */
extern const uint8_t vrgbShuffleSerial[21];

/*
 * FSerialAndEnvFromSz - Decode serial string to binary components
 *
 * @param plSerial  Output: 4-byte serial number (stored at FileHashBlock offset 2-5)
 * @param pbEnv     Output: 11-byte hardware fingerprint (stored at offset 6-16)
 * @param szSerial  Input: 28-character serial string
 * @return          1 if valid, 0 if invalid
 *
 * The serial string is base64-decoded to 21 bytes, shuffled using
 * vrgbShuffleSerial, then split into lSerial (bytes 0-3) and pbEnv (bytes 4-14).
 *
 * Address: 1020:2aec
 */
int16_t FSerialAndEnvFromSz(int32_t *plSerial, uint8_t *pbEnv, char *szSerial);

/*
 * FormatSerialAndEnv - Encode binary components to serial string
 *
 * @param lSerial   Input: 4-byte serial number
 * @param pbEnv     Input: 11-byte hardware fingerprint
 * @param szOut     Output: 28-character serial string (+ null terminator)
 *
 * Inverse of FSerialAndEnvFromSz. Combines lSerial and pbEnv into 21 bytes,
 * applies inverse shuffle, then base64-encodes to 28 characters.
 *
 * Address: 1020:2886
 */
void FormatSerialAndEnv(int32_t lSerial, uint8_t *pbEnv, char *szOut);

/*
 * LongFromSerialCh - Convert single serial character to value
 *
 * @param ch  Serial character (A-Z maps to 0-25, then XOR 0x15 if < 0x20)
 * @return    Numeric value (0-35)
 *
 * Used for older 8-character serial format validation.
 * Different encoding than the base64-like scheme in FSerialAndEnvFromSz.
 *
 * Address: 1038:6280
 */
uint16_t LongFromSerialCh(char ch);

/*
 * FValidSerialNo - Validate 8-character serial string
 *
 * @param szSerial  8-character serial string
 * @param plSerial  Optional output: decoded 32-bit value
 * @return          1 if valid, 0 if invalid
 *
 * Validates the older 8-character serial format using LongFromSerialCh.
 * Characters at positions 0,1,4,7,3 encode the base value.
 * Characters at positions 2,5,6 are check digits.
 *
 * Address: 1038:62f8
 */
int16_t FValidSerialNo(char *szSerial, int32_t *plSerial);

/*
 * FValidSerialLong - Validate decoded 32-bit serial value
 *
 * @param lSerial  32-bit serial value (from FSerialAndEnvFromSz)
 * @return         1 if valid, 0 if invalid
 *
 * Checks that the serial value passes various validation tests including
 * the "bogus long" check and serial type verification.
 * Valid serial types: 0x02, 0x04, 0x06, 0x12, 0x16
 *
 * Address: 1070:48c4
 */
int16_t FValidSerialLong(uint32_t lSerial);

#endif /* SERIAL_ENCODING_H */
