/*
 * Serial Number Encoding - Stars! 2.60j RC3
 * Decompiled from stars.exe
 *
 * This file contains functions for encoding/decoding Stars! serial numbers.
 * The serial number system uses a base64-like encoding with a shuffle table
 * to obfuscate the stored data.
 *
 * SERIAL STRING FORMAT:
 *   - 28 characters using: A-Z, a-z, 0-9, '-', '*'
 *   - Each character encodes 6 bits (28 chars × 6 bits = 168 bits = 21 bytes)
 *   - The visible portion "CV6JVUAX" is typically the first 8 characters
 *
 * CHARACTER ENCODING (6 bits each):
 *   A-Z  → 0-25   (ch - 'A')
 *   a-z  → 26-51  (ch - 'a' + 26, stored as ch + 0xb9 = ch - 71)
 *   0-9  → 52-61  (ch - '0' + 52, stored as ch + 4)
 *   '-'  → 62     (0x3e)
 *   '*'  → 63     (0x3f)
 *
 * SHUFFLE TABLE (vrgbShuffleSerial at 1020:2870):
 *   Used to permute the 21 decoded bytes before extracting serial/env data.
 *   The table maps: shuffled[i] = decoded[vrgbShuffleSerial[i]]
 *
 * OUTPUT STRUCTURE (21 bytes after decode + shuffle):
 *   Bytes 0-3:   lSerial (32-bit serial number, stored in FileHashBlock offset 2-5)
 *   Bytes 4-14:  pbEnv (11-byte hardware fingerprint, stored in FileHashBlock offset 6-16)
 *
 * KEY FUNCTIONS:
 *   FSerialAndEnvFromSz() - Decode serial string → (lSerial, pbEnv)
 *   FormatSerialAndEnv()  - Encode (lSerial, pbEnv) → serial string
 *   FValidSerialNo()      - Validate 8-char serial string format
 *   FValidSerialLong()    - Validate decoded 32-bit serial value
 *   LongFromSerialCh()    - Convert single char to numeric value (older format)
 */

#include <stdint.h>

/* Shuffle table at 1020:2870 - permutes 21 decoded bytes */
static const uint8_t vrgbShuffleSerial[21] = {
    0x0b, 0x04, 0x05, 0x10, 0x11, 0x0c, 0x13, 0x0f,
    0x0a, 0x01, 0x0e, 0x0d, 0x03, 0x12, 0x02, 0x14,
    0x09, 0x07, 0x00, 0x08, 0x06
};

/*
 * Inverse mapping: which source index produces each output position
 *   Output[0]  ← Source[18]  (vrgbShuffleSerial[18] = 0x00)
 *   Output[1]  ← Source[9]   (vrgbShuffleSerial[9]  = 0x01)
 *   Output[2]  ← Source[14]  (vrgbShuffleSerial[14] = 0x02)
 *   Output[3]  ← Source[12]  (vrgbShuffleSerial[12] = 0x03)
 *   ... and so on
 */



// ======================================================================
// Function: FSerialAndEnvFromSz
// Address: 1020:2aec
// ======================================================================


int __cdecl16far MDI::FSerialAndEnvFromSz(undefined2 *param_1,undefined2 param_2,char *param_3)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  undefined *puVar5;
  byte local_48;
  undefined local_46 [22];
  uint local_30;
  uint local_2e;
  undefined2 local_2c;
  undefined2 local_2a;
  uint local_28;
  int local_26;
  int local_24;
  int local_22;
  byte local_20;
  uint local_1e;
  int local_1c;
  undefined2 local_1a;
  undefined2 local_18;
  byte local_16 [20];
  
  local_28 = 0;
  *param_1 = 0;
  param_1[1] = 0;
  PUBLIC::_memset(param_2,0,0xb);
  local_26 = 0;
  local_24 = 0;
  local_30 = 0;
  local_2e = 0;
  for (local_22 = 0; local_22 < 0x15; local_22 = local_22 + 1) {
    for (; local_24 < 8; local_24 = local_24 + 6) {
      if ((*param_3 < 'A') || ('Z' < *param_3)) {
        if ((*param_3 < 'a') || ('z' < *param_3)) {
          if ((*param_3 < '0') || ('9' < *param_3)) {
            if (*param_3 == '-') {
              local_48 = 0x3e;
            }
            else {
              local_48 = 0x3f;
            }
          }
          else {
            local_48 = *param_3 + 4;
          }
        }
        else {
          local_48 = *param_3 + 0xb9;
        }
      }
      else {
        local_48 = *param_3 + 0xbf;
      }
      uVar3 = (uint)local_48 << ((byte)local_24 & 0x1f);
      local_30 = local_30 | uVar3;
      local_2e = local_2e | (int)uVar3 >> 0xf;
      param_3 = param_3 + 1;
    }
    puVar5 = local_46 + local_26;
    local_26 = local_26 + 1;
    *puVar5 = (char)local_30;
    local_24 = local_24 + -8;
    local_30 = PUBLIC::__aFlshr();
  }
  for (local_22 = 0; local_22 < 0x15; local_22 = local_22 + 1) {
    *(undefined *)((int)&local_1a + (uint)*(byte *)(local_22 + 0x2870)) = local_46[local_22];
  }
  local_2c = local_1a;
  local_2a = local_18;
  iVar4 = IO::FValidSerialLong(local_1a,local_18);
  if (iVar4 == 0) {
    local_1c = 0;
  }
  else {
    local_1c = 1;
    UTILGEN::PushRandom(0xb,0x11);
    UTILGEN::Randomize(local_2c,local_2a);
    local_26 = 0xf;
    for (local_22 = 0; local_22 < 0xb; local_22 = local_22 + 1) {
      for (local_1e = (uint)local_16[local_22]; 0 < (int)local_1e; local_1e = local_1e - 1) {
        UTILGEN::Random(0x10);
      }
      if (local_28 == 0) {
        bVar1 = *(byte *)((int)&local_1a + local_26);
        bVar2 = UTILGEN::Random(0x10);
        if ((bVar1 & 0xf) != bVar2) {
          local_1c = 0;
        }
      }
      else {
        bVar1 = *(byte *)((int)&local_1a + local_26);
        uVar3 = UTILGEN::Random(0x10);
        if ((int)(uint)bVar1 >> 4 != (uVar3 & 0xff)) {
          local_1c = 0;
        }
        local_26 = local_26 + 1;
      }
      local_28 = local_28 + 1 & 1;
    }
    local_20 = 0;
    for (local_22 = 0; local_22 < 0xf; local_22 = local_22 + 1) {
      local_20 = local_20 ^ *(byte *)((int)&local_1a + local_22);
    }
    if ((int)(uint)*(byte *)((int)&local_1a + local_26) >> 4 != (local_20 & 0xf)) {
      local_1c = 0;
    }
    UTILGEN::PopRandom();
    if (local_1c != 0) {
      *param_1 = local_2c;
      param_1[1] = local_2a;
      PUBLIC::_memcpy(param_2,local_16,0xb);
    }
  }
  return local_1c;
}



// ======================================================================
// Function: FormatSerialAndEnv
// Address: 1020:2886
// ======================================================================


void __cdecl16far
MDI::FormatSerialAndEnv(undefined2 param_1,undefined2 param_2,int param_3,char *param_4)

{
  byte *pbVar1;
  int iVar2;
  undefined uVar3;
  byte bVar4;
  uint uVar5;
  byte local_40 [22];
  uint local_2a;
  uint local_28;
  uint local_26;
  int local_24;
  int local_22;
  int local_20;
  byte local_1e;
  uint local_1c;
  undefined2 local_1a;
  undefined2 local_18;
  undefined local_16 [20];
  
  local_26 = 0;
  UTILGEN::PushRandom(0xb,0x11);
  UTILGEN::Randomize(param_1,param_2);
  local_1a = param_1;
  local_18 = param_2;
  PUBLIC::_memcpy(local_16,param_3,0xb);
  local_24 = 0xf;
  for (local_20 = 0; iVar2 = local_24, local_20 < 0xb; local_20 = local_20 + 1) {
    for (local_1c = (uint)*(byte *)(param_3 + local_20); 0 < (int)local_1c; local_1c = local_1c - 1)
    {
      UTILGEN::Random(0x10);
    }
    if (local_26 == 0) {
      uVar3 = UTILGEN::Random(0x10);
      *(undefined *)((int)&local_1a + local_24) = uVar3;
    }
    else {
      uVar5 = UTILGEN::Random(0x10);
      iVar2 = local_24;
      local_24 = local_24 + 1;
      pbVar1 = (byte *)((int)&local_1a + iVar2);
      *pbVar1 = *pbVar1 | (byte)((uVar5 & 0xf) << 4);
    }
    local_26 = local_26 + 1 & 1;
  }
  local_1e = 0;
  for (local_20 = 0; local_20 < 0xf; local_20 = local_20 + 1) {
    local_1e = local_1e ^ *(byte *)((int)&local_1a + local_20);
  }
  local_24 = local_24 + 1;
  pbVar1 = (byte *)((int)&local_1a + iVar2);
  *pbVar1 = *pbVar1 | local_1e << 4;
  UTILGEN::PopRandom();
  for (local_20 = 0; local_20 < 0x15; local_20 = local_20 + 1) {
    local_40[local_20] = *(byte *)((int)&local_1a + (uint)*(byte *)(local_20 + 0x2870));
  }
  local_24 = 0;
  local_22 = 0;
  local_2a = 0;
  local_28 = 0;
  for (local_20 = 0; iVar2 = local_24, local_20 < 0x1c; local_20 = local_20 + 1) {
    if (local_22 < 6) {
      local_24 = local_24 + 1;
      uVar5 = (uint)local_40[iVar2] << ((byte)local_22 & 0x1f);
      local_2a = local_2a | uVar5;
      local_28 = local_28 | (int)uVar5 >> 0xf;
      local_22 = local_22 + 8;
    }
    bVar4 = (byte)local_2a & 0x3f;
    local_2a = PUBLIC::__aFlshr();
    local_22 = local_22 + -6;
    if (bVar4 < 0x1a) {
      *param_4 = bVar4 + 0x41;
    }
    else if (bVar4 < 0x34) {
      *param_4 = bVar4 + 0x47;
    }
    else if (bVar4 < 0x3e) {
      *param_4 = bVar4 - 4;
    }
    else if (bVar4 == 0x3e) {
      *param_4 = '-';
    }
    else {
      *param_4 = '*';
    }
    param_4 = param_4 + 1;
  }
  *param_4 = '\0';
  return;
}



// ======================================================================
// Function: LongFromSerialCh
// Address: 1038:6280
// ======================================================================


uint __cdecl16far UTIL::LongFromSerialCh(char param_1)

{
  uint local_8;
  int local_6;
  
  if ((param_1 < 'A') || ('Z' < param_1)) {
    local_8 = (int)param_1 - 0x16;
  }
  else {
    local_8 = (int)param_1 - 0x41;
  }
  local_6 = (int)local_8 >> 0xf;
  if ((local_6 < 0) || ((local_6 < 1 && (local_8 < 0x20)))) {
    local_8 = local_8 ^ 0x15;
  }
  return local_8;
}



// ======================================================================
// Function: FValidSerialNo
// Address: 1038:62f8
// ======================================================================


undefined2 __cdecl16far UTIL::FValidSerialNo(char *param_1,undefined2 *param_2)

{
  undefined2 uVar1;
  uint uVar2;
  uint uVar3;
  int in_DX;
  int iVar4;
  undefined2 uVar5;
  bool bVar6;
  long lVar7;
  undefined4 uVar8;
  uint local_16;
  int local_14;
  uint local_12;
  uint local_e;
  int local_a;
  int local_8;
  int local_6;
  
  local_12 = LongFromSerialCh((int)*param_1);
  if ((in_DX < 1) && ((in_DX < 0 || (local_12 < 0x20)))) {
    local_12 = local_12 ^ 0x15;
  }
  iVar4 = in_DX;
  uVar1 = LongFromSerialCh((int)param_1[1]);
  lVar7 = PUBLIC::__aFulmul(local_12,in_DX,0x24,0);
  lVar7 = lVar7 + CONCAT22(iVar4,uVar1);
  uVar5 = (undefined2)((ulong)lVar7 >> 0x10);
  uVar1 = LongFromSerialCh((int)param_1[4]);
  lVar7 = PUBLIC::__aFulmul(lVar7,0x24,0);
  lVar7 = lVar7 + CONCAT22(uVar5,uVar1);
  uVar5 = (undefined2)((ulong)lVar7 >> 0x10);
  uVar1 = LongFromSerialCh((int)param_1[7]);
  lVar7 = PUBLIC::__aFulmul(lVar7,0x24,0);
  lVar7 = lVar7 + CONCAT22(uVar5,uVar1);
  uVar5 = (undefined2)((ulong)lVar7 >> 0x10);
  uVar1 = LongFromSerialCh((int)param_1[3]);
  lVar7 = PUBLIC::__aFulmul(lVar7,0x24,0);
  lVar7 = lVar7 + CONCAT22(uVar5,uVar1);
  uVar1 = (undefined2)((ulong)lVar7 >> 0x10);
  if (param_2 != (undefined2 *)0x0) {
    *param_2 = (int)lVar7;
    param_2[1] = uVar1;
  }
  UTILGEN::PushRandom(0xb,0x11);
  UTILGEN::Randomize2(lVar7);
  local_e = PUBLIC::__aFlshr();
  local_8 = 0;
  local_6 = 0;
  for (local_a = 0; local_a < 3; local_a = local_a + 1) {
    local_16 = local_e & 0xf;
    for (local_14 = 0; (0 < local_14 || (-1 < local_14)); local_14 = local_14 - (uint)bVar6) {
      UTILGEN::Random(0x100);
      bVar6 = local_16 == 0;
      local_16 = local_16 - 1;
    }
    uVar2 = UTILGEN::Random(0x100);
    uVar3 = PUBLIC::__aFlshl();
    local_8 = uVar3 + uVar2;
    local_6 = local_6 + ((int)uVar2 >> 0xf) + (uint)CARRY2(uVar3,uVar2);
    local_e = PUBLIC::__aFlshr();
  }
  UTILGEN::PopRandom();
  uVar5 = LongFromSerialCh((int)param_1[2]);
  lVar7 = PUBLIC::__aFlrem(local_8,local_6,0x24,0);
  if (lVar7 == CONCAT22(uVar1,uVar5)) {
    uVar8 = PUBLIC::__aFldiv(local_8,local_6,0x24,0);
    uVar5 = (undefined2)((ulong)uVar8 >> 0x10);
    uVar1 = LongFromSerialCh((int)param_1[5]);
    lVar7 = PUBLIC::__aFlrem(uVar8,0x24,0);
    if (lVar7 == CONCAT22(uVar5,uVar1)) {
      uVar8 = PUBLIC::__aFldiv(uVar8,0x24,0);
      uVar5 = (undefined2)((ulong)uVar8 >> 0x10);
      uVar1 = LongFromSerialCh((int)param_1[6]);
      lVar7 = PUBLIC::__aFlrem(uVar8,0x24,0);
      if (lVar7 == CONCAT22(uVar5,uVar1)) {
        uVar1 = 1;
      }
      else {
        uVar1 = 0;
      }
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// ======================================================================
// Function: FValidSerialLong
// Address: 1070:48c4
// ======================================================================


/* WARNING: Removing unreachable block (ram,0x10704975) */

undefined2 __cdecl16far IO::FValidSerialLong(uint param_1,int param_2)

{
  int iVar1;
  undefined2 uVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  int local_a;
  uint local_8;
  int local_6;
  
  iVar1 = FBogusLong(param_1,param_2);
  if (iVar1 == 0) {
    lVar4 = CONCAT22(param_2,param_1);
    for (local_a = 0; local_a < 4; local_a = local_a + 1) {
      lVar4 = PUBLIC::__aFuldiv(lVar4,0x24,0);
    }
    local_a = 0;
    lVar5 = lVar4;
    while( true ) {
      local_6 = (int)((ulong)lVar5 >> 0x10);
      local_8 = (uint)lVar5;
      if (3 < local_a) break;
      lVar5 = PUBLIC::__aFulmul(lVar5,0x24,0);
      local_a = local_a + 1;
    }
    uVar3 = (param_2 - local_6) - (uint)(param_1 < local_8);
    if (((param_2 - local_6 == (uint)(param_1 < local_8)) && (param_1 - local_8 < 100)) ||
       ((0x15 < uVar3 && ((0x16 < uVar3 || (0xe360 < param_1 - local_8)))))) {
      uVar2 = 0;
    }
    else if ((((lVar4 == 0x12) || (lVar4 == 0x16)) || (lVar4 == 2)) ||
            ((lVar4 == 4 || (lVar4 == 6)))) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



