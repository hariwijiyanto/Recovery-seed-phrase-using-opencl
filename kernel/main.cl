
// main.cl - Kernel brute-force BIP39 seed dari kombinasi kata subset
#include "kernel/sha512.cl"
#include "kernel/sha256.cl"
#include "kernel/pbkdf2_hmac_sha512.cl"
#include "kernel/hmac_sha512.cl"
#include "kernel/ec.cl"
#include "kernel/common.cl"
#include "kernel/bip39.cl"

__constant char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void base58_encode(const uchar *input, uint len, __global uchar *output) {
  uchar temp[64] = {0};
  uint digits[64] = {0};
  uint digitlength = 1;
  for (uint i = 0; i < len; i++) {
    uint carry = input[i];
    for (uint j = 0; j < digitlength; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry /= 58;
    }
    while (carry) {
      digits[digitlength++] = carry % 58;
      carry /= 58;
    }
  }

  uint zeroes = 0;
  while (zeroes < len && input[zeroes] == 0) {
    zeroes++;
  }

  uint p = 0;
  for (uint i = 0; i < zeroes; i++) {
    output[p++] = BASE58_ALPHABET[0];
  }
  for (int i = digitlength - 1; i >= 0; i--) {
    output[p++] = BASE58_ALPHABET[digits[i]];
  }
  output[p] = '\0';
}

__kernel void verify(__global const ushort *subset,
                     const uint subset_len,
                     const ulong total_comb,
                     __global ushort *output) {

  ulong gid = get_global_id(0);
  if (gid >= total_comb)
    return;

  ushort indices[12];
  #pragma unroll
  for (int i = 0; i < 12; i++) {
    ulong div = 1;
    for (int j = 0; j < i; j++) div *= subset_len;
    indices[i] = subset[(gid / div) % subset_len];
  }

  uint seedNum[12];
  for (int i = 0; i < 12; i++) seedNum[i] = indices[i];

  uchar mnemonicString[128] = {0};
  uint offset = 0;
  prepareSeedString(seedNum, mnemonicString, offset);

  ulong mnemonicLong[16] = {0};
  ucharLong(mnemonicString, offset - 1, mnemonicLong, 0);

  ulong inner_data[32] = {0};
  ulong outer_data[32] = {0};
  ulong pbkdLong[16] = {0};
  ulong hmacSeedOutput[8] = {0};

  for (int lid = 0; lid < 16; lid++) {
    inner_data[lid] = mnemonicLong[lid] ^ IPAD;
    outer_data[lid] = mnemonicLong[lid] ^ OPAD;
  }
  outer_data[16] = 6655295901103053916UL;
  inner_data[16] = 7885351518267664739UL;
  inner_data[17] = 6442450944UL;
  outer_data[24] = 0x8000000000000000UL;
  outer_data[31] = 1536UL;
  inner_data[31] = 1120UL;

  pbkdf2_hmac_sha512_long(inner_data, outer_data, pbkdLong);
  hmac_sha512_bitcoin_seed(pbkdLong, hmacSeedOutput);

  // EC derive public key
  uint seckey[8];
  for (int i = 0; i < 8; i++)
    seckey[i] = (uint)((hmacSeedOutput[i / 2] >> ((1 - (i % 2)) * 32)) & 0xFFFFFFFF);

  uint pubkey[64] = {0};
  derive_public_key(seckey, pubkey);

  // Hash pubkey: SHA256 then RIPEMD160
  uchar pubkey_bytes[65] = {0};
  pubkey_bytes[0] = 0x04;
  for (int i = 0; i < 64; i++)
    pubkey_bytes[i + 1] = (uchar)((pubkey[i / 4] >> (8 * (3 - (i % 4)))) & 0xFF);

  uint sha_out[8] = {0};
  sha256(pubkey_bytes, 65, sha_out);

  uchar sha_bytes[32];
  for (int i = 0; i < 8; i++) {
    sha_bytes[i * 4 + 0] = (sha_out[i] >> 24) & 0xff;
    sha_bytes[i * 4 + 1] = (sha_out[i] >> 16) & 0xff;
    sha_bytes[i * 4 + 2] = (sha_out[i] >> 8) & 0xff;
    sha_bytes[i * 4 + 3] = sha_out[i] & 0xff;
  }

  uchar hash160[20];
  ripemd160(sha_bytes, hash160);

  uchar addr_input[25];
  addr_input[0] = 0x00;
  for (int i = 0; i < 20; i++) addr_input[i + 1] = hash160[i];

  uint chk[8] = {0};
  sha256(addr_input, 21, chk);
  sha256((uchar*)chk, 32, chk);
  for (int i = 0; i < 4; i++)
    addr_input[21 + i] = (chk[0] >> (24 - 8 * i)) & 0xFF;

  uchar address[64];
  base58_encode(addr_input, 25, address);

  const char target[] = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo";
  int match = 1;
  for (int i = 0; target[i] != 0 && i < 64; i++) {
    if (target[i] != address[i]) {
      match = 0;
      break;
    }
  }

  if (match) {
    for (int i = 0; i < 12; i++) {
      output[i] = indices[i];
    }
  }
}
