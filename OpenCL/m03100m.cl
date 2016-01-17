#ifndef IS_APPLE
static void m03100m (__L u32 s_SPtrans[8][64], __L u32 s_skb[8][64], u32 w[16], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

#endif

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf1[4];

  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  u32 salt_buf2[4];

  salt_buf2[0] = 0;
  salt_buf2[1] = 0;
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 salt_word_len = (salt_len + pw_len) * 2;

  /**
   * prepend salt
   */

  u32 w0_t[4];
  u32 w1_t[4];
  u32 w2_t[4];
  u32 w3_t[4];

  w0_t[0] = w[ 0];
  w0_t[1] = w[ 1];
  w0_t[2] = w[ 2];
  w0_t[3] = w[ 3];
  w1_t[0] = w[ 4];
  w1_t[1] = w[ 5];
  w1_t[2] = w[ 6];
  w1_t[3] = w[ 7];
  w2_t[0] = w[ 8];
  w2_t[1] = w[ 9];
  w2_t[2] = w[10];
  w2_t[3] = w[11];
  w3_t[0] = w[12];
  w3_t[1] = w[13];
  w3_t[2] = w[14];
  w3_t[3] = w[15];

  switch_buffer_by_offset (w0_t, w1_t, w2_t, w3_t, salt_len);

  w0_t[0] |= salt_buf0[0];
  w0_t[1] |= salt_buf0[1];
  w0_t[2] |= salt_buf0[2];
  w0_t[3] |= salt_buf0[3];
  w1_t[0] |= salt_buf1[0];
  w1_t[1] |= salt_buf1[1];
  w1_t[2] |= salt_buf1[2];
  w1_t[3] |= salt_buf1[3];
  w2_t[0] |= salt_buf2[0];
  w2_t[1] |= salt_buf2[1];
  w2_t[2] |= salt_buf2[2];
  w2_t[3] |= salt_buf2[3];
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  u32 dst[16];

  dst[ 0] = w0_t[0];
  dst[ 1] = w0_t[1];
  dst[ 2] = w0_t[2];
  dst[ 3] = w0_t[3];
  dst[ 4] = w1_t[0];
  dst[ 5] = w1_t[1];
  dst[ 6] = w1_t[2];
  dst[ 7] = w1_t[3];
  dst[ 8] = w2_t[0];
  dst[ 9] = w2_t[1];
  dst[10] = w2_t[2];
  dst[11] = w2_t[3];
  dst[12] = w3_t[0];
  dst[13] = w3_t[1];
  dst[14] = w3_t[2];
  dst[15] = w3_t[3];

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = words_buf_r[il_pos];

    const u32 w0 = w0l | w0r;

    overwrite_at (dst, w0, salt_len);

    /**
     * precompute key1 since key is static: 0x0123456789abcdef
     * plus LEFT_ROTATE by 2
     */

    u32 Kc[16];

    Kc[ 0] = 0x64649040;
    Kc[ 1] = 0x14909858;
    Kc[ 2] = 0xc4b44888;
    Kc[ 3] = 0x9094e438;
    Kc[ 4] = 0xd8a004f0;
    Kc[ 5] = 0xa8f02810;
    Kc[ 6] = 0xc84048d8;
    Kc[ 7] = 0x68d804a8;
    Kc[ 8] = 0x0490e40c;
    Kc[ 9] = 0xac183024;
    Kc[10] = 0x24c07c10;
    Kc[11] = 0x8c88c038;
    Kc[12] = 0xc048c824;
    Kc[13] = 0x4c0470a8;
    Kc[14] = 0x584020b4;
    Kc[15] = 0x00742c4c;

    u32 Kd[16];

    Kd[ 0] = 0xa42ce40c;
    Kd[ 1] = 0x64689858;
    Kd[ 2] = 0x484050b8;
    Kd[ 3] = 0xe8184814;
    Kd[ 4] = 0x405cc070;
    Kd[ 5] = 0xa010784c;
    Kd[ 6] = 0x6074a800;
    Kd[ 7] = 0x80701c1c;
    Kd[ 8] = 0x9cd49430;
    Kd[ 9] = 0x4c8ce078;
    Kd[10] = 0x5c18c088;
    Kd[11] = 0x28a8a4c8;
    Kd[12] = 0x3c180838;
    Kd[13] = 0xb0b86c20;
    Kd[14] = 0xac84a094;
    Kd[15] = 0x4ce0c0c4;

    /**
     * key1 (generate key)
     */

    u32 iv[2];

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32 data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      #ifndef IS_APPLE
      _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
      #else
      #include DES_CRYPT_ENCRYPT
      #endif
    }

    /**
     * key2 (generate hash)
     */

    #ifndef IS_APPLE
    _des_crypt_keysetup (iv[0], iv[1], Kc, Kd, s_skb);
    #else
    #define c iv[0]
    #define d iv[1]
    #include DES_CRYPT_KEYSETUP
    #undef c
    #undef d
    #endif

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32 data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      #ifndef IS_APPLE
      _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
      #else
      #include DES_CRYPT_ENCRYPT
      #endif
    }

    /**
     * cmp
     */

    const u32 r0 = iv[0];
    const u32 r1 = iv[1];
    const u32 r2 = 0;
    const u32 r3 = 0;

    #include COMPARE_M
  }

#ifndef IS_APPLE
}
#endif
