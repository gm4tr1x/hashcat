#ifndef IS_APPLE
static void m08400s (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, __L u32 l_bin2asc[256])
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

#endif

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 0]);
  salt_buf0[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 1]);
  salt_buf0[2] = swap32 (salt_bufs[salt_pos].salt_buf[ 2]);
  salt_buf0[3] = swap32 (salt_bufs[salt_pos].salt_buf[ 3]);

  u32 salt_buf1[4];

  salt_buf1[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 4]);
  salt_buf1[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 5]);
  salt_buf1[2] = swap32 (salt_bufs[salt_pos].salt_buf[ 6]);
  salt_buf1[3] = swap32 (salt_bufs[salt_pos].salt_buf[ 7]);

  u32 salt_buf2[4];

  salt_buf2[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 8]);
  salt_buf2[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 9]);
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = bfs_buf[il_pos].i;

    w0[0] = w0l | w0r;

    u32 w0_t[4];

    w0_t[0] = w0[0];
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];

    u32 w1_t[4];

    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];

    u32 w2_t[4];

    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];

    u32 w3_t[4];

    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = 0;
    w3_t[3] = pw_len * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    u32 a;
    u32 b;
    u32 c;
    u32 d;
    u32 e;

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1_t[0] = 0x80000000;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = (salt_len + 40) * 8;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1_t[0] = 0x80000000;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = (salt_len + 40) * 8;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    const u32 r0 = digest[3];
    const u32 r1 = digest[4];
    const u32 r2 = digest[2];
    const u32 r3 = digest[1];

    #include COMPARE_S
  }

#ifndef IS_APPLE
}
#endif