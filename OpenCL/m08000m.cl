#ifndef IS_APPLE
static void m08000m (__L u32 w_s1[64], __L u32 w_s2[64], u32 w[16], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

#endif

  w[ 1] = w[ 1] >> 8;
  w[ 2] = w[ 2] >> 8;
  w[ 3] = w[ 3] >> 8;
  w[ 4] = w[ 4] >> 8;
  w[ 5] = w[ 5] >> 8;
  w[ 6] = w[ 6] >> 8;
  w[ 7] = w[ 7] >> 8;
  w[ 8] = w[ 8] >> 8;
  w[ 9] = w[ 9] >> 8;
  w[10] = w[10] >> 8;
  w[11] = w[11] >> 8;
  w[12] = w[12] >> 8;
  w[13] = w[13] >> 8;
  w[14] = w[14] >> 8;
  w[15] = w[15] >> 8;

  /**
   * salt
   */

  const u32 salt_buf0 = swap32 (salt_bufs[salt_pos].salt_buf[ 0]);
  const u32 salt_buf1 = swap32 (salt_bufs[salt_pos].salt_buf[ 1]);
  const u32 salt_buf2 = swap32 (salt_bufs[salt_pos].salt_buf[ 2]); // 0x80

  /**
   * precompute final msg blocks
   */

  w_s1[lid] = 0;
  w_s2[lid] = 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (lid == 0)
  {
    w_s1[15] =               0 | salt_buf0 >> 16;

    #pragma unroll
    for (int i = 16; i < 64; i++)
    {
      w_s1[i] = SHA256_EXPAND (w_s1[i - 2], w_s1[i - 7], w_s1[i - 15], w_s1[i - 16]);
    }
  }
  else if (lid == 1)
  {
    w_s2[ 0] = salt_buf0 << 16 | salt_buf1 >> 16;
    w_s2[ 1] = salt_buf1 << 16 | salt_buf2 >> 16;
    w_s2[ 2] = salt_buf2 << 16 | 0;
    w_s2[15] = (510 + 8) * 8;

    #pragma unroll
    for (int i = 16; i < 64; i++)
    {
      w_s2[i] = SHA256_EXPAND (w_s2[i - 2], w_s2[i - 7], w_s2[i - 15], w_s2[i - 16]);
    }
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = words_buf_r[il_pos];

    const u32 w0 = w0l | w0r;

    w[0] = w0 >> 8;

    u32 digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform   (digest, w);     //   0 -  64
    sha256_transform_z (digest);        //  64 - 128
    sha256_transform_z (digest);        // 128 - 192
    sha256_transform_z (digest);        // 192 - 256
    sha256_transform_z (digest);        // 256 - 320
    sha256_transform_z (digest);        // 320 - 384
    sha256_transform_z (digest);        // 384 - 448

    #ifndef IS_APPLE
    sha256_transform_s (digest, w_s1);  // 448 - 512
    sha256_transform_s (digest, w_s2);  // 512 - 576
    #else
    u32 a, b, c, d, e, f, g, h;
    #define w w_s1
    #include SHA256_TRANSFORM_S
    #undef w
    #define w w_s2
    #include SHA256_TRANSFORM_S
    #undef w
    #endif

    const u32 r0 = digest[3];
    const u32 r1 = digest[7];
    const u32 r2 = digest[2];
    const u32 r3 = digest[6];

    #include COMPARE_M
  }

#ifndef IS_APPLE
}
#endif
