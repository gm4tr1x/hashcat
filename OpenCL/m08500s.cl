#ifndef IS_APPLE
static void m08500s (__L u32 s_SPtrans[8][64], __L u32 s_skb[8][64], u32 w[16], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset)
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

  u32 salt_buf0[2];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf_pc[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf_pc[1];

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
   * loop
   */

  u32 w0l = w[0];

  u32 w1 = w[1];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = words_buf_r[il_pos];

    const u32 w0 = w0l | w0r;

    u32 key[2];

    transform_racf_key (w0, w1, key);

    u32 c = key[0];
    u32 d = key[1];

    u32 Kc[16];
    u32 Kd[16];

    #ifndef IS_APPLE
    _des_crypt_keysetup (c, d, Kc, Kd, s_skb);
    #else
    u32 tt;
    #include DES_CRYPT_KEYSETUP
    #endif

    u32 data[2];

    data[0] = salt_buf0[0];
    data[1] = salt_buf0[1];

    u32 iv[2];

    #ifndef IS_APPLE
    _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
    #else
    u32 r, l;
    #include DES_CRYPT_ENCRYPT
    #endif

    const u32 r0 = iv[0];
    const u32 r1 = iv[1];
    const u32 r2 = 0;
    const u32 r3 = 0;

    #include COMPARE_S
  }

#ifndef IS_APPLE
}
#endif
