#ifndef IS_APPLE
static void m08600m (__L u32 s_lotus_magic_table[256], u32 w[16], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

#endif

  /**
   * padding
   */

  if (pw_len < 16)
  {
    pad (&w[ 0], pw_len & 0xf);
  }
  else if (pw_len < 32)
  {
    pad (&w[ 4], pw_len & 0xf);
  }
  else if (pw_len < 48)
  {
    pad (&w[ 8], pw_len & 0xf);
  }
  else if (pw_len < 64)
  {
    pad (&w[12], pw_len & 0xf);
  }

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = words_buf_r[il_pos];

    const u32 w0 = w0l | w0r;

    u32 w_tmp[16];

    w_tmp[ 0] = w0;
    w_tmp[ 1] = w[ 1];
    w_tmp[ 2] = w[ 2];
    w_tmp[ 3] = w[ 3];
    w_tmp[ 4] = w[ 4];
    w_tmp[ 5] = w[ 5];
    w_tmp[ 6] = w[ 6];
    w_tmp[ 7] = w[ 7];
    w_tmp[ 8] = w[ 8];
    w_tmp[ 9] = w[ 9];
    w_tmp[10] = w[10];
    w_tmp[11] = w[11];
    w_tmp[12] = w[12];
    w_tmp[13] = w[13];
    w_tmp[14] = w[14];
    w_tmp[15] = w[15];

    u32 state[4];

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    #ifndef IS_APPLE
    domino_big_md (w_tmp, pw_len, state, s_lotus_magic_table);
    #else
    #define saved_key w_tmp
    #include DOMINO_BIG_MD
    #undef saved_key
    #endif

    const u32 r0 = state[0];
    const u32 r1 = state[1];
    const u32 r2 = state[2];
    const u32 r3 = state[3];

    #include COMPARE_M
  }

#ifndef IS_APPLE
}
#endif