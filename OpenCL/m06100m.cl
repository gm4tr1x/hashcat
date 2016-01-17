#ifndef IS_APPLE
static void m06100m (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, __L u32 s_Cl[8][256], __L u32 s_Ch[8][256])
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

#endif

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = bfs_buf[il_pos].i;

    w0[0] = w0l | w0r;

    u32 wl[16];

    wl[ 0] = w0[0];
    wl[ 1] = w0[1];
    wl[ 2] = w0[2];
    wl[ 3] = w0[3];
    wl[ 4] = w1[0];
    wl[ 5] = w1[1];
    wl[ 6] = w1[2];
    wl[ 7] = w1[3];
    wl[ 8] = w2[0];
    wl[ 9] = w2[1];
    wl[10] = w2[2];
    wl[11] = w2[3];
    wl[12] = w3[0];
    wl[13] = w3[1];
    wl[14] = 0;
    wl[15] = pw_len * 8;

    u32 dgst[16];

    #ifndef IS_APPLE
    whirlpool_transform (wl, dgst, s_Ch, s_Cl);
    #else
    #define w wl
    #include WHIRLPOOL_TRANSFORM
    #undef w
    #endif

    const u32 r0 = dgst[0];
    const u32 r1 = dgst[1];
    const u32 r2 = dgst[2];
    const u32 r3 = dgst[3];

    #include COMPARE_M
  }

#ifndef IS_APPLE
}
#endif
