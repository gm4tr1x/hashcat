#ifndef IS_APPLE
static void m06900m (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, __L u32 s_tables[4][256])
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

#endif

  /**
   * base
   */

  const u32 w14 = pw_len * 8;

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = bfs_buf[il_pos].i;

    w0[0] = w0l | w0r;

    u32 data[8];

    data[0] = w0[0];
    data[1] = w0[1];
    data[2] = w0[2];
    data[3] = w0[3];
    data[4] = w1[0];
    data[5] = w1[1];
    data[6] = w1[2];
    data[7] = w1[3];

    u32 state[16];

    state[ 0] = 0;
    state[ 1] = 0;
    state[ 2] = 0;
    state[ 3] = 0;
    state[ 4] = 0;
    state[ 5] = 0;
    state[ 6] = 0;
    state[ 7] = 0;
    state[ 8] = data[0];
    state[ 9] = data[1];
    state[10] = data[2];
    state[11] = data[3];
    state[12] = data[4];
    state[13] = data[5];
    state[14] = data[6];
    state[15] = data[7];

    u32 state_m[8];
    u32 data_m[8];

    /* gost1 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    u32 tmp[8];

    if (pw_len > 0)
    {
      PASS0 (state, tmp, state_m, data_m, s_tables);
      PASS2 (state, tmp, state_m, data_m, s_tables);
      PASS4 (state, tmp, state_m, data_m, s_tables);
      PASS6 (state, tmp, state_m, data_m, s_tables);

      SHIFT12 (state_m, data, tmp);
      SHIFT16 (state, data_m, state_m);
      SHIFT61 (state, data_m);
    }

    data[0] = w14;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;

    /* gost2 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* gost3 */

    data[0] = state[ 8];
    data[1] = state[ 9];
    data[2] = state[10];
    data[3] = state[11];
    data[4] = state[12];
    data[5] = state[13];
    data[6] = state[14];
    data[7] = state[15];

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* store */

    const u32 r0 = state[0];
    const u32 r1 = state[1];
    const u32 r2 = state[2];
    const u32 r3 = state[3];

    #include COMPARE_M
  }

#ifndef IS_APPLE
}
#endif