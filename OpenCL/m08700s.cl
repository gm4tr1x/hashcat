#ifndef IS_APPLE
static void m08700s (__L u32 s_lotus_magic_table[256], __L u32 l_bin2asc[256], u32 w[16], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset)
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
   * salt
   */

  const u32 salt0 = salt_bufs[salt_pos].salt_buf[0];
  const u32 salt1 = (salt_bufs[salt_pos].salt_buf[1] & 0xff) | '(' << 8;

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
    u32 dbm_checksum[4];
    u32 dbm_block[4];
    u32 curpos;
    u32 idx;
    u32 p, t, c2;
    u32 x[12];
    #define saved_key w_tmp
    #define size pw_len
    #include DOMINO_BIG_MD
    #undef saved_key
    #undef size
    #endif

    const u32 w0_t = uint_to_hex_upper8 ((state[0] >>  0) & 255) <<  0
                     | uint_to_hex_upper8 ((state[0] >>  8) & 255) << 16;
    const u32 w1_t = uint_to_hex_upper8 ((state[0] >> 16) & 255) <<  0
                     | uint_to_hex_upper8 ((state[0] >> 24) & 255) << 16;
    const u32 w2_t = uint_to_hex_upper8 ((state[1] >>  0) & 255) <<  0
                     | uint_to_hex_upper8 ((state[1] >>  8) & 255) << 16;
    const u32 w3_t = uint_to_hex_upper8 ((state[1] >> 16) & 255) <<  0
                     | uint_to_hex_upper8 ((state[1] >> 24) & 255) << 16;
    const u32 w4_t = uint_to_hex_upper8 ((state[2] >>  0) & 255) <<  0
                     | uint_to_hex_upper8 ((state[2] >>  8) & 255) << 16;
    const u32 w5_t = uint_to_hex_upper8 ((state[2] >> 16) & 255) <<  0
                     | uint_to_hex_upper8 ((state[2] >> 24) & 255) << 16;
    const u32 w6_t = uint_to_hex_upper8 ((state[3] >>  0) & 255) <<  0
                     | uint_to_hex_upper8 ((state[3] >>  8) & 255) << 16;
    //const u32 w7_t = uint_to_hex_upper8 ((state[3] >> 16) & 255) <<  0
    //                 | uint_to_hex_upper8 ((state[3] >> 24) & 255) << 16;

    const u32 pade = 0x0e0e0e0e;

    w_tmp[ 0] = salt0;
    w_tmp[ 1] = salt1      | w0_t << 16;
    w_tmp[ 2] = w0_t >> 16 | w1_t << 16;
    w_tmp[ 3] = w1_t >> 16 | w2_t << 16;
    w_tmp[ 4] = w2_t >> 16 | w3_t << 16;
    w_tmp[ 5] = w3_t >> 16 | w4_t << 16;
    w_tmp[ 6] = w4_t >> 16 | w5_t << 16;
    w_tmp[ 7] = w5_t >> 16 | w6_t << 16;
    w_tmp[ 8] = w6_t >> 16 | pade << 16; // | w7_t <<  8;
    w_tmp[ 9] = pade;
    w_tmp[10] = pade;
    w_tmp[11] = pade;
    w_tmp[12] = 0;
    w_tmp[13] = 0;
    w_tmp[14] = 0;
    w_tmp[15] = 0;

    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    #ifndef IS_APPLE
    domino_big_md (w_tmp, 34, state, s_lotus_magic_table);
    #else
    const u32 pw_len2 = 34;
    #define saved_key w_tmp
    #define size pw_len2
    #include DOMINO_BIG_MD
    #undef saved_key
    #undef size
    #endif

    u32 a = state[0] & 0xffffffff;
    u32 b = state[1] & 0xffffffff;
    u32 c = state[2] & 0x000000ff;
    u32 d = state[3] & 0x00000000;

    const u32 r0 = a;
    const u32 r1 = b;
    const u32 r2 = c;
    const u32 r3 = d;

    #include COMPARE_S
  }
#ifndef IS_APPLE
}
#endif
