#ifndef IS_APPLE
static void m05500m (__L u32 s_SPtrans[8][64], __L u32 s_skb[8][64], u32 w[16], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset)
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

  const u32 s0 = salt_bufs[salt_pos].salt_buf[0];
  const u32 s1 = salt_bufs[salt_pos].salt_buf[1];
  const u32 s2 = salt_bufs[salt_pos].salt_buf[2];

  u32 data[2];

  data[0] = s0;
  data[1] = s1;

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < bfs_cnt; il_pos++)
  {
    const u32 w0r = words_buf_r[il_pos];

    const u32 w0 = w0l | w0r;

    u32 a = MD4M_A;
    u32 b = MD4M_B;
    u32 c = MD4M_C;
    u32 d = MD4M_D;

    #define w0_t w0
    #define w1_t w[ 1]
    #define w2_t w[ 2]
    #define w3_t w[ 3]
    #define w4_t w[ 4]
    #define w5_t w[ 5]
    #define w6_t w[ 6]
    #define w7_t w[ 7]
    #define w8_t w[ 8]
    #define w9_t w[ 9]
    #define wa_t w[10]
    #define wb_t w[11]
    #define wc_t w[12]
    #define wd_t w[13]
    #define we_t w[14]
    #define wf_t w[15]

    MD4_STEP (MD4_Fo, a, b, c, d, w0_t, MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1_t, MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2_t, MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3_t, MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w4_t, MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w5_t, MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w6_t, MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w7_t, MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w8_t, MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w9_t, MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, wa_t, MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, wb_t, MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, wc_t, MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, wd_t, MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, we_t, MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, wf_t, MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0_t, MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w4_t, MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w8_t, MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, wc_t, MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w1_t, MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w5_t, MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w9_t, MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, wd_t, MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w2_t, MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w6_t, MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, wa_t, MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, we_t, MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w3_t, MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w7_t, MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, wb_t, MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, wf_t, MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0_t, MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w8_t, MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w4_t, MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, wc_t, MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w2_t, MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, wa_t, MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w6_t, MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, we_t, MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w1_t, MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w9_t, MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w5_t, MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, wd_t, MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w3_t, MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, wb_t, MD4C02, MD4S21);

    if (allx (s2 != ((d + MD4M_D) >> 16))) continue;

    MD4_STEP (MD4_H , c, d, a, b, w7_t, MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, wf_t, MD4C02, MD4S23);

    a += MD4M_A;
    b += MD4M_B;
    c += MD4M_C;
    d += MD4M_D;

    /**
     * DES1
     */

    u32 key[2];

    transform_netntlmv1_key (a, b, key);

    u32 Kc[16];
    u32 Kd[16];

    #ifndef IS_APPLE
    _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);
    #else
    u32 tt;
    #define c key[0]
    #define d key[1]
    #include DES_CRYPT_KEYSETUP
    #undef c
    #undef d
    #endif

    u32 iv1[2];

    #ifndef IS_APPLE
    _des_crypt_encrypt (iv1, data, Kc, Kd, s_SPtrans);
    #else
    u32 r;
    u32 l;
    #define iv iv1
    #include DES_CRYPT_ENCRYPT
    #undef iv
    #endif

    /**
     * DES2
     */

    const u32 bc = (b >> 24) | (c << 8);
    const u32 cd = (c >> 24) | (d << 8);

    transform_netntlmv1_key (bc, cd, key);

    #ifndef IS_APPLE
    _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);
    #else
    #define c key[0]
    #define d key[1]
    #include DES_CRYPT_KEYSETUP
    #undef c
    #undef d
    #endif

    u32 iv2[2];

    #ifndef IS_APPLE
    _des_crypt_encrypt (iv2, data, Kc, Kd, s_SPtrans);
    #else
    #define iv iv2
    #include DES_CRYPT_ENCRYPT
    #undef iv
    #endif

    /**
     * compare
     */

    const u32 r0 = iv1[0];
    const u32 r1 = iv1[1];
    const u32 r2 = iv2[0];
    const u32 r3 = iv2[1];

    #include COMPARE_M
  }

#ifndef IS_APPLE
}
#endif
