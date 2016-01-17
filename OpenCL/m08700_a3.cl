/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _LOTUS6_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 0
#define DGST_R1 1
#define DGST_R2 2
#define DGST_R3 3

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

#define LOTUS_MIX "OpenCL/m08700_lotus_mix.cl"
#define LOTUS_TRANSFORM_PASSWORD "OpenCL/m08700_lotus_transform_password.cl"
#define MDTRANSFORM_NORECALC "OpenCL/m08700_mdtransform_norecalc.cl"
#define MDTRANSFORM "OpenCL/m08700_mdtransform.cl"
#define DOMINO_BIG_MD "OpenCL/m08700_domino_big_md.cl"

#define COMPUTE_S "OpenCL/m08700s.cl"
#define COMPUTE_M "OpenCL/m08700m.cl"

__constant u32 lotus_magic_table[256] =
{
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
  0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
  0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
  0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
  0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
  0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
  0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
  0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
  0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
  0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
  0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
  0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
  0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
  0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
  0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
  0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
  0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
  0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
  0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
  0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
  0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
  0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
};

#define BOX(S,i) (S)[(i)]

#define uint_to_hex_upper8(i) l_bin2asc[(i)]

#ifndef IS_APPLE
#include LOTUS_MIX
#endif

#ifndef IS_APPLE
#include LOTUS_TRANSFORM_PASSWORD
#endif

static void pad (u32 w[4], const u32 len)
{
  const u32 val = 16 - len;

  const u32 mask1 = val << 24;

  const u32 mask2 = val << 16
                   | val << 24;

  const u32 mask3 = val <<  8
                   | val << 16
                   | val << 24;

  const u32 mask4 = val <<  0
                   | val <<  8
                   | val << 16
                   | val << 24;

  switch (len)
  {
    case  0:  w[0]  = mask4;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  1:  w[0] |= mask3;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  2:  w[0] |= mask2;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  3:  w[0] |= mask1;
              w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  4:  w[1]  = mask4;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  5:  w[1] |= mask3;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  6:  w[1] |= mask2;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  7:  w[1] |= mask1;
              w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  8:  w[2]  = mask4;
              w[3]  = mask4;
              break;
    case  9:  w[2] |= mask3;
              w[3]  = mask4;
              break;
    case 10:  w[2] |= mask2;
              w[3]  = mask4;
              break;
    case 11:  w[2] |= mask1;
              w[3]  = mask4;
              break;
    case 12:  w[3]  = mask4;
              break;
    case 13:  w[3] |= mask3;
              break;
    case 14:  w[3] |= mask2;
              break;
    case 15:  w[3] |= mask1;
              break;
  }
}

#ifndef IS_APPLE
#inclde MDTRANSFORM_NORECALC
#endif

#ifndef IS_APPLE
#include MDTRANSFORM
#endif

#ifndef IS_APPLE
#include DOMINO_BIG_MD
#endif

#ifndef IS_APPLE
#include COMPUTE_M
#include COMPUTE_S
#endif

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m08700_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'A' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'A' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'A' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'A' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'A' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'A' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'A' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'A' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  s_lotus_magic_table[lid4 + 0] = lotus_magic_table[lid4 + 0];
  s_lotus_magic_table[lid4 + 1] = lotus_magic_table[lid4 + 1];
  s_lotus_magic_table[lid4 + 2] = lotus_magic_table[lid4 + 2];
  s_lotus_magic_table[lid4 + 3] = lotus_magic_table[lid4 + 3];

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_M
  #else
  m08700m (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m08700_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'A' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'A' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'A' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'A' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'A' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'A' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'A' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'A' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  s_lotus_magic_table[lid4 + 0] = lotus_magic_table[lid4 + 0];
  s_lotus_magic_table[lid4 + 1] = lotus_magic_table[lid4 + 1];
  s_lotus_magic_table[lid4 + 2] = lotus_magic_table[lid4 + 2];
  s_lotus_magic_table[lid4 + 3] = lotus_magic_table[lid4 + 3];

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_M
  #else
  m08700m (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m08700_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'A' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'A' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'A' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'A' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'A' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'A' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'A' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'A' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  s_lotus_magic_table[lid4 + 0] = lotus_magic_table[lid4 + 0];
  s_lotus_magic_table[lid4 + 1] = lotus_magic_table[lid4 + 1];
  s_lotus_magic_table[lid4 + 2] = lotus_magic_table[lid4 + 2];
  s_lotus_magic_table[lid4 + 3] = lotus_magic_table[lid4 + 3];

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_M
  #else
  m08700m (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m08700_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'A' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'A' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'A' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'A' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'A' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'A' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'A' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'A' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  s_lotus_magic_table[lid4 + 0] = lotus_magic_table[lid4 + 0];
  s_lotus_magic_table[lid4 + 1] = lotus_magic_table[lid4 + 1];
  s_lotus_magic_table[lid4 + 2] = lotus_magic_table[lid4 + 2];
  s_lotus_magic_table[lid4 + 3] = lotus_magic_table[lid4 + 3];

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_S
  #else
  m08700s (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m08700_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'A' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'A' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'A' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'A' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'A' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'A' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'A' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'A' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  s_lotus_magic_table[lid4 + 0] = lotus_magic_table[lid4 + 0];
  s_lotus_magic_table[lid4 + 1] = lotus_magic_table[lid4 + 1];
  s_lotus_magic_table[lid4 + 2] = lotus_magic_table[lid4 + 2];
  s_lotus_magic_table[lid4 + 3] = lotus_magic_table[lid4 + 3];

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_S
  #else
  m08700s (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m08700_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __constant u32 * words_buf_r, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'A' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'A' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'A' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'A' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'A' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'A' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'A' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'A' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  /**
   * sbox
   */

  __local u32 s_lotus_magic_table[256];

  s_lotus_magic_table[lid4 + 0] = lotus_magic_table[lid4 + 0];
  s_lotus_magic_table[lid4 + 1] = lotus_magic_table[lid4 + 1];
  s_lotus_magic_table[lid4 + 2] = lotus_magic_table[lid4 + 2];
  s_lotus_magic_table[lid4 + 3] = lotus_magic_table[lid4 + 3];

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_S
  #else
  m08700s (s_lotus_magic_table, l_bin2asc, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset);
  #endif
}
