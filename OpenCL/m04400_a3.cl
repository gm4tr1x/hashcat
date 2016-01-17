/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _MD5_SHA1_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 0
#define DGST_R1 3
#define DGST_R2 2
#define DGST_R3 1

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

#define COMPUTE_S "OpenCL/m04400s.cl"
#define COMPUTE_M "OpenCL/m04400m.cl"

#define uint_to_hex_lower8(i) l_bin2asc[(i)]

#ifndef IS_APPLE
#include COMPUTE_M
#include COMPUTE_S
#endif

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m04400_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);


  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = pws[gid].i[15];

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

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_M
  #else
  m04400m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset, l_bin2asc);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m04400_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = pws[gid].i[15];

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

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_M
  #else
  m04400m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset, l_bin2asc);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m04400_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

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

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_M
  #else
  m04400m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset, l_bin2asc);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m04400_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = pws[gid].i[15];

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

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_S
  #else
  m04400s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset, l_bin2asc);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m04400_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = pws[gid].i[15];

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

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_S
  #else
  m04400s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset, l_bin2asc);
  #endif
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m04400_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 bfs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

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

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  #ifdef IS_APPLE
  #include COMPUTE_S
  #else
  m04400s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, bfs_cnt, digests_cnt, digests_offset, l_bin2asc);
  #endif
}
