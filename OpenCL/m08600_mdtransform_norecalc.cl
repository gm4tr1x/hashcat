#ifndef IS_APPLE
static void mdtransform_norecalc (u32 mdtn_state[4], u32 mdtn_block[4], __L u32 s_lotus_magic_table[256])
{
  u32 x[12];
#endif

  x[ 0] = mdtn_state[0];
  x[ 1] = mdtn_state[1];
  x[ 2] = mdtn_state[2];
  x[ 3] = mdtn_state[3];
  x[ 4] = mdtn_block[0];
  x[ 5] = mdtn_block[1];
  x[ 6] = mdtn_block[2];
  x[ 7] = mdtn_block[3];
  x[ 8] = mdtn_state[0] ^ mdtn_block[0];
  x[ 9] = mdtn_state[1] ^ mdtn_block[1];
  x[10] = mdtn_state[2] ^ mdtn_block[2];
  x[11] = mdtn_state[3] ^ mdtn_block[3];

  #ifndef IS_APPLE
  lotus_mix (x, s_lotus_magic_table);
  #else
  #define in x
  #include LOTUS_MIX
  #undef in
  #endif

  mdtn_state[0] = x[0];
  mdtn_state[1] = x[1];
  mdtn_state[2] = x[2];
  mdtn_state[3] = x[3];

#ifndef IS_APPLE
}
#endif
