#ifndef IS_APPLE
static void mdtransform (u32 mdt_state[4], u32 mdt_checksum[4], u32 mdt_block[4], __L u32 s_lotus_magic_table[256])
{
#endif

  #ifndef IS_APPLE
  mdtransform_norecalc (mdt_state, mdt_block, s_lotus_magic_table);
  #else
  u32 p;
  u32 x[12];
  #define mdtn_state mdt_state
  #define mdtn_block mdt_block
  #include MDTRANSFORM_NORECALC
  #undef mdtn_state
  #undef mdtn_block
  #endif

  #ifndef IS_APPLE
  lotus_transform_password (mdt_block, mdt_checksum, s_lotus_magic_table);
  #else
  #define in mdt_block
  #define out mdt_checksum
  #include LOTUS_TRANSFORM_PASSWORD
  #undef in
  #undef out
  #endif

#ifndef IS_APPLE
}
#endif
