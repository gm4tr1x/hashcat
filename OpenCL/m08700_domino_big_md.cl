#ifndef IS_APPLE
static void domino_big_md (const u32 saved_key[16], const u32 size, u32 state[4], __L u32 s_lotus_magic_table[256])
{
  u32 dbm_checksum[4];
  u32 dbm_block[4];
  u32 curpos;
  u32 idx;
  u32 p;
  u32 x[12];
#endif

  dbm_checksum[0] = 0;
  dbm_checksum[1] = 0;
  dbm_checksum[2] = 0;
  dbm_checksum[3] = 0;

  dbm_block[0] = 0;
  dbm_block[1] = 0;
  dbm_block[2] = 0;
  dbm_block[3] = 0;

  for (curpos = 0, idx = 0; curpos + 16 < size; curpos += 16, idx += 4)
  {
    dbm_block[0] = saved_key[idx + 0];
    dbm_block[1] = saved_key[idx + 1];
    dbm_block[2] = saved_key[idx + 2];
    dbm_block[3] = saved_key[idx + 3];

    #ifndef IS_APPLE
    mdtransform (state, dbm_checksum, dbm_block, s_lotus_magic_table);
    #else
    #define mdt_state state
    #define mdt_checksum dbm_checksum
    #define mdt_block dbm_block
    #include MDTRANSFORM
    #undef mdt_state
    #undef mdt_checksum
    #undef mdt_block
    #endif
  }

  dbm_block[0] = saved_key[idx + 0];
  dbm_block[1] = saved_key[idx + 1];
  dbm_block[2] = saved_key[idx + 2];
  dbm_block[3] = saved_key[idx + 3];

  #ifndef IS_APPLE
  mdtransform (state, dbm_checksum, dbm_block, s_lotus_magic_table);
  #else
  #define mdt_state state
  #define mdt_checksum dbm_checksum
  #define mdt_block dbm_block
  #include MDTRANSFORM
  #undef mdt_state
  #undef mdt_checksum
  #undef mdt_block
  #endif

  #ifndef IS_APPLE
  mdtransform_norecalc (state, dbm_checksum, s_lotus_magic_table);
  #else
  #define mdtn_state state
  #define mdtn_block dbm_checksum
  #include MDTRANSFORM_NORECALC
  #undef mdtn_state
  #undef mdtn_block
  #endif

#ifndef IS_APPLE
}
#endif
