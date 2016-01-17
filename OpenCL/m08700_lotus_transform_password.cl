#ifndef IS_APPLE
static void lotus_transform_password (u32 in[4], u32 out[4], __L u32 s_lotus_magic_table[256])
{
  u32 t, c2;
#endif

  t = out[3] >> 24;

  c2 = 0;

  //#pragma unroll // kernel fails if used
  for (int i = 0; i < 4; i++)
  {
    t ^= (in[i] >>  0) & 0xff; c2 = BOX (s_lotus_magic_table, t); out[i] ^= c2 <<  0; t = ((out[i] >>  0) & 0xff);
    t ^= (in[i] >>  8) & 0xff; c2 = BOX (s_lotus_magic_table, t); out[i] ^= c2 <<  8; t = ((out[i] >>  8) & 0xff);
    t ^= (in[i] >> 16) & 0xff; c2 = BOX (s_lotus_magic_table, t); out[i] ^= c2 << 16; t = ((out[i] >> 16) & 0xff);
    t ^= (in[i] >> 24) & 0xff; c2 = BOX (s_lotus_magic_table, t); out[i] ^= c2 << 24; t = ((out[i] >> 24) & 0xff);
  }
#ifndef IS_APPLE
}
#endif
