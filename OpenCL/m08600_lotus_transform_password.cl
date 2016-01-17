#ifndef IS_APPLE
static void lotus_transform_password (u32 in[4], u32 out[4], __L u32 s_lotus_magic_table[256])
{
#endif
  u32 t = out[3] >> 24;

  u32 c;

  #pragma unroll 4
  for (int i = 0; i < 4; i++)
  {
    t ^= (in[i] >>  0) & 0xff; c = BOX (s_lotus_magic_table, t); out[i] ^= c <<  0; t = ((out[i] >>  0) & 0xff);
    t ^= (in[i] >>  8) & 0xff; c = BOX (s_lotus_magic_table, t); out[i] ^= c <<  8; t = ((out[i] >>  8) & 0xff);
    t ^= (in[i] >> 16) & 0xff; c = BOX (s_lotus_magic_table, t); out[i] ^= c << 16; t = ((out[i] >> 16) & 0xff);
    t ^= (in[i] >> 24) & 0xff; c = BOX (s_lotus_magic_table, t); out[i] ^= c << 24; t = ((out[i] >> 24) & 0xff);
  }
#ifndef IS_APPLE
}
#endif
