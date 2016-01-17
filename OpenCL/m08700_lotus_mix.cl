#ifndef IS_APPLE
static void lotus_mix (u32 *in, __L u32 s_lotus_magic_table[256])
{
  u32 p;
#endif

  p = 0;

  for (int i = 0; i < 18; i++)
  {
    u32 s = 48;

    #pragma unroll
    for (int j = 0; j < 12; j++)
    {
      u32 tmp_in = in[j];
      u32 tmp_out = 0;

      p = (p + s--) & 0xff; p = ((tmp_in >>  0) & 0xff) ^ BOX (s_lotus_magic_table, p); tmp_out |= p <<  0;
      p = (p + s--) & 0xff; p = ((tmp_in >>  8) & 0xff) ^ BOX (s_lotus_magic_table, p); tmp_out |= p <<  8;
      p = (p + s--) & 0xff; p = ((tmp_in >> 16) & 0xff) ^ BOX (s_lotus_magic_table, p); tmp_out |= p << 16;
      p = (p + s--) & 0xff; p = ((tmp_in >> 24) & 0xff) ^ BOX (s_lotus_magic_table, p); tmp_out |= p << 24;

      in[j] = tmp_out;
    }
  }
#ifndef IS_APPLE
}
#endif
