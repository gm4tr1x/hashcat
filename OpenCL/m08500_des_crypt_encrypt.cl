#ifndef IS_APPLE
static void _des_crypt_encrypt (u32 iv[2], u32 data[2], u32 Kc[16], u32 Kd[16], __L u32 s_SPtrans[8][64])
{
  //u32 tt;
  u32 r, l;

#endif

  r = data[0];
  l = data[1];

  #pragma unroll 16
  for (u32 i = 0; i < 16; i += 2)
  {
    u32 u;
    u32 t;

    u = Kc[i + 0] ^ r;
    t = Kd[i + 0] ^ rotl32 (r, 28u);

    l ^= BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | BOX (((t >> 26) & 0x3f), 7, s_SPtrans);

    u = Kc[i + 1] ^ l;
    t = Kd[i + 1] ^ rotl32 (l, 28u);

    r ^= BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | BOX (((t >> 26) & 0x3f), 7, s_SPtrans);
  }

  iv[0] = l;
  iv[1] = r;

#ifndef IS_APPLE
}
#endif