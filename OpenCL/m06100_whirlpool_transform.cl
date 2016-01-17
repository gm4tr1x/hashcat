#ifndef IS_APPLE
static void whirlpool_transform (const u32 w[16], u32 dgst[16], __L u32 s_Ch[8][256], __L u32 s_Cl[8][256])
{
#endif
  u32 Kh[8];
  u32 Kl[8];

  Kh[0] = 0x300beec0;
  Kl[0] = 0xaf902967;
  Kh[1] = 0x28282828;
  Kl[1] = 0x28282828;
  Kh[2] = 0x28282828;
  Kl[2] = 0x28282828;
  Kh[3] = 0x28282828;
  Kl[3] = 0x28282828;
  Kh[4] = 0x28282828;
  Kl[4] = 0x28282828;
  Kh[5] = 0x28282828;
  Kl[5] = 0x28282828;
  Kh[6] = 0x28282828;
  Kl[6] = 0x28282828;
  Kh[7] = 0x28282828;
  Kl[7] = 0x28282828;

  u32 stateh[8];
  u32 statel[8];

  stateh[0] = w[ 0];
  statel[0] = w[ 1];
  stateh[1] = w[ 2];
  statel[1] = w[ 3];
  stateh[2] = w[ 4];
  statel[2] = w[ 5];
  stateh[3] = w[ 6];
  statel[3] = w[ 7];
  stateh[4] = w[ 8];
  statel[4] = w[ 9];
  stateh[5] = w[10];
  statel[5] = w[11];
  stateh[6] = w[12];
  statel[6] = w[13];
  stateh[7] = w[14];
  statel[7] = w[15];

  u32 Lh[8];
  u32 Ll[8];

  #pragma unroll
  for (int i = 0; i < 8; i++)
  {
    const u32 Lp0 = stateh[(i + 8) & 7] >> 24;
    const u32 Lp1 = stateh[(i + 7) & 7] >> 16;
    const u32 Lp2 = stateh[(i + 6) & 7] >>  8;
    const u32 Lp3 = stateh[(i + 5) & 7] >>  0;
    const u32 Lp4 = statel[(i + 4) & 7] >> 24;
    const u32 Lp5 = statel[(i + 3) & 7] >> 16;
    const u32 Lp6 = statel[(i + 2) & 7] >>  8;
    const u32 Lp7 = statel[(i + 1) & 7] >>  0;

    Lh[i] = BOX (s_Ch, 0, Lp0 & 0xff)
          ^ BOX (s_Ch, 1, Lp1 & 0xff)
          ^ BOX (s_Ch, 2, Lp2 & 0xff)
          ^ BOX (s_Ch, 3, Lp3 & 0xff)
          ^ BOX (s_Ch, 4, Lp4 & 0xff)
          ^ BOX (s_Ch, 5, Lp5 & 0xff)
          ^ BOX (s_Ch, 6, Lp6 & 0xff)
          ^ BOX (s_Ch, 7, Lp7 & 0xff);

    Ll[i] = BOX (s_Cl, 0, Lp0 & 0xff)
          ^ BOX (s_Cl, 1, Lp1 & 0xff)
          ^ BOX (s_Cl, 2, Lp2 & 0xff)
          ^ BOX (s_Cl, 3, Lp3 & 0xff)
          ^ BOX (s_Cl, 4, Lp4 & 0xff)
          ^ BOX (s_Cl, 5, Lp5 & 0xff)
          ^ BOX (s_Cl, 6, Lp6 & 0xff)
          ^ BOX (s_Cl, 7, Lp7 & 0xff);
  }

  stateh[0] = Lh[0] ^ Kh[0];
  statel[0] = Ll[0] ^ Kl[0];
  stateh[1] = Lh[1] ^ Kh[1];
  statel[1] = Ll[1] ^ Kl[1];
  stateh[2] = Lh[2] ^ Kh[2];
  statel[2] = Ll[2] ^ Kl[2];
  stateh[3] = Lh[3] ^ Kh[3];
  statel[3] = Ll[3] ^ Kl[3];
  stateh[4] = Lh[4] ^ Kh[4];
  statel[4] = Ll[4] ^ Kl[4];
  stateh[5] = Lh[5] ^ Kh[5];
  statel[5] = Ll[5] ^ Kl[5];
  stateh[6] = Lh[6] ^ Kh[6];
  statel[6] = Ll[6] ^ Kl[6];
  stateh[7] = Lh[7] ^ Kh[7];
  statel[7] = Ll[7] ^ Kl[7];

  for (int r = 2; r <= R; r++)
  {
    u32 Lh[8];
    u32 Ll[8];

    #pragma unroll
    for (int i = 0; i < 8; i++)
    {
      const u32 Lp0 = Kh[(i + 8) & 7] >> 24;
      const u32 Lp1 = Kh[(i + 7) & 7] >> 16;
      const u32 Lp2 = Kh[(i + 6) & 7] >>  8;
      const u32 Lp3 = Kh[(i + 5) & 7] >>  0;
      const u32 Lp4 = Kl[(i + 4) & 7] >> 24;
      const u32 Lp5 = Kl[(i + 3) & 7] >> 16;
      const u32 Lp6 = Kl[(i + 2) & 7] >>  8;
      const u32 Lp7 = Kl[(i + 1) & 7] >>  0;

      Lh[i] = BOX (s_Ch, 0, Lp0 & 0xff)
            ^ BOX (s_Ch, 1, Lp1 & 0xff)
            ^ BOX (s_Ch, 2, Lp2 & 0xff)
            ^ BOX (s_Ch, 3, Lp3 & 0xff)
            ^ BOX (s_Ch, 4, Lp4 & 0xff)
            ^ BOX (s_Ch, 5, Lp5 & 0xff)
            ^ BOX (s_Ch, 6, Lp6 & 0xff)
            ^ BOX (s_Ch, 7, Lp7 & 0xff);

      Ll[i] = BOX (s_Cl, 0, Lp0 & 0xff)
            ^ BOX (s_Cl, 1, Lp1 & 0xff)
            ^ BOX (s_Cl, 2, Lp2 & 0xff)
            ^ BOX (s_Cl, 3, Lp3 & 0xff)
            ^ BOX (s_Cl, 4, Lp4 & 0xff)
            ^ BOX (s_Cl, 5, Lp5 & 0xff)
            ^ BOX (s_Cl, 6, Lp6 & 0xff)
            ^ BOX (s_Cl, 7, Lp7 & 0xff);
    }

    Kh[0] = Lh[0] ^ rch[r];
    Kl[0] = Ll[0] ^ rcl[r];
    Kh[1] = Lh[1];
    Kl[1] = Ll[1];
    Kh[2] = Lh[2];
    Kl[2] = Ll[2];
    Kh[3] = Lh[3];
    Kl[3] = Ll[3];
    Kh[4] = Lh[4];
    Kl[4] = Ll[4];
    Kh[5] = Lh[5];
    Kl[5] = Ll[5];
    Kh[6] = Lh[6];
    Kl[6] = Ll[6];
    Kh[7] = Lh[7];
    Kl[7] = Ll[7];

    #pragma unroll 8
    for (int i = 0; i < 8; i++)
    {
      const u32 Lp0 = stateh[(i + 8) & 7] >> 24;
      const u32 Lp1 = stateh[(i + 7) & 7] >> 16;
      const u32 Lp2 = stateh[(i + 6) & 7] >>  8;
      const u32 Lp3 = stateh[(i + 5) & 7] >>  0;
      const u32 Lp4 = statel[(i + 4) & 7] >> 24;
      const u32 Lp5 = statel[(i + 3) & 7] >> 16;
      const u32 Lp6 = statel[(i + 2) & 7] >>  8;
      const u32 Lp7 = statel[(i + 1) & 7] >>  0;

      Lh[i] = BOX (s_Ch, 0, Lp0 & 0xff)
            ^ BOX (s_Ch, 1, Lp1 & 0xff)
            ^ BOX (s_Ch, 2, Lp2 & 0xff)
            ^ BOX (s_Ch, 3, Lp3 & 0xff)
            ^ BOX (s_Ch, 4, Lp4 & 0xff)
            ^ BOX (s_Ch, 5, Lp5 & 0xff)
            ^ BOX (s_Ch, 6, Lp6 & 0xff)
            ^ BOX (s_Ch, 7, Lp7 & 0xff);

      Ll[i] = BOX (s_Cl, 0, Lp0 & 0xff)
            ^ BOX (s_Cl, 1, Lp1 & 0xff)
            ^ BOX (s_Cl, 2, Lp2 & 0xff)
            ^ BOX (s_Cl, 3, Lp3 & 0xff)
            ^ BOX (s_Cl, 4, Lp4 & 0xff)
            ^ BOX (s_Cl, 5, Lp5 & 0xff)
            ^ BOX (s_Cl, 6, Lp6 & 0xff)
            ^ BOX (s_Cl, 7, Lp7 & 0xff);
    }

    stateh[0] = Lh[0] ^ Kh[0];
    statel[0] = Ll[0] ^ Kl[0];
    stateh[1] = Lh[1] ^ Kh[1];
    statel[1] = Ll[1] ^ Kl[1];
    stateh[2] = Lh[2] ^ Kh[2];
    statel[2] = Ll[2] ^ Kl[2];
    stateh[3] = Lh[3] ^ Kh[3];
    statel[3] = Ll[3] ^ Kl[3];
    stateh[4] = Lh[4] ^ Kh[4];
    statel[4] = Ll[4] ^ Kl[4];
    stateh[5] = Lh[5] ^ Kh[5];
    statel[5] = Ll[5] ^ Kl[5];
    stateh[6] = Lh[6] ^ Kh[6];
    statel[6] = Ll[6] ^ Kl[6];
    stateh[7] = Lh[7] ^ Kh[7];
    statel[7] = Ll[7] ^ Kl[7];
  }

  dgst[ 0] = stateh[0] ^ w[ 0];
  dgst[ 1] = statel[0] ^ w[ 1];
  dgst[ 2] = stateh[1] ^ w[ 2];
  dgst[ 3] = statel[1] ^ w[ 3];
  dgst[ 4] = stateh[2] ^ w[ 4];
  dgst[ 5] = statel[2] ^ w[ 5];
  dgst[ 6] = stateh[3] ^ w[ 6];
  dgst[ 7] = statel[3] ^ w[ 7];
  dgst[ 8] = stateh[4] ^ w[ 8];
  dgst[ 9] = statel[4] ^ w[ 9];
  dgst[10] = stateh[5] ^ w[10];
  dgst[11] = statel[5] ^ w[11];
  dgst[12] = stateh[6] ^ w[12];
  dgst[13] = statel[6] ^ w[13];
  dgst[14] = stateh[7] ^ w[14];
  dgst[15] = statel[7] ^ w[15];

#ifndef IS_APPLE
}
#endif