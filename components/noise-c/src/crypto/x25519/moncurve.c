#include "moncurve.h"


static void mon_cswap_point(ProPoint *p, ProPoint *q, int cbit)
{
  Word mask, tx, tz;
  int i;
  
  cbit &= 1;  
  mask = ~((Word) cbit) + 1;
  
  for (i = 0; i < NWORDS; i++) {
    tx = (p->x[i] ^ q->x[i]) & mask;
    tz = (p->z[i] ^ q->z[i]) & mask;
    p->x[i] ^= tx;
    p->z[i] ^= tz;
    q->x[i] ^= tx;
    q->z[i] ^= tz; 
  }
}

void mon_ladder_step(ProPoint *p, ProPoint *q, const Word *xd)
{
  Word *tmp1 = p->y, *tmp2 = q->y;
  
  gfp_add(tmp1, p->x, p->z);
  gfp_sub(p->x, p->x, p->z);
  gfp_add(tmp2, q->x, q->z);
  gfp_sub(q->x, q->x, q->z);
  gfp_sqr(p->z, tmp1);
  gfp_mul(q->z, tmp2, p->x);
  gfp_mul(tmp2, q->x, tmp1);
  gfp_sqr(tmp1, p->x);
  gfp_mul(p->x, p->z, tmp1);
  gfp_sub(tmp1, p->z, tmp1);
  gfp_mul32(q->x, tmp1, (CONSTA-2)/4);
  gfp_add(q->x, q->x, p->z);
  gfp_mul(p->z, q->x, tmp1);
  gfp_add(tmp1, tmp2, q->z);
  gfp_sqr(q->x, tmp1);
  gfp_sub(tmp1, tmp2, q->z);
  gfp_sqr(tmp2, tmp1);
  gfp_mul(q->z, tmp2, xd);
}

void mon_mul_varbase(Word *r, const Word *k, const Word *x)
{
  ProPoint p1, p2;
  Word kp[NWORDS];
  int i, b, s = 0;
  
  // prune scalar k
  for (i = 0; i < NWORDS; i++) kp[i] = k[i];
  kp[0] &= (~((Word) 7));                        // 0xFFF..FF8 
  kp[NWORDS-1] &= (~(((Word) 1) << (WBITS-1)));  // 0x7FF..FFF
  kp[NWORDS-1] |= (((Word) 1) << (WBITS-2));     // 0x400..000
  
  // initialize ladder
  for (i = 0; i < NWORDS; i++) {
    p1.x[i] = p1.z[i] = p2.z[i] = 0;
    p2.x[i] = x[i];
  }
  p1.x[0] = p2.z[0] = 1;
  
  // main ladder loop
  for (i = 254; i >= 0; i--) {
    b = kp[i>>WPOW2] >> (i & (WBITS-1));
    s = s ^ b;
    mon_cswap_point(&p1, &p2, s);
    mon_ladder_step(&p1, &p2, x);
    s = b;
  }
  
  mon_cswap_point(&p1, &p2, s);
  
  // projective -> affine
  gfp_inv(p2.y, p1.z);
  gfp_mul(r, p2.y, p1.x);
}





void mon_test25519(void)
{
  uint32_t x[8] = {                                 \
    0x6768DBE6, 0xDB303058, 0xA4C19435, 0x7C5FB124, \
    0xEC246672, 0x3B35B326, 0xA603A910, 0x4C1CABD0 };
  uint32_t k[8] = {                                 \
    0x6BE346A0, 0x9D7C52F0, 0x4B15163B, 0xDD5E4682, \
    0x0A4C1462, 0x185AFCC1, 0x44226A50, 0x449A44BA };
  uint32_t r[8];
  
  mon_mul_varbase((Word *) r, (const Word *) k, (const Word *) x);
  mpi_print("r = 0x", r, NWORDS);
  
  // correct result:
  // r = 0x5285A2775507B454F7711C4903CFEC324F088DF24DEA948E90C6E99D3755DAC3
}

