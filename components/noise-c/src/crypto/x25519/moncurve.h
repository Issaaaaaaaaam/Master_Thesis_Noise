#ifndef _MONCURVE_H
#define _MONCURVE_H

#include "share.h"
#include "gfparith.h"

typedef struct projective_point {
  Word x[NWORDS];
  Word y[NWORDS];
  Word z[NWORDS];
} ProPoint;

void mon_ladder_step(ProPoint *p, ProPoint *q, const Word *xd);
void mon_mul_varbase(Word *r, const Word *k, const Word *x);

#endif 
