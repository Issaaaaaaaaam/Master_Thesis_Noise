#ifndef _GFPARITH_H
#define _GFPARITH_H

#include "share.h"
#define MPISE_ISA

void gfp_mul_isa(Word *r, const Word *a, const Word *b);
void gfp_sqr_isa(Word *r, const Word *a);
void gfp_add_isa(Word *r, const Word *a, const Word *b);
void gfp_sub_isa(Word *r, const Word *a, const Word *b);
void gfp_mul32_isa(Word *r, const Word *a, uint32_t b);

void gfp_mul_ise(Word *r, const Word *a, const Word *b);
void gfp_sqr_ise(Word *r, const Word *a);
void gfp_add_ise(Word *r, const Word *a, const Word *b);
void gfp_sub_ise(Word *r, const Word *a, const Word *b);
void gfp_mul32_ise(Word *r, const Word *a, uint32_t b);

void gfp_inv(Word *r, const Word *a);

#if   defined( MPISE_ISE )
#define gfp_mul(r, a, b)   gfp_mul_ise((r), (a), (b))
#define gfp_sqr(r, a)      gfp_mul_ise((r), (a), (a))
#define gfp_add(r, a, b)   gfp_add_ise((r), (a), (b))
#define gfp_sub(r, a, b)   gfp_sub_ise((r), (a), (b))
#define gfp_mul32(r, a, b) gfp_mul32_ise((r), (a), (b))
#elif defined( MPISE_ISA )
/*
#define gfp_mul(r, a, b)   gfp_mul_isa((r), (a), (b))
#define gfp_sqr(r, a)      gfp_sqr_isa((r), (a))
#define gfp_add(r, a, b)   gfp_add_isa((r), (a), (b))
#define gfp_sub(r, a, b)   gfp_sub_isa((r), (a), (b))
#define gfp_mul32(r, a, b) gfp_mul32_isa((r), (a), (b))
*/
#define gfp_mul(r, a, b)   gfp_mul_rvm((r), (a), (b))
#define gfp_sqr(r, a)      gfp_sqr_rvm((r), (a))
#define gfp_add(r, a, b)   gfp_add_rvm((r), (a), (b))
#define gfp_sub(r, a, b)   gfp_sub_rvm((r), (a), (b))
#define gfp_mul32(r, a, b) gfp_mul32_rvm((r), (a), (b))
#endif

#endif
