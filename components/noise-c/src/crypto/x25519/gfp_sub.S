///////////////////////////////////////////////////////////////////////////////
// gfp_sub_rvm.S: Subtraction Modulo a 255-bit Pseudo-Mersenne Prime.        //
// This file is part of Micro25519, a lightweight implementation of X25519   //
// key exchange and Ed25519 signatures for 8/16/32-bit microcontrollers.     //
// Version 1.0.0 (13-09-24), see <http://github.com/johgrolux/> for updates. //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Author: Johann Groszschaedl (in personal capacity).                       //
// ------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify it   //
// under the terms of the GNU General Public License as published by the     //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This program is distributed in the hope that   //
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied     //
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  //
// GNU General Public License for more details. You should have received a   //
// copy of the GNU General Public License along with this program. If not,   //
// see <http://www.gnu.org/licenses/>.                                       //
///////////////////////////////////////////////////////////////////////////////


// Function prototype:
// -------------------
// void gfp_sub_rvm(uint32_t *r, const uint32_t *a, const uint32_t *b);
//
// Description:
// ------------
// The function `gfp_sub_rvm` computes the difference $r = a - b \bmod p$ of
// two elements $a$ and $b$ of a pseudo-Mersenne prime field. The prime $p$ is
// the 255-bit pseudo-Mersenne prime $p = 2^{255} - 19$. Operands $a$ and $b$
// are allowed to be larger than $p$. The result $r$ may not be fully reduced,
// but $r$ is always less than $2p$.
//
// Parameters:
// -----------
// `r`: pointer to array for the eight 32-bit words of the result $r$.
// `a`: pointer to array containing the eight 32-bit words of operand $a$.
// `b`: pointer to array containing the eight 32-bit words of operand $b$.


///////////////////////////////////////////////////////////////////////////////
//////////////////////// REGISTER NAMES AND CONSTANTS /////////////////////////
///////////////////////////////////////////////////////////////////////////////


// Constant c of the pseudo-Mersenne prime: p = 2^k - c
.equ CCON, 19

// Register `rptr` holds the start address of array `r`
#define rptr a0
// Register `aptr` holds the start address of array `a`
#define aptr a1
// Register `bptr` holds the start address of array `b`
#define bptr a2
// Registers `tmp0` and `tmp1` hold intermediate results
#define tmp0 a3
#define tmp1 a4
// Registers `sumw` and `cryw` hold sum and carry words
#define sumw a5
#define cryw a6
// Register `rmsw` holds the most-significant result-word
#define rmsw a7


///////////////////////////////////////////////////////////////////////////////
///////////////// MACROS FOR WORD-WISE SUBTRACTION OPERATIONS /////////////////
///////////////////////////////////////////////////////////////////////////////


// The macro `SUBW_V1` loads the words `a[i]` and `b[i]` from RAM, adds the
// former to an incoming carry in `cin` (which is non-negative), and subtracts
// `b[i]` as well as the constant $4c$ from the sum. The double-length result
// is put in the `shi:slo` register-pair. This result can be negative, whereby
// the upper word of the result (in `shi`) is always in the range $[-2, 1]$.
// The lower word of the result is stored in `r[i]` in RAM.
// NOTE: Register `slo` has to be different from `cin`.

.macro SUBW_V1 shi:req, slo:req, ccw:req, cin:req, i:req
    slli    \ccw, \ccw, 2
    sltu    tmp0, \cin, \ccw
    sub     \shi, \cin, \ccw
    lw      \slo, \i(aptr)
    lw      tmp1, \i(bptr)
    add     \slo, \slo, \shi
    sltu    \shi, \slo, \shi
    sub     \shi, \shi, tmp0
    sltu    tmp0, \slo, tmp1
    sub     \slo, \slo, tmp1
    sub     \shi, \shi, tmp0
    sw      \slo, \i(rptr)
.endm


// The macro `SUBW_V2` loads the words `a[i]` and `b[i]` from RAM, adds the
// former to an incoming carry in `cin` (which is signed and can be negative),
// and subtracts `b[i]` from the sum. The double-length result is put in the
// `shi:slo` register-pair. This result can be negative, whereby the upper word
// of the result (in `shi`) is always in the range $[-2, 1]$. The lower word of
// the result is stored in `r[i]` in RAM.

.macro SUBW_V2 shi:req, slo:req, cin:req, i:req
    lw      tmp0, \i(aptr)
    lw      tmp1, \i(bptr)
    srai    \shi, \cin, 1
    add     \slo, \cin, tmp0
    sltu    tmp0, \slo, tmp0
    add     \shi, \shi, tmp0
    sltu    tmp0, \slo, tmp1
    sub     tmp1, \slo, tmp1
    sub     \shi, \shi, tmp0
    sw      tmp1, \i(rptr)
.endm


// The macro `SUBW_V3` loads the words `a[i]` and `b[i]` from RAM, adds the
// former to 0x1FFFFFFFC, and subtracts the latter from the sum. The double-
// length result put in the `shi:slo` register-pair. This result is always
// positive, whereby the upper word of the result (in `shi`) is in the range
// [0, 2].

.macro SUBW_V3 shi:req, slo:req, i:req
    lw      tmp0, \i(aptr)
    lw      tmp1, \i(bptr)
    addi    \slo, tmp0, -4
    sltu    tmp0, \slo, tmp0
    addi    \shi, tmp0, 1
    sltu    tmp0, \slo, tmp1
    sub     \slo, \slo, tmp1
    sub     \shi, \shi, tmp0
.endm


// The macro `SUBW_V4` adds the word `cin` along with 4 to `sum` and stores the
// result in `r[i]` in RAM.
// NOTE: the bit-length of `sum` and `cin` can be up to 31.

.macro SUBW_V4 sum:req, cin:req, i:req
    add     \sum, \sum, \cin
    addi    \sum, \sum, 4
    sw      \sum, \i(rptr)
.endm


// The macro `MULHIXC` first splits the double-length word in `dhi:dlo` into a
// 31-bit lower part and an upper part. The lower part is put in `rlo`, while
// the upper part is multiplied by the constant $c = 19$ and the single-word
// product is put in `rhi`.
// NOTE: the bit-length of `dhi` can be up to $32 - \log_2(c) - 1$, e.g., for
// $c = 19$, `dhi` can be up to 26 bits long.

.macro MULHIXC rhi:req, rlo:req, ccw:req, dhi:req, dlo:req
    srli    tmp0, \dlo, 31
    slli    \rhi, \dhi, 1
    add     \rhi, \rhi, tmp0
    slli    \rlo, \dlo, 1
    mul     \rhi, \rhi, \ccw
    srli    \rlo, \rlo, 1
 .endm


///////////////////////////////////////////////////////////////////////////////
/////////// SPEED-OPTIMIZED PRIME-FIELD SUBTRACTION (FULLY UNROLLED) //////////
///////////////////////////////////////////////////////////////////////////////


// This implementation of prime-field subtraction tightly integrates a normal
// subtraction $a - b$ with a fast reduction modulo $p = 2^{255} - 19$. It aims
// for high performance, which means the loop is fully unrolled. Each word of
// the arrays `a` and `b` is loaded from RAM exactly once, and each word of
// the result-array `r` is stored to RAM exactly once.

.text
.global gfp_sub_rvm
.type gfp_sub_rvm,%function
// .balign 8
gfp_sub_rvm:
    SUBW_V3 cryw, sumw, 28
    li      tmp1, CCON  // tmp1 = 19
    MULHIXC cryw, rmsw, tmp1, cryw, sumw
    SUBW_V1 cryw, sumw, tmp1, cryw, 0
    SUBW_V2 cryw, sumw, cryw, 4
    SUBW_V2 cryw, sumw, cryw, 8
    SUBW_V2 cryw, sumw, cryw, 12
    SUBW_V2 cryw, sumw, cryw, 16
    SUBW_V2 cryw, sumw, cryw, 20
    SUBW_V2 cryw, sumw, cryw, 24
    SUBW_V4 rmsw, cryw, 28
    ret


.end
