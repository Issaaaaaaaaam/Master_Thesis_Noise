///////////////////////////////////////////////////////////////////////////////
// gfp_mul32_rvm.S: Multiplication by 32-bit Integer Mod a 255-bit PM Prime. //
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
// void gfp_mul32_rvm(uint32_t *r, const uint32_t *a, const uint32_t *b);
//
// Description:
// ------------
// The function `gfp_mul32_rvm` computes the product $r = a \cdot b \bmod p$ of
// two elements $a$ and $b$ of a pseudo-Mersenne prime field, with element $b$
// being up to 32 bits long. The prime $p$ is the 255-bit pseudo-Mersenne prime
// $p = 2^{255} - 19$. Operand $a$ is allowed to be larger than $p$. The result
// $r$ may not be fully reduced, but $r$ is always less than $2p$.
//
// Parameters:
// -----------
// `r`: pointer to array for the eight 32-bit words of the result $r$.
// `a`: pointer to array containing the eight 32-bit words of operand $a$.
// `b`: pointer to the 32-bit word of operand $b$.


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
// Registers `tmp0` to `tmp2` hold intermediate results
#define tmp0 a1
#define tmp1 a2
#define tmp2 a3
// Registers `aw00` to `aw07` hold words of operand `a`
#define aw00 a5
#define aw01 a6
#define aw02 a7
#define aw03 t0
#define aw04 t1
#define aw05 t2
#define aw06 t3
#define aw07 t4
// Registers `rw00` to `rw08` hold words of the product
#define rw00 a4
#define rw01 a5
#define rw02 a6
#define rw03 a7
#define rw04 t0
#define rw05 t1
#define rw06 t2
#define rw07 t3
#define rw08 t4
// Register `bw00` holds the single word of operand `b`
#define bw00 t5


///////////////////////////////////////////////////////////////////////////////
///////////////// MACROS FOR WORD-WISE MULTIPLY-ADD OPERATIONS ////////////////
///////////////////////////////////////////////////////////////////////////////


// The macro `MADD_V1` multiplies the word `aiw` by `bjw` and puts the product
// in the `rhi:rlo` register-pair (i.e., this macro performs a multiply-add
// operation where 0 is added to the product, i.e., a normal multiplication).
// NOTE: Registers `rhi` and `rlo` have to be different from `aiw` and `bjw`.

.macro MADD_V1 rhi:req, rlo:req, aiw:req, bjw:req
    mul     \rlo, \aiw, \bjw
    mulhu   \rhi, \aiw, \bjw
.endm


// The macro `MADD_V2` multiplies the word `aiw` by `bjw` and adds the word
// `c0w` to the product. The double-length result is put in the `rhi:rlo`
// register-pair.
// NOTE: Registers `rhi` and `rlo` have to be different from `aiw` and `bjw`.

.macro MADD_V2 rhi:req, rlo:req, aiw:req, bjw:req, c0w:req
    mul     tmp0, \aiw, \bjw
    mulhu   \rhi, \aiw, \bjw
    add     \rlo, \c0w, tmp0
    sltu    tmp0, \rlo, tmp0
    add     \rhi, \rhi, tmp0
.endm


///////////////////////////////////////////////////////////////////////////////
//////////// MACROS FOR LOW-LEVEL OPERATIONS FOR MODULAR REDUCTION ////////////
///////////////////////////////////////////////////////////////////////////////


// The macro `MULHIXC` first splits the double-length word in `dhi:dlo` into a
// 31-bit lower part and a 33-bit upper part. The lower part is put in `msw`,
// while the upper part is multiplied by the constant $c = 19$ and the double-
// length product is put in `rhi:rlo`.

.macro MULHIXC rhi:req, rlo:req, msw:req, ccw:req, dhi:req, dlo:req
    srli    tmp0, \dlo, 31
    sub     tmp0, zero, tmp0
    and     tmp0, tmp0, \ccw
    slli    \ccw, \ccw, 1
    slli    \msw, \dlo, 1
    mulhu   \rhi, \dhi, \ccw
    mul     \rlo, \dhi, \ccw
    srli    \msw, \msw, 1
    add     \rlo, \rlo, tmp0
    sltu    tmp0, \rlo, tmp0
    add     \rhi, \rhi, tmp0
.endm


// The macro `ADDWORD` adds the double-length word `dhi:dlo` to the 8-word
// operand `rw00`-`rw07`.
// NOTE: the bit-length of `dhi` can be up to 31.

.macro ADDWORD dhi:req, dlo:req
    add     rw00, rw00, \dlo
    sltu    tmp0, rw00, \dlo
    add     tmp0, tmp0, \dhi  // no carry !!!
    add     rw01, rw01, tmp0
    sltu    tmp0, rw01, tmp0
    add     rw02, rw02, tmp0
    sltu    tmp0, rw02, tmp0
    add     rw03, rw03, tmp0
    sltu    tmp0, rw03, tmp0
    add     rw04, rw04, tmp0
    sltu    tmp0, rw04, tmp0
    add     rw05, rw05, tmp0
    sltu    tmp0, rw05, tmp0
    add     rw06, rw06, tmp0
    sltu    tmp0, rw06, tmp0
    add     rw07, rw07, tmp0
.endm


///////////////////////////////////////////////////////////////////////////////
////////// HIGH-LEVEL MACROS FOR MULTIPLICATION AND MODULAR REDUCTION /////////
///////////////////////////////////////////////////////////////////////////////


// The macro `MULROW1` multiplies the 8-word operand `aw00`-`aw07` by a single
// word (held in `bw00`) and puts the 9-word product in `p0w`-`p8w`. This macro
// corresponds to the operation $r = a \cdot b_0$ performed by the very first
// iteration of the outer loop of the operand-scanning method. he word $b_0$
// of the multiplier is loaded to `bw00` via base-address `bptr` and offset 0.

.macro MULROW1
    // lw      bw00, 0(bptr)
    mv      bw00, a2
    MADD_V1 rw01, rw00, aw00, bw00
    MADD_V2 rw02, rw01, aw01, bw00, rw01
    MADD_V2 rw03, rw02, aw02, bw00, rw02
    MADD_V2 rw04, rw03, aw03, bw00, rw03
    MADD_V2 rw05, rw04, aw04, bw00, rw04
    MADD_V2 rw06, rw05, aw05, bw00, rw05
    MADD_V2 rw07, rw06, aw06, bw00, rw06
    MADD_V2 rw08, rw07, aw07, bw00, rw07
.endm


// The macro `MODREDP` reduces the 9-word operand `rw00`-`rw08` modulo the
// prime $p = 2^{256} - 19$ to get an 8-word result. First, the double-length
// word `rw08:rw07` is split into a 31-bit lower part and a 33-bit upper part,
// which is multiplied the constant $c = 19$ (macro `MULHIXC`). The double-
// length product is added to the eight words `rw00`-`rw07` (macro `ADDWORD`).

.macro MODREDP
    li      bw00, CCON  // bw00 = 19
    MULHIXC tmp2, tmp1, rw07, bw00, rw08, rw07
    ADDWORD tmp2, tmp1
.endm


///////////////////////////////////////////////////////////////////////////////
////////// HELPER MACROS FOR OPERAND-SCANNING MODULAR MULTIPLICATION //////////
///////////////////////////////////////////////////////////////////////////////


// The macro `LDM_OPA` loads the eight words of array `a` from RAM and puts
// them in registers `aw00`-`aw07`.

.macro LDM_OPA
    lw      aw00, 0(aptr)
    lw      aw01, 4(aptr)
    lw      aw02, 8(aptr)
    lw      aw03, 12(aptr)
    lw      aw04, 16(aptr)
    lw      aw05, 20(aptr)
    lw      aw06, 24(aptr)
    lw      aw07, 28(aptr)
.endm


// The macro `STM_RES` stores the eight result-words, which are in registers
// `rw00`-`rw07`, to array `r` in RAM.

.macro STM_RES
    sw      rw00, 0(rptr)
    sw      rw01, 4(rptr)
    sw      rw02, 8(rptr)
    sw      rw03, 12(rptr)
    sw      rw04, 16(rptr)
    sw      rw05, 20(rptr)
    sw      rw06, 24(rptr)
    sw      rw07, 28(rptr)
.endm


///////////////////////////////////////////////////////////////////////////////
///////// SPEED-OPTIMIZED PRIME-FIELD MULTIPLICATION (FULLY UNROLLED) /////////
///////////////////////////////////////////////////////////////////////////////


// This implementation of prime-field multiplication is based on the operand-
// scanning method and includes a fast reduction modulo $p = 2^{255} - 19$. It
// is aimed at high speed, which means the loops are fully unrolled. Each word
// of the arrays `a` and `b` is loaded from RAM exactly once, and each word of
// the result-array `r` is stored to RAM exactly once.

.text
.global gfp_mul32_rvm
.type gfp_mul32_rvm,%function
// .balign 8
gfp_mul32_rvm:
    LDM_OPA             // load the eight words of array `a` from RAM
    MULROW1             // row-wise multiplication R = A*b[0]
    MODREDP             // modular reduction: Rlo = (Rlo + Rhi*2*c) mod p
    STM_RES             // store the eight result-words in array `r` in RAM
    ret


.end
