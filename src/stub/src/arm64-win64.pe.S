/* arm64-win64.pe.S -- loader and de-compressor for ar64-winpe
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) Laszlo Molnar
*  Copyright (C) John F. Reiser
*  All Rights Reserved.
*
*  UPX and the UCL library are free software; you can redistribute them
*  and/or modify them under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of
*  the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; see the file COPYING.
*  If not, write to the Free Software Foundation, Inc.,
*  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*
*  Markus F.X.J. Oberhumer              Laszlo Molnar
*  <markus@oberhumer.com>               <ml1050@users.sourceforge.net>
*
*  John F. Reiser
*  <jreiser@users.sourceforge.net>
*/

#include "arch/arm64/v8/macros.S"
VADDR0 .req x28
rADCON .req x27
rax .req x0
  eax .req w0
rbx .req x3
  ebx .req w3
rdx .req x2
  edx .req w2
rcx .req x1
  ecx .req w1
rsp .req sp
rbp .req fp
rsi .req x6
  esi .req w6
rdi .req x7
  edi .req w7
r8  .req x8
r9  .req x9

arg1 .req x0
arg2 .req x1
  arg2w .req w1
arg3 .req x2
  arg3w .req w2
arg4 .req x3

// X86_64:
// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170&viewFallbackFrom=vs-2019#callercallee-saved-registers
// Arguments 1-4: rcx,rdx,r8,r9; push rest on stack, right-to-left
// Volatile:  rax,rcx,rdx,r8,r9,r10,r11  [callee may scribble]
// Non-volatile: rbx,rbp,rdi,rsi,rsp,r12-r15  [callee must preserve]

// ARM64:
// https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=msvc-170#integer-registers
// Register      Volatility       Role
// x0-x8         Volatile         Parameter/Result scratch registers
// x9-x15        Volatile         Scratch registers
// x16-x17       Volatile         Intra-procedure-call scratch registers
// x18            N/A             Reserved platform register: in kernel mode, points to KPCR for the current processor; In user mode, points to TEB
// x19-x28       Non-volatile     Scratch registers
// x29/fp        Non-volatile     Frame pointer
// x30/lr        Both             Link Register: Callee function must preserve it for its own return, but caller's value is lost.

// =============
// ============= ENTRY POINT
// =============

section START
  mov x8,#1; bkpt
                stp fp,lr,[sp,#-2*NBPW]!
                stp rADCON,VADDR0,[sp,#-2*NBPW]!
                bl start2
ADCONS:
                .word ADCONS
original_entry_:.word original_entry
ExitProcess_:   .word ExitProcess
GetProcAddress_:.word GetProcAddress
LoadLibraryA_:  .word LoadLibraryA
VirtualProtect_:.word VirtualProtect

start_of_compressed_:  .word start_of_compressed
start_of_uncompressed_:.word start_of_uncompressed
c_len_: .word c_len
u_len_: .word u_len
//lzma_u_len_:   .word lzma_u_len
//lzma_c_len_:   .word lzma_c_len
icon_offset_:    .word icon_offset
icon_delta_:     .word icon_delta
tls_address_:    .word tls_address
tls_value_:      .word tls_value
//tls_callbacks_ptr_: .word tls_callbacks_ptr
//tls_module_base_:   .word tls_module_base
filter_buffer_start_: .word filter_buffer_start
filter_length_:       .word filter_length
filter_cto_:     .word filter_cto
compressed_imports_:   .word compressed_imports
start_of_imports_:     .word start_of_imports
start_of_relocs_:      .word start_of_relocs
kernel32_ordinals_:    .word kernel32_ordinals
//reloc_delt_:         .word reloc_delt
vp_base_:   .word vp_base
vp_size_:   .word vp_size
swri_:      .word swri

start2:
        ldr eax,[lr]  // rva ADCONS
        mov rADCON,lr
        sub VADDR0,lr,rax

section PEISDLL0
  mov x8,6; bkpt
                stp rcx,rdx,[sp,#0*NBPW]
                stp r8,r9,  [sp,#2*NBPW]
section PEISEFI0
  mov x8,7; bkpt
                stp rdx,rcx,[sp,#-2*NBPW]!  // MATCH_10

section PEISDLL1
  mov x8,8; bkpt
                and rax,rdx,#0xff
                cmp  rax,#1
                bne reloc_end_jmp

section PEMAIN01
                PUSH4(rsi,rdi,rbp,rbx)  // MATCH_12  ABI saved registers
// Arguments to NRV2 de-compressors:
src  .req x0
srcw .req w0
len  .req w1
dst  .req x2
dstw .req w2
                ldr srcw,[rADCON, start_of_compressed_ - ADCONS]
                add src,src,VADDR0
                ldr dstw,[rADCON, start_of_uncompressed_ - ADCONS]
                add dst,src,dstw,sxtw
                ldr len,[rADCON, c_len_ - ADCONS]

section PETLSHAK
  mov x8,13; bkpt
                ldr eax,[rADCON, tls_address_ - ADCONS]
                add rax,rax,rdi
                ldr rcx,[rax]  // TLS index
                ldr edx,[rADCON, tls_value_ - ADCONS]
                str edx,[rax]
                PUSH2(rdx,rcx)  // MATCH_13

section PETLSHAK2               // restore the TLS index
  mov x8,50; bkpt
                POP2(rdi,rax)  // MATCH_13
                str eax,[rdi]

section PEMAIN02
                // empty

//// =============
//// ============= FILTERS
//// =============
//
section PECTTPOS
  mov x8,42; bkpt
//                lea     rdi, [rsi + filter_buffer_start]
section PECTTNUL
  mov x8,43; bkpt
//                mov     rdi, rsi
//
section PEFILTER49
  mov x8,44; bkpt
//                push    rsi
//                mov     rdi, rsi
//                mov     rsi, offset filter_length
//                mov     dl, IMM8(filter_cto)
//.att_syntax
//#include "arch/arm64/v8/bxx.S"
//
//                pop     rsi

//// =============
//// ============= DECOMPRESSION
//// =============
//
section NRV_HEAD
M_NRV2B_LE32=   2
M_NRV2D_LE32=   5
M_NRV2E_LE32=   8
M_LZMA=         14

                PUSH2(dst,xzr)  // MATCH_15  vaddr_of_uncompressed, dlen
                add x3,sp,#NBPW
                bl NRV_go
//FIXME: call unfilter
//FIXME: sync_cache
                b PEMAIN10
NRV_go:  // fall into the one de-compression algorithm

#define NO_METHOD_CHECK 1

section NRV2B
#define NO_SYNC_CACHE  1  /* FIXME: Win11 says all cache control instr ar illegal */
#include "arch/arm64/v8/nrv2b_d32.S"

section NRV2D
  mov x8,47; bkpt
#include "arch/arm64/v8/nrv2d_d32.S"

section NRV2E
  mov x8,48; bkpt
#include "arch/arm64/v8/nrv2e_d32.S"

section LZMA_HEAD
  mov x8,49; bkpt
//
//#include "arch/arm64/v8/lzma_d.S"
//
section LZMA_TAIL
  mov x8,50; bkpt

eofe:

#undef eof
#undef len

section PEICONS1
  mov x8,11; bkpt
                ldr rax,icon_offset
                ldr edx,[rdi,rax]
                add rdx,rdx,#1
                str edx,[rdi,rax]
section PEICONS2
  mov x8,12; bkpt
                //add     [rdi + icon_offset], IMM16(icon_delta)
                ldr rax,icon_offset
                ldr rdx,[rdi,rax]
                ldr rcx,icon_delta
                add rcx,rcx,rdx
                str ecx,[rdi,rax]
//// =============
//// ============= IMPORTS
//// =============
//
// Imports and relocation call WinAPIs; must use WinAPI registers.
// amd64 non-volatile registers: rbx,rbp,rsi,rdi
// arm64 non-volative registers: r19 and above
  .unreq rbp
         rbp .req x20
  .unreq rbx
         rbx .req x21
  .unreq ebx
         ebx .req w21
  .unreq rsi
         rsi .req x22
  .unreq rdi
         rdi .req x23

section PEMAIN10
                POP2(rsi,rcx)  // MATCH_15  vaddr_of_uncompressed, dlen

section PEIMPORT  // In: rsi= vaddr_of_uncompressed
                ldr eax,[rADCON, compressed_imports_ - ADCONS]
                add rdi,rsi,rax
next_dll:
                ldr eax,[rdi,#0]; cbz rax,imports_done
                ldr edx,[rADCON, start_of_imports_ - ADCONS]
                ldr ebx,[rdi,#4]    // iat
                add rdi,rdi,#2*4
                add rax,rax,rdx
                add arg1,rsi,rax
                add rbx,rbx,rsi
//
//  HMODULE LoadLibraryA(
//  [in] LPCSTR lpLibFileName
//  );
                ldr edx,[rADCON, LoadLibraryA_ - ADCONS]
                ldr rdx,[VADDR0, rdx]
                blr rdx
                mov rbp,rax  // rbp= HMODULE;  FIXME: error check?
next_func:
                ldrb eax,[rdi],#1
                cbz eax,next_dll  // FIXME cbnz ?
section PEIBYORD
  mov x8,16; bkpt
                tbz eax,#7,byname  // bit 7 is 0
section PEK32ORD
  mov x8,17; bkpt
                tbz eax,#6,not_kernel32  // FIXME
                ldr eax,[rdi],#4
                ldr edx,[rADCON, kernel32_ordinals_ - ADCONS]
                add eax,eax,edx
                ldr eax,[rsi,rax]
                b next_imp
not_kernel32:

section PEIMORD1
  mov x8,18; bkpt
                ldrh edx,[rdi],#2
                b first_imp
byname:

section PEIMPOR2
                mov arg2,rdi  // current module
next_name:
                ldrb eax,[rdi],#1
                cbnz eax,next_name
first_imp:
                mov arg1,rbp
//  FARPROC GetProcAddress(
//      HMODULE hModule,
//      LPCSTR lpProcName
//  );
                ldr edx,[rADCON, GetProcAddress_ - ADCONS]
                ldr rdx,[VADDR0, rdx]
                blr rdx; cbz rax,imp_failed
next_imp:
                str rax,[rbx],#NBPW
                b next_func
imp_failed:  // fall into error handler

section PEIERDLL
  mov x8,10; bkpt
                POP4(rsi,rdi,rbp,rbx)  // MATCH_12
                mov rax,#0  // FIXME error code?
                ret

section PEIEREXE
  mov x8,21; bkpt
                mov rax,#3  // error code
                ldr rdx,[rADCON, ExitProcess_ - ADCONS]
                ldr rdx,[VADDR0, rdx]
                br  rdx

section PEIMDONE
imports_done:

//// =============
//// ============= RELOCATION
//// =============
//
section PERELOC1
  mov x8,23; bkpt
                ldr edi,[rADCON, start_of_relocs_ - ADCONS]
                add rdi,rdi,VADDR0
section PERELOC2
                add rdi,rdi,#4
section PERELOC3
                add rbx,rsi,#-4
reloc_main:
                ldrb eax,[rdi],#1; cbz eax,reloc_endx
                cmp eax,#0xEF; bhi reloc_fx
reloc_add:
                add rbx,rbx,rax
                ldr rax,[rbx]
                rev rax,rax
                add rax,rax,rsi
                str rax,[rbx]
                b reloc_main
reloc_fx:
                ldrh edx,[rdi],#2
                and eax,eax,#0x0F
                lsl eax,eax,#16
                orr eax,eax,edx

section REL64BIG
  mov x8,26; bkpt
                cbnz eax,reloc_add
                ldr eax,[rdi],#4

section RELOC64J
                b reloc_add
reloc_endx:
// =============

section PEDEPHAK  // DEPHAK means Data Execution Prevention hack
                ldr eax,  [rADCON, VirtualProtect_ - ADCONS]
                ldr arg2w,[rADCON, vp_size_ - ADCONS]  // dwSize: 1 or 2 pages (@4K)
                ldr rbp,[VADDR0, rax] // &VirtualProtect
                mov arg1,VADDR0  // lpAddress
PAGE_READWRITE= 4  // https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
                mov arg3,#PAGE_READWRITE  // flNewProtect
                sub  rsp,rsp,#4*NBPW + 0x10  // ABI save area plus temp space
                add arg4,rsp,#4*NBPW  // lpflOldProtect
//
//  BOOL VirtualProtect(
//    LPVOID lpAddress,
//    SIZE_T dwSize,
//    DWORD flNewProtect,
//    PDWORD lpflOldProtect
//  );
                blr rbp  // VirtualProtect  FIXME: check return value?
// The page that has the pe_section_t is now writeable.

so_pe_section_t= 40  // sizeof(pe_section_t) == 0x28
IMAGE_SCN_MEM_WRITE=(1 << 31)  // in pe_section_t.flags, which is last in pe_section_t
// 'swri' is the page offset of the highest byte in osection[x].flags
                ldr eax,[rADCON, swri_ - ADCONS]
                add rax,rax,VADDR0

                ldrb edx,[rax]  // in UPX0
                ldrb ecx,[rax,#so_pe_section_t]  // in UPX1
                and  edx,edx,#0xff & ~(IMAGE_SCN_MEM_WRITE>>24) // 0x7f
                and  ecx,ecx,#0xff & ~(IMAGE_SCN_MEM_WRITE>>24)
                strb edx,[rax]  // marks UPX0 non-writeable
                strb ecx,[rax,#so_pe_section_t]  // marks UPX0 non-writeable

                mov arg1,VADDR0  // lpAddress
                ldr arg2w,[rADCON, vp_size_ - ADCONS]  // dwSize: 1 or 2 pages (@4K)
                ldr arg3w,[sp,#4*NBPW]  // original protection
                add arg4, rsp,#4*NBPW  // lpflOldProtect
                blr rbp  // VirtualProtect  FIXME: check return value?
// The page that has the pe_section_t is no longer writeable.

                add  rsp,rsp,#4*NBPW + 0x10  // remove ABI save area and temp space

//// =============
//// ============= TLS callback support part 1
//// =============
//
section PETLSC
  mov x8,32; bkpt
//                movb    [rip + PETLSC2], 0xfc   // "cld" instead of "ret"
//                lea     rcx, [rsi + tls_module_base] // module base
//                push    1                       // DLL_PROCESS_ATTACH
//                pop     rdx
//                xor     r8, r8                  // 0 - reserved
//
//                push    rax                     // align stack
//                call    PETLSC2
//                pop     rax
//
//// ============= Cleanup
//
section PEMAIN20
                POP4(rsi,rdi,rbp,rbx)  // MATCH_12

// clear the dirty stack
.macro          clearstack128  tmp_reg
                .local   loop
                add \tmp_reg,rsp,#-128
loop:
                stp xzr,xzr,[sp,#-2*NBPW]!
                cmp rsp,\tmp_reg
                bne loop
                sub rsp,rsp,#-128
.endm

section CLEARSTACK
                clearstack128 rax

section PEMAIN21
reloc_end_jmp:

section PEISDLL9
  mov x8,36; bkpt
//                mov     r8, [rsp + 0x18]
//                mov     rdx, [rsp + 0x10]
//                mov     rcx, [rsp + 8]

section PEISEFI9
  mov x8,37; bkpt
//                pop     rdx
//                pop     rcx
//
section PERETURN
  mov x8,38; bkpt
//                push    1
//                pop     rax
//                ret
section PEDOJUMP
  mov x8,39; bkpt
                ldr eax,[rADCON, original_entry_ - ADCONS]
                add rax,rax,VADDR0
                ldp rADCON,VADDR0,[sp],#2*NBPW
                ldp fp,x30,[sp],#2*NBPW
                br rax
//
//// =============
//// ============= TLS callback support part 2
//// =============
//
//// this is the new TLS callback handler
//// it calls the original callbacks ONLY after the decompression is done
//
section PETLSC2         // TLS_CALLBACK(hModule, reason, reserved)
  mov x8,40; bkpt
//                ret             // this ret gets overwritten with cld by PETLSC
//                push    rsi
//                lea     rsi, [rip + tls_callbacks_ptr]
//walk_tlsc_chain2:
//                lodsq
//                test    rax, rax
//                jz      done_callbacks
//
//                push    rcx
//                push    rdx
//                push    r8
//
//                sub     rsp, 0x28
//                call    rax
//                add     rsp, 0x28
//
//                pop     r8
//                pop     rdx
//                pop     rcx
//
//                jmp     walk_tlsc_chain2
//done_callbacks:
//                pop     rsi
//                ret
//
//
section PEMAIN03
  mov x8,41; bkpt
//


#include        "include/header.S"

// vim:set ts=8 sw=8 et:
