// The MIT License (MIT)
//
// Copyright (c) 2020, National Cybersecurity Agency of France (ANSSI)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Low-level "HAL" for syscalls

use syscall;
use core::arch::asm;

/// Generates a syscall of number `num` with arguments `arg[1-3]`, returning the value returned
/// from the syscall. Will call `syscall::syscall_received` as privileged code to handle this call.
pub unsafe fn syscall(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let res: usize;
    asm!("svc 0",
        lateout("r0") res,            // Output: Result in r0
        in("r0") num,                 // Input: System call number in r0
        in("r1") arg1,                // Input: First argument in r1
        in("r2") arg2,                // Input: Second argument in r2
        in("r3") arg3,                // Input: Third argument in r3
        clobber_abi("C")
    );
    res
}

/// Generates a syscall of number `num` with arguments `arg[1-3]`, returning the value returned
/// from the syscall. Will call `syscall::syscall_received` as privileged code to handle this call.
///
/// In addition to what `syscall` does, `syscall_saveall` also clears all the state stored in
/// registers and regenerates it afterwise, so that data is not leaked through registers.
pub unsafe fn syscall_saveall(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let res: usize;
    asm!(
        // Clear all registers
        "mrs r4, APSR",
        "bic r4, #0xF8000000",
        "msr APSR, r4",
        "mov r4, #0",
        "mov r5, #0",
        "mov r6, #0",
        "mov r7, #0",
        "mov r8, #0",
        "mov r9, #0",
        "mov r10, #0",
        "mov r11, #0",
        "mov r12, #0",

        // Trigger the syscall
        "svc 0",

        // Outputs
        lateout("r0") res,

        // Inputs
        in("r0") num,
        in("r1") arg1,
        in("r2") arg2,
        in("r3") arg3,

        // Clobbered registers
        lateout("r1") _,   // Explicitly mark clobbered registers
        lateout("r2") _,
        lateout("r3") _,
        out("r4") _,
        out("r5") _,
        out("r8") _,
        out("r9") _,
        out("r10") _,
        out("r11") _,
        out("r12") _,

        // Clobber memory and flags
        clobber_abi("C")

    );
    res
}

/// Handler for the `SVC` exception (triggered by `syscall`).
///
/// Calls `syscall::syscall_received` to handle the syscall.
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn SVC_Handler(num: usize, arg1: usize, arg2: usize, arg3: usize) -> () {
    syscall::syscall_received(num, arg1, arg2, arg3);
}
