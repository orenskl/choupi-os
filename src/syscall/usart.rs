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

//! Module for syscalls handling IO via the USART

use crate::syscall::{syscall, Syscall};
use crate::{context, usart_ll};

/// Write data to the USART
pub fn output(msg: &str) {
    unsafe {
        syscall(
            Syscall::UsartOutput,
            msg.as_ptr() as usize,
            msg.bytes().len(),
            0,
        );
    }
}

/// Actually performs the `UsartOutput` syscall
pub fn syscall_output(ptr: usize, len: usize, _: usize) -> Option<usize> {
    assert!(context::is_readable_from_current_context(ptr, len));
    unsafe {
        usart_ll::write_buf(ptr as *const u8, len);
        Some(0)
    }
}

/// Write data to the USART without syscall from privileged mode
pub fn privileged_output(msg: &str) {
    unsafe {
        usart_ll::write_buf(msg.as_ptr(), msg.bytes().len());
    }
}
