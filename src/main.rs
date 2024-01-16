use unicorn_engine::{
    unicorn_const::{Arch, Mode, Permission, SECOND_SCALE},
    InsnSysX86, RegisterX86, Unicorn,
};

const BASE: u64 = 0x1000;

/*
 * SYSCALL instructions can be found inlined in LibC implementations as
 * well as some other programs and libraries.  There are also a handful
 * of SYSCALL instructions in the vDSO used, for example, as a
 * clock_gettimeofday fallback.
 *
 * 64-bit SYSCALL saves rip to rcx, clears rflags.RF, then saves rflags to r11,
 * then loads new ss, cs, and rip from previously programmed MSRs.
 * rflags gets masked by a value from another MSR (so CLD and CLAC
 * are not needed). SYSCALL does not save anything on the stack
 * and does not change rsp.
 *
 * Registers on entry:
 * rax  system call number
 * rcx  return address
 * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
 * (note: r12-r15, rbp, rbx are callee-preserved in C ABI)
 *
 * Only called from user space.
 *
 * When user can change pt_regs->foo always force IRET. That is because
 * it deals with uncanonical addresses better. SYSRET has trouble
 * with them due to bugs in both AMD and Intel CPUs.
 */
fn syscall_hook<D>(emu: &mut Unicorn<D>) {
    // Get the system call number from the RAX register
    let syscall_number = emu.reg_read(RegisterX86::RAX).unwrap();
    println!("System call number: {}", syscall_number);

    // Emulate the system call or perform any other actions here
    // For example, we can set the return value to 0
    emu.reg_write(RegisterX86::RCX, 0).unwrap();
    // TODO: actually do the syscall
}

fn emulate() {
    // tip: use https://asmjit.com/parser.html -> Output (C-array) for the shellcode
    let code = [
        0x49, 0xC7, 0xC0, 0x08, // mov r8, 8
        0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x39, 0x05, 0x00, 0x00, // mov rax, 1337
        0x0F, 0x05, // syscall
    ];

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64)
        .expect("failed to initialize Unicorn instance");
    emu.mem_map(0x1000, 0x4000, Permission::ALL)
        .expect("failed to map code page");
    emu.mem_write(0x1000, &code)
        .expect("failed to write instructions");
    let end = ((BASE as usize) + code.len()) as u64;
    emu.add_insn_sys_hook(InsnSysX86::SYSCALL, 0x1000, end, syscall_hook)
        .unwrap();
    eprintln!("Added instruction hook");

    emu.emu_start(
        BASE,
        ((BASE as usize) + code.len()) as u64,
        10 * SECOND_SCALE,
        1000,
    )
    .unwrap();
    emu.emu_stop().unwrap();
}

fn main() {
    emulate();
}
