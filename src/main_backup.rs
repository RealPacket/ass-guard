use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use unicorn_engine::Unicorn;
use unicorn_engine::{InsnSysX86, RegisterX86};

fn syscall_hook<D>(emu: &mut Unicorn<D>) {
    // Get the system call number from the RAX register
    let syscall_number = emu.reg_read(RegisterX86::RAX).unwrap();
    println!("System call number: {}", syscall_number);

    // Emulate the system call or perform any other actions here
    // For example, we can set the return value to 0
    emu.reg_write(RegisterX86::RAX, 0).unwrap();
    // TODO: actually do the syscall
}

const BASE: u64 = 0x1000;

fn emulate() {
    // Write some code that contains a syscall instruction
    // This code simply calls the write system call with some arguments
    let code: Vec<u8> = vec![
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov    rax,0x1
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov    rdi,0x1
        0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00, // lea    rsi,[rip+0xa]
        0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00, // mov    rdx,0x5
        0x0f, 0x05, //                               syscall
        0xc3, //                                     ret
        0x48, 0x65, 0x6c, 0x6c, 0x6f, //             "Hello"
    ];
    let end = ((BASE as usize) + code.len()) as u64;
    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64)
        .expect("failed to initialize Unicorn instance");
    emu.add_insn_sys_hook(InsnSysX86::SYSCALL, 0x1000, end, syscall_hook)
        .unwrap();
    eprintln!("Added instruction hook");
    emu.mem_map(0x1000, 0x4000, Permission::ALL)
        .expect("failed to map code page");
    eprintln!("Mapped code page!");
    emu.mem_write(0x1000, &code)
        .expect("failed to write instructions");
    eprintln!("Wrote instructions");
    emu.reg_write(RegisterX86::RBP, BASE).unwrap();
    emu.reg_write(RegisterX86::EIP, BASE).unwrap();
    emu.emu_start(BASE, end, 10 * SECOND_SCALE, 1000).unwrap();
    emu.emu_stop().unwrap();
}

// fn main() {
//     emulate();
// }
