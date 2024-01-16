use unicorn_engine::{
    unicorn_const::{Arch, Mode, Permission, SECOND_SCALE},
    InsnSysX86, RegisterX86, Unicorn,
};

const BASE: u64 = 0x1000;

fn syscall_hook<D>(emu: &mut Unicorn<D>) {
    // Get the system call number from the RAX register
    let syscall_number = emu.reg_read(RegisterX86::RAX).unwrap();
    println!("System call number: {}", syscall_number);

    // Emulate the system call or perform any other actions here
    // For example, we can set the return value to 0
    emu.reg_write(RegisterX86::RAX, 0).unwrap();
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
