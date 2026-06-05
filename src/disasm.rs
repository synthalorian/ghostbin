use capstone::prelude::*;

#[derive(Debug, Clone)]
pub struct DisasmInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm64,
    Unknown,
}

impl Architecture {
    pub fn from_elf_machine(machine: u16) -> Self {
        match machine {
            3 => Architecture::X86,      // EM_386
            62 => Architecture::X86_64,  // EM_X86_64
            183 => Architecture::Arm64,  // EM_AARCH64
            _ => Architecture::Unknown,
        }
    }

    pub fn from_pe_machine(machine: u16) -> Self {
        match machine {
            0x14c => Architecture::X86,      // IMAGE_FILE_MACHINE_I386
            0x8664 => Architecture::X86_64,  // IMAGE_FILE_MACHINE_AMD64
            0xaa64 => Architecture::Arm64,   // IMAGE_FILE_MACHINE_ARM64
            _ => Architecture::Unknown,
        }
    }

    pub fn from_macho_cpu(cputype: u32) -> Self {
        match cputype {
            7 => Architecture::X86,      // CPU_TYPE_X86
            0x01000007 => Architecture::X86_64,  // CPU_TYPE_X86_64
            0x0100000c => Architecture::Arm64,   // CPU_TYPE_ARM64
            _ => Architecture::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86_64",
            Architecture::Arm64 => "arm64",
            Architecture::Unknown => "unknown",
        }
    }
}

pub struct Disassembler {
    cs: Capstone,
    arch: Architecture,
}

impl Disassembler {
    pub fn new(arch: Architecture) -> anyhow::Result<Self> {
        let cs = match arch {
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .build()?,
            Architecture::X86 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .build()?,
            Architecture::Arm64 => Capstone::new()
                .arm64()
                .build()?,
            Architecture::Unknown => {
                // Default to x86_64
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .build()?
            }
        };

        Ok(Disassembler { cs, arch })
    }

    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    pub fn disassemble(&self, code: &[u8], address: u64) -> anyhow::Result<Vec<DisasmInstruction>> {
        let instructions = self.cs.disasm_all(code, address)?;

        let mut result = Vec::new();
        for insn in instructions.iter() {
            result.push(DisasmInstruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("???").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
            });
        }

        Ok(result)
    }
}
