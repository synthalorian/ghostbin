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
    Arm32,
    Arm64,
    Unknown,
}

impl Architecture {
    pub fn from_elf_machine(machine: u16) -> Self {
        match machine {
            3 => Architecture::X86,      // EM_386
            62 => Architecture::X86_64,  // EM_X86_64
            40 => Architecture::Arm32,   // EM_ARM
            183 => Architecture::Arm64,  // EM_AARCH64
            _ => Architecture::Unknown,
        }
    }

    pub fn from_pe_machine(machine: u16) -> Self {
        match machine {
            0x14c => Architecture::X86,      // IMAGE_FILE_MACHINE_I386
            0x8664 => Architecture::X86_64,  // IMAGE_FILE_MACHINE_AMD64
            0x1c0 => Architecture::Arm32,    // IMAGE_FILE_MACHINE_ARM
            0xaa64 => Architecture::Arm64,   // IMAGE_FILE_MACHINE_ARM64
            _ => Architecture::Unknown,
        }
    }

    pub fn from_macho_cpu(cputype: u32) -> Self {
        match cputype {
            7 => Architecture::X86,      // CPU_TYPE_X86
            0x01000007 => Architecture::X86_64,  // CPU_TYPE_X86_64
            12 => Architecture::Arm32,   // CPU_TYPE_ARM
            0x0100000c => Architecture::Arm64,   // CPU_TYPE_ARM64
            _ => Architecture::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86_64",
            Architecture::Arm32 => "arm32",
            Architecture::Arm64 => "arm64",
            Architecture::Unknown => "unknown",
        }
    }

    /// Auto-detect architecture from raw binary data by examining headers
    pub fn auto_detect(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Architecture::Unknown;
        }

        // Check ELF magic
        if data.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) && data.len() >= 18 {
            let machine = u16::from_le_bytes([data[18], data[19]]);
            return Self::from_elf_machine(machine);
        }

        // Check PE magic (DOS header)
        if data.len() >= 64 && &data[0..2] == b"MZ" {
            // PE header offset is at 0x3C
            let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
            if data.len() >= pe_offset + 24 {
                // Check PE signature
                if &data[pe_offset..pe_offset + 4] == b"PE\x00\x00" {
                    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
                    return Self::from_pe_machine(machine);
                }
            }
        }

        // Check Mach-O magic
        if data.len() >= 4 {
            let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            match magic {
                0xfeedface | 0xfeedfacf => {
                    // Mach-O single arch (big endian)
                    if data.len() >= 8 {
                        let cputype = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                        return Self::from_macho_cpu(cputype);
                    }
                }
                0xcefaedfe | 0xcffaedfe
                    if data.len() >= 8 => {
                        let cputype = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                        return Self::from_macho_cpu(cputype);
                    }
                _ => {}
            }
        }

        Architecture::Unknown
    }
}

pub struct Disassembler {
    cs: Capstone,
    #[allow(dead_code)]
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
            Architecture::Arm32 => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .build()?,
            Architecture::Arm64 => Capstone::new()
                .arm64()
                .build()?,
            Architecture::Unknown => {
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .build()?
            }
        };

        Ok(Disassembler { cs, arch })
    }

    #[allow(dead_code)]
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
