use goblin::Object;
use serde::Serialize;
use std::collections::HashMap;

use crate::decompiler::Decompiler;
use crate::disasm::{Architecture, Disassembler, DisasmInstruction};
use crate::graph::layout_graph;
use petgraph::graph::DiGraph;

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub offset: u64,
    pub flags: u64,
    pub section_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: String,
    pub bind: String,
    pub section_index: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Relocation {
    pub offset: u64,
    pub symbol: String,
    pub reloc_type: u32,
    pub addend: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Function {
    pub address: u64,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Import {
    pub dll: String,
    pub name: String,
    pub ordinal: Option<u16>,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Export {
    pub name: String,
    pub address: u64,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resource {
    pub resource_type: String,
    pub name: String,
    pub id: u32,
    pub size: u32,
    pub rva: u32,
    pub language: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone)]
pub enum BinaryFormat {
    Elf,
    MachO,
    Pe,
    Raw,
}

#[derive(Debug, Clone)]
pub struct Binary {
    pub id: String,
    pub name: String,
    pub data: Vec<u8>,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub functions: Vec<Function>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub resources: Vec<Resource>,
}

pub struct BinaryAnalyzer {
    binaries: HashMap<String, Binary>,
}

impl BinaryAnalyzer {
    pub fn new() -> Self {
        BinaryAnalyzer {
            binaries: HashMap::new(),
        }
    }

    pub async fn load(&mut self, path: &str) -> anyhow::Result<String> {
        let data = tokio::fs::read(path).await?;
        let id = format!("bin_{}", self.binaries.len());

        let mut binary = Binary {
            id: id.clone(),
            name: path.to_string(),
            data,
            format: BinaryFormat::Raw,
            architecture: Architecture::Unknown,
            entry_point: 0,
            sections: Vec::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            functions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            resources: Vec::new(),
        };

        // Parse the object format first (clone data to avoid borrow issues)
        let data_clone = binary.data.clone();
        let object = Object::parse(&data_clone)?;
        
        match object {
            Object::Elf(elf) => {
                binary.format = BinaryFormat::Elf;
                binary.architecture = Architecture::from_elf_machine(elf.header.e_machine);
                binary.entry_point = elf.entry;

                // Parse sections
                for sh in &elf.section_headers {
                    let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                    binary.sections.push(Section {
                        name,
                        address: sh.sh_addr,
                        size: sh.sh_size,
                        offset: sh.sh_offset,
                        flags: sh.sh_flags,
                        section_type: format!("0x{:x}", sh.sh_type),
                    });
                }

                // Parse symbols (both static and dynamic)
                for sym in elf.syms.iter() {
                    if sym.st_name == 0 {
                        continue;
                    }
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        let sym_type = match sym.st_type() {
                            0 => "NOTYPE",
                            1 => "OBJECT",
                            2 => "FUNC",
                            3 => "SECTION",
                            4 => "FILE",
                            5 => "COMMON",
                            6 => "TLS",
                            _ => "UNKNOWN",
                        };
                        let bind = match sym.st_bind() {
                            0 => "LOCAL",
                            1 => "GLOBAL",
                            2 => "WEAK",
                            _ => "UNKNOWN",
                        };
                        binary.symbols.push(Symbol {
                            name: name.to_string(),
                            address: sym.st_value,
                            size: sym.st_size,
                            symbol_type: sym_type.to_string(),
                            bind: bind.to_string(),
                            section_index: sym.st_shndx as u16,
                        });

                        // Collect functions from symbol table
                        if sym.st_type() == 2 && sym.st_value != 0 {
                            // STT_FUNC
                            binary.functions.push(Function {
                                address: sym.st_value,
                                name: name.to_string(),
                                size: sym.st_size,
                            });
                        }
                    }
                }

                // Parse dynamic symbols
                for sym in elf.dynsyms.iter() {
                    if sym.st_name == 0 {
                        continue;
                    }
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        // Avoid duplicates
                        if !binary.symbols.iter().any(|s| s.name == name && s.address == sym.st_value) {
                            let sym_type = match sym.st_type() {
                                0 => "NOTYPE",
                                1 => "OBJECT",
                                2 => "FUNC",
                                _ => "UNKNOWN",
                            };
                            let bind = match sym.st_bind() {
                                0 => "LOCAL",
                                1 => "GLOBAL",
                                2 => "WEAK",
                                _ => "UNKNOWN",
                            };
                            binary.symbols.push(Symbol {
                                name: name.to_string(),
                                address: sym.st_value,
                                size: sym.st_size,
                                symbol_type: sym_type.to_string(),
                                bind: bind.to_string(),
                                section_index: sym.st_shndx as u16,
                            });

                            if sym.st_type() == 2 && sym.st_value != 0 {
                                if !binary.functions.iter().any(|f| f.address == sym.st_value) {
                                    binary.functions.push(Function {
                                        address: sym.st_value,
                                        name: name.to_string(),
                                        size: sym.st_size,
                                    });
                                }
                            }
                        }
                    }
                }

                // Parse relocations
                // Dynamic relocations with addend
                for reloc in elf.dynrelas.iter() {
                    let sym_name = if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                        elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string()
                    } else {
                        String::new()
                    };
                    binary.relocations.push(Relocation {
                        offset: reloc.r_offset,
                        symbol: sym_name,
                        reloc_type: reloc.r_type,
                        addend: reloc.r_addend.unwrap_or(0),
                    });
                }

                // Dynamic relocations without addend
                for reloc in elf.dynrels.iter() {
                    let sym_name = if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                        elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string()
                    } else {
                        String::new()
                    };
                    binary.relocations.push(Relocation {
                        offset: reloc.r_offset,
                        symbol: sym_name,
                        reloc_type: reloc.r_type,
                        addend: 0,
                    });
                }

                // PLT relocations
                for reloc in elf.pltrelocs.iter() {
                    let sym_name = if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                        elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string()
                    } else {
                        String::new()
                    };
                    binary.relocations.push(Relocation {
                        offset: reloc.r_offset,
                        symbol: sym_name,
                        reloc_type: reloc.r_type,
                        addend: reloc.r_addend.unwrap_or(0),
                    });
                }

                // Section relocations (for relocatable objects)
                for (_shdr_idx, reloc_section) in &elf.shdr_relocs {
                    for reloc in reloc_section.iter() {
                        let sym_name = if let Some(sym) = elf.syms.get(reloc.r_sym) {
                            elf.strtab.get_at(sym.st_name).unwrap_or("").to_string()
                        } else {
                            String::new()
                        };
                        binary.relocations.push(Relocation {
                            offset: reloc.r_offset,
                            symbol: sym_name,
                            reloc_type: reloc.r_type,
                            addend: reloc.r_addend.unwrap_or(0),
                        });
                    }
                }

                // If no functions found from symbols, try function boundary detection
                if binary.functions.is_empty() {
                    binary.functions = Self::detect_elf_function_boundaries(&binary.data, &elf, binary.architecture);
                }
            }
            Object::Mach(mach) => {
                binary.format = BinaryFormat::MachO;
                Self::parse_mach_o(&mut binary, mach)?;
            }
            Object::PE(pe) => {
                binary.format = BinaryFormat::Pe;
                Self::parse_pe(&mut binary, pe)?;
            }
            _ => {
                binary.functions.push(Function {
                    address: 0x1000,
                    name: "entry".to_string(),
                    size: 0,
                });
            }
        }

        // Sort functions by address
        binary.functions.sort_by_key(|f| f.address);

        self.binaries.insert(id.clone(), binary);
        Ok(id)
    }

    fn parse_mach_o(binary: &mut Binary, mach: goblin::mach::Mach) -> anyhow::Result<()> {
        match mach {
            goblin::mach::Mach::Binary(macho) => {
                binary.architecture = Architecture::from_macho_cpu(macho.header.cputype);
                binary.entry_point = macho.entry;

                // Parse segments and sections
                for segment in &macho.segments {
                    let seg_name = segment.name().unwrap_or("").to_string();
                    
                    // Add segment as a section-like entry
                    binary.sections.push(Section {
                        name: seg_name.clone(),
                        address: segment.vmaddr,
                        size: segment.vmsize,
                        offset: segment.fileoff as u64,
                        flags: segment.maxprot as u64,
                        section_type: "segment".to_string(),
                    });

                    // Parse sections within segment
                    for section_result in segment.into_iter() {
                        if let Ok((section, _data)) = section_result {
                            let sect_name = section.name().unwrap_or("").to_string();
                            binary.sections.push(Section {
                                name: format!("{}/{}", sect_name, seg_name),
                                address: section.addr,
                                size: section.size,
                                offset: section.offset as u64,
                                flags: section.flags as u64,
                                section_type: format!("0x{:x}", section.flags),
                            });
                        }
                    }
                }

                // Parse symbols
                for sym_result in macho.symbols() {
                    let (name, nlist) = sym_result?;
                    let name = name.to_string();
                    let addr = nlist.n_value;
                    
                    // Determine symbol type from n_type
                    let n_type = nlist.n_type;
                    let sym_type = if n_type & goblin::mach::symbols::N_TYPE == goblin::mach::symbols::N_SECT {
                        "SECT"
                    } else if n_type & goblin::mach::symbols::N_TYPE == goblin::mach::symbols::N_ABS {
                        "ABS"
                    } else if n_type & goblin::mach::symbols::N_TYPE == goblin::mach::symbols::N_UNDF {
                        "UNDF"
                    } else {
                        "UNKNOWN"
                    };

                    let bind = if n_type & goblin::mach::symbols::N_EXT != 0 {
                        "EXT"
                    } else {
                        "LOCAL"
                    };

                    binary.symbols.push(Symbol {
                        name: name.clone(),
                        address: addr,
                        size: 0, // Mach-O doesn't store symbol sizes directly
                        symbol_type: sym_type.to_string(),
                        bind: bind.to_string(),
                        section_index: nlist.n_sect as u16,
                    });

                    // Check if this is a function symbol
                    // In Mach-O, function symbols are typically in __text section
                    if n_type & goblin::mach::symbols::N_TYPE == goblin::mach::symbols::N_SECT
                        && addr != 0
                        && nlist.n_sect > 0
                    {
                        // Check if it's in a text section
                        let is_text = binary.sections.iter().any(|s| {
                            s.name.contains("__text") && s.address <= addr && addr < s.address + s.size
                        });
                        
                        if is_text || name.starts_with('_') {
                            if !binary.functions.iter().any(|f| f.address == addr) {
                                binary.functions.push(Function {
                                    address: addr,
                                    name: name.clone(),
                                    size: 0,
                                });
                            }
                        }
                    }
                }

                // Function boundary detection for Mach-O
                if binary.functions.is_empty() {
                    binary.functions = Self::detect_macho_function_boundaries(binary);
                }
            }
            goblin::mach::Mach::Fat(multi) => {
                // Try to parse the first architecture
                match multi.get(0) {
                    Ok(goblin::mach::SingleArch::MachO(macho)) => {
                        return Self::parse_mach_o(binary, goblin::mach::Mach::Binary(macho));
                    }
                    Ok(_) => anyhow::bail!("Fat Mach-O contains non-MachO archive"),
                    Err(e) => anyhow::bail!("Failed to parse fat Mach-O binary: {}", e),
                }
            }
        }

        Ok(())
    }

    fn parse_pe(binary: &mut Binary, pe: goblin::pe::PE) -> anyhow::Result<()> {
        binary.architecture = Architecture::from_pe_machine(pe.header.coff_header.machine);
        binary.entry_point = pe.entry as u64;

        // Parse sections
        for section in &pe.sections {
            let name = std::str::from_utf8(&section.name)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            
            binary.sections.push(Section {
                name,
                address: section.virtual_address as u64,
                size: section.virtual_size as u64,
                offset: section.pointer_to_raw_data as u64,
                flags: section.characteristics as u64,
                section_type: format!("0x{:x}", section.characteristics),
            });
        }

        // Parse imports
        for import in &pe.imports {
            let dll = import.dll.to_string();
            let ordinal = if import.name.is_empty() {
                Some(import.ordinal)
            } else {
                None
            };
            
            binary.imports.push(Import {
                dll,
                name: import.name.to_string(),
                ordinal,
                address: import.offset as u64,
            });
        }

        // Parse exports
        let ordinal_base = pe.export_data.as_ref().map(|ed| ed.export_directory_table.ordinal_base).unwrap_or(1);
        for (i, export) in pe.exports.iter().enumerate() {
            let name = export.name.unwrap_or("").to_string();
            let ordinal = ordinal_base + i as u32;
            
            binary.exports.push(Export {
                name: name.clone(),
                address: export.rva as u64,
                ordinal,
            });

            // Export points could be functions - add them
            if export.rva != 0 && !name.is_empty() && !binary.functions.iter().any(|f| f.address == export.rva as u64) {
                binary.functions.push(Function {
                    address: export.rva as u64,
                    name,
                    size: 0,
                });
            }
        }

        if let Some(resource_data) = pe.resource_data {
            binary.resources = Self::parse_pe_resources(&resource_data, &binary.data, &pe.sections, pe.header.coff_header.machine);
        }

        // Function boundary detection for PE
        if binary.functions.is_empty() {
            binary.functions = Self::detect_pe_function_boundaries(binary);
        }

        Ok(())
    }

    fn parse_pe_resources(
        resource_data: &goblin::pe::resource::ResourceData,
        _data: &[u8],
        _sections: &[goblin::pe::section_table::SectionTable],
        _machine: u16,
    ) -> Vec<Resource> {
        let mut resources = Vec::new();

        for entry in resource_data.entries() {
            if let Ok(entry) = entry {
                let resource_type = if entry.name_is_string() {
                    "named".to_string()
                } else {
                    match entry.id() {
                        Some(goblin::pe::resource::RT_CURSOR) => "CURSOR",
                        Some(goblin::pe::resource::RT_BITMAP) => "BITMAP",
                        Some(goblin::pe::resource::RT_ICON) => "ICON",
                        Some(goblin::pe::resource::RT_MENU) => "MENU",
                        Some(goblin::pe::resource::RT_DIALOG) => "DIALOG",
                        Some(goblin::pe::resource::RT_STRING) => "STRING",
                        Some(goblin::pe::resource::RT_FONTDIR) => "FONTDIR",
                        Some(goblin::pe::resource::RT_FONT) => "FONT",
                        Some(goblin::pe::resource::RT_ACCELERATOR) => "ACCELERATOR",
                        Some(goblin::pe::resource::RT_RCDATA) => "RCDATA",
                        Some(goblin::pe::resource::RT_MESSAGETABLE) => "MESSAGETABLE",
                        Some(goblin::pe::resource::RT_GROUP_CURSOR) => "GROUP_CURSOR",
                        Some(goblin::pe::resource::RT_GROUP_ICON) => "GROUP_ICON",
                        Some(goblin::pe::resource::RT_VERSION) => "VERSION",
                        Some(goblin::pe::resource::RT_DLGINCLUDE) => "DLGINCLUDE",
                        Some(goblin::pe::resource::RT_PLUGPLAY) => "PLUGPLAY",
                        Some(goblin::pe::resource::RT_VXD) => "VXD",
                        Some(goblin::pe::resource::RT_ANICURSOR) => "ANICURSOR",
                        Some(goblin::pe::resource::RT_ANIICON) => "ANIICON",
                        Some(goblin::pe::resource::RT_HTML) => "HTML",
                        Some(goblin::pe::resource::RT_MANIFEST) => "MANIFEST",
                        _ => "UNKNOWN",
                    }.to_string()
                };

                resources.push(Resource {
                    resource_type,
                    name: if entry.name_is_string() {
                        format!("0x{:x}", entry.name_offset())
                    } else {
                        entry.id().map(|id| id.to_string()).unwrap_or_default()
                    },
                    id: entry.name_or_id,
                    size: 0,
                    rva: entry.offset_to_data_or_directory,
                    language: 0,
                });
            }
        }

        resources
    }

    fn detect_elf_function_boundaries(
        data: &[u8],
        elf: &goblin::elf::Elf,
        arch: Architecture,
    ) -> Vec<Function> {
        let mut functions = Vec::new();

        // Find .text section
        let text_section = elf.section_headers.iter().find(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(|name| name == ".text")
                .unwrap_or(false)
        });

        if let Some(text) = text_section {
            let start = text.sh_offset as usize;
            let end = start + text.sh_size as usize;
            if end <= data.len() {
                let text_data = &data[start..end];
                let base_addr = text.sh_addr;

                match arch {
                    Architecture::X86_64 | Architecture::X86 => {
                        // Look for function prologues:
                        // push rbp / push ebp (0x55)
                        // push rbp; mov rbp, rsp (0x55 0x48 0x89 0xe5)
                        for i in 0..text_data.len() {
                            if text_data[i] == 0x55 {
                                // Check for common prologue
                                let has_mov_rbp_rsp = i + 3 < text_data.len()
                                    && text_data[i + 1] == 0x48
                                    && text_data[i + 2] == 0x89
                                    && text_data[i + 3] == 0xe5;

                                if has_mov_rbp_rsp || i == 0 || text_data[i - 1] == 0xc3 || text_data[i - 1] == 0xc2 {
                                    // Function start: either has prologue or follows a ret instruction
                                    let addr = base_addr + i as u64;
                                    // Estimate size by looking for next function or ret
                                    let mut size = 0u64;
                                    for j in (i + 1)..text_data.len() {
                                        if text_data[j] == 0x55 && j + 3 < text_data.len()
                                            && text_data[j + 1] == 0x48
                                            && text_data[j + 2] == 0x89
                                            && text_data[j + 3] == 0xe5
                                        {
                                            size = (j - i) as u64;
                                            break;
                                        }
                                    }
                                    if size == 0 {
                                        size = (text_data.len() - i) as u64;
                                    }

                                    functions.push(Function {
                                        address: addr,
                                        name: format!("sub_{:x}", addr),
                                        size,
                                    });
                                }
                            }
                        }
                    }
                    Architecture::Arm64 => {
                        // ARM64 function prologues:
                        // stp x29, x30, [sp, #-N]! (common)
                        // sub sp, sp, #N
                        for i in (0..text_data.len()).step_by(4) {
                            if i + 3 < text_data.len() {
                                let insn = u32::from_le_bytes([
                                    text_data[i],
                                    text_data[i + 1],
                                    text_data[i + 2],
                                    text_data[i + 3],
                                ]);
                                // stp x29, x30, [sp, ...]
                                let is_stp = (insn & 0x7f800000) == 0x29800000;
                                // sub sp, sp, #imm
                                let is_sub_sp = (insn & 0x7f800000) == 0x51000000 && ((insn >> 5) & 0x1f) == 31;

                                if is_stp || is_sub_sp {
                                    let addr = base_addr + i as u64;
                                    let mut size = 0u64;
                                    for j in ((i + 4)..text_data.len()).step_by(4) {
                                        if j + 3 < text_data.len() {
                                            let next_insn = u32::from_le_bytes([
                                                text_data[j],
                                                text_data[j + 1],
                                                text_data[j + 2],
                                                text_data[j + 3],
                                            ]);
                                            if (next_insn & 0x7f800000) == 0x29800000 {
                                                size = (j - i) as u64;
                                                break;
                                            }
                                        }
                                    }
                                    if size == 0 {
                                        size = (text_data.len() - i) as u64;
                                    }

                                    functions.push(Function {
                                        address: addr,
                                        name: format!("sub_{:x}", addr),
                                        size,
                                    });
                                }
                            }
                        }
                    }
                    Architecture::Unknown => {
                        // Fallback: entry point as single function
                        functions.push(Function {
                            address: elf.entry,
                            name: "entry".to_string(),
                            size: text.sh_size,
                        });
                    }
                }
            }
        }

        // If still no functions found, use entry point
        if functions.is_empty() {
            functions.push(Function {
                address: elf.entry,
                name: "entry".to_string(),
                size: 0,
            });
        }

        functions
    }

    fn detect_macho_function_boundaries(binary: &Binary) -> Vec<Function> {
        let mut functions = Vec::new();

        // Find __text section
        let text_section = binary.sections.iter().find(|s| s.name.contains("__text"));

        if let Some(text) = text_section {
            let start = text.offset as usize;
            let end = start + text.size as usize;
            if end <= binary.data.len() {
                let text_data = &binary.data[start..end];
                let base_addr = text.address;

                match binary.architecture {
                    Architecture::X86_64 => {
                        for i in 0..text_data.len() {
                            if text_data[i] == 0x55 {
                                let has_mov_rbp_rsp = i + 3 < text_data.len()
                                    && text_data[i + 1] == 0x48
                                    && text_data[i + 2] == 0x89
                                    && text_data[i + 3] == 0xe5;

                                if has_mov_rbp_rsp || i == 0 || text_data.get(i.wrapping_sub(1)) == Some(&0xc3) {
                                    let addr = base_addr + i as u64;
                                    functions.push(Function {
                                        address: addr,
                                        name: format!("sub_{:x}", addr),
                                        size: 0,
                                    });
                                }
                            }
                        }
                    }
                    Architecture::Arm64 => {
                        for i in (0..text_data.len()).step_by(4) {
                            if i + 3 < text_data.len() {
                                let insn = u32::from_le_bytes([
                                    text_data[i],
                                    text_data[i + 1],
                                    text_data[i + 2],
                                    text_data[i + 3],
                                ]);
                                let is_stp = (insn & 0x7f800000) == 0x29800000;
                                let is_sub_sp = (insn & 0x7f800000) == 0x51000000 && ((insn >> 5) & 0x1f) == 31;

                                if is_stp || is_sub_sp {
                                    let addr = base_addr + i as u64;
                                    functions.push(Function {
                                        address: addr,
                                        name: format!("sub_{:x}", addr),
                                        size: 0,
                                    });
                                }
                            }
                        }
                    }
                    _ => {
                        functions.push(Function {
                            address: binary.entry_point,
                            name: "entry".to_string(),
                            size: text.size,
                        });
                    }
                }
            }
        }

        if functions.is_empty() {
            functions.push(Function {
                address: binary.entry_point,
                name: "entry".to_string(),
                size: 0,
            });
        }

        functions
    }

    fn detect_pe_function_boundaries(binary: &Binary) -> Vec<Function> {
        let mut functions = Vec::new();

        // Find .text section in PE
        let text_section = binary.sections.iter().find(|s| {
            s.name == ".text" || s.name == "CODE" || s.name == "text"
        });

        if let Some(text) = text_section {
            let start = text.offset as usize;
            let end = start + text.size as usize;
            if end <= binary.data.len() {
                let text_data = &binary.data[start..end];
                let base_addr = text.address;

                match binary.architecture {
                    Architecture::X86_64 | Architecture::X86 => {
                        // PE function prologues
                        for i in 0..text_data.len() {
                            if text_data[i] == 0x55 {
                                let has_mov_rbp_rsp = i + 3 < text_data.len()
                                    && text_data[i + 1] == 0x48
                                    && text_data[i + 2] == 0x89
                                    && text_data[i + 3] == 0xe5;

                                // Also look for MSVC-style prologue
                                let has_mov_esp_ebp = i + 2 < text_data.len()
                                    && text_data[i + 1] == 0x8b
                                    && text_data[i + 2] == 0xec;

                                if has_mov_rbp_rsp || has_mov_esp_ebp || i == 0 
                                    || text_data.get(i.wrapping_sub(1)) == Some(&0xc3)
                                    || text_data.get(i.wrapping_sub(1)) == Some(&0xc2) {
                                    let addr = base_addr + i as u64;
                                    functions.push(Function {
                                        address: addr,
                                        name: format!("sub_{:x}", addr),
                                        size: 0,
                                    });
                                }
                            }
                        }
                    }
                    Architecture::Arm64 => {
                        for i in (0..text_data.len()).step_by(4) {
                            if i + 3 < text_data.len() {
                                let insn = u32::from_le_bytes([
                                    text_data[i],
                                    text_data[i + 1],
                                    text_data[i + 2],
                                    text_data[i + 3],
                                ]);
                                let is_stp = (insn & 0x7f800000) == 0x29800000;
                                let is_sub_sp = (insn & 0x7f800000) == 0x51000000 && ((insn >> 5) & 0x1f) == 31;

                                if is_stp || is_sub_sp {
                                    let addr = base_addr + i as u64;
                                    functions.push(Function {
                                        address: addr,
                                        name: format!("sub_{:x}", addr),
                                        size: 0,
                                    });
                                }
                            }
                        }
                    }
                    _ => {
                        functions.push(Function {
                            address: binary.entry_point,
                            name: "entry".to_string(),
                            size: text.size,
                        });
                    }
                }
            }
        }

        // Also check export table for function addresses
        for export in &binary.exports {
            if export.address != 0 && !functions.iter().any(|f| f.address == export.address) {
                functions.push(Function {
                    address: export.address,
                    name: export.name.clone(),
                    size: 0,
                });
            }
        }

        if functions.is_empty() {
            functions.push(Function {
                address: binary.entry_point,
                name: "entry".to_string(),
                size: 0,
            });
        }

        functions
    }

    pub fn get_binary(&self, id: &str) -> anyhow::Result<Binary> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.clone())
    }

    pub fn get_functions(&self, id: &str) -> anyhow::Result<Vec<Function>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.functions.clone())
    }

    pub fn get_sections(&self, id: &str) -> anyhow::Result<Vec<Section>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.sections.clone())
    }

    pub fn get_symbols(&self, id: &str) -> anyhow::Result<Vec<Symbol>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.symbols.clone())
    }

    pub fn get_relocations(&self, id: &str) -> anyhow::Result<Vec<Relocation>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.relocations.clone())
    }

    pub fn get_imports(&self, id: &str) -> anyhow::Result<Vec<Import>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.imports.clone())
    }

    pub fn get_exports(&self, id: &str) -> anyhow::Result<Vec<Export>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.exports.clone())
    }

    pub fn get_resources(&self, id: &str) -> anyhow::Result<Vec<Resource>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;
        Ok(binary.resources.clone())
    }

    pub fn disassemble_function(
        &self,
        id: &str,
        addr: &str,
    ) -> anyhow::Result<Vec<Instruction>> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;

        let address = u64::from_str_radix(addr.trim_start_matches("0x"), 16)?;

        // Find the function to get its size
        let function = binary
            .functions
            .iter()
            .find(|f| f.address == address)
            .ok_or_else(|| anyhow::anyhow!("Function not found at address {}", addr))?;

        // Find the section containing this address
        let section = binary.sections.iter().find(|s| {
            s.address <= address && address < s.address + s.size
        });

        let code = if let Some(sec) = section {
            let offset = (address - sec.address) as usize;
            let size = if function.size > 0 {
                function.size as usize
            } else {
                (sec.size as usize).saturating_sub(offset)
            };
            &binary.data[sec.offset as usize + offset..sec.offset as usize + offset + size]
        } else {
            // Fallback: try to find in program headers for loaded segments (ELF)
            match Object::parse(&binary.data)? {
                Object::Elf(elf) => {
                    for ph in &elf.program_headers {
                        if ph.p_type == goblin::elf::program_header::PT_LOAD {
                            let seg_start = ph.p_vaddr;
                            let seg_end = ph.p_vaddr + ph.p_filesz;
                            if seg_start <= address && address < seg_end {
                                let file_offset = (address - seg_start + ph.p_offset) as usize;
                                let max_size = (ph.p_filesz - (address - seg_start)) as usize;
                                let size = if function.size > 0 {
                                    std::cmp::min(function.size as usize, max_size)
                                } else {
                                    max_size
                                };
                                return Ok(
                                    Self::disassemble_bytes(&binary.data[file_offset..file_offset + size],
                                        address,
                                        binary.architecture,
                                    )?
                                );
                            }
                        }
                    }
                    anyhow::bail!("Address {} not found in any loaded segment", addr)
                }
                _ => anyhow::bail!("Cannot find code for address {}", addr),
            }
        };

        Self::disassemble_bytes(code, address, binary.architecture)
    }

    fn disassemble_bytes(
        code: &[u8],
        address: u64,
        arch: Architecture,
    ) -> anyhow::Result<Vec<Instruction>> {
        let disassembler = Disassembler::new(arch)?;
        let disasm = disassembler.disassemble(code, address)?;

        Ok(disasm
            .into_iter()
            .map(|i| Instruction {
                address: i.address,
                bytes: i.bytes,
                mnemonic: i.mnemonic,
                operands: i.operands,
            })
            .collect())
    }

    pub fn decompile_function(&self, id: &str, addr: &str) -> anyhow::Result<String> {
        let disassembly = self.disassemble_function(id, addr)?;

        if disassembly.is_empty() {
            return Ok(format!("// No instructions found at {}", addr));
        }

        let decompiler = Decompiler::new();
        let disasm_instructions: Vec<DisasmInstruction> = disassembly
            .into_iter()
            .map(|i| DisasmInstruction {
                address: i.address,
                bytes: i.bytes,
                mnemonic: i.mnemonic,
                operands: i.operands,
            })
            .collect();

        let cfg = decompiler.build_cfg(&disasm_instructions);
        Ok(decompiler.decompile(&cfg))
    }

    pub fn get_cfg(&self, id: &str) -> anyhow::Result<serde_json::Value> {
        let binary = self
            .binaries
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Binary not found"))?;

        if binary.functions.is_empty() {
            return Ok(serde_json::json!({
                "nodes": [],
                "edges": []
            }));
        }

        // Build CFG for the first function
        let first_func = &binary.functions[0];
        let disassembly = self.disassemble_function(id, &format!("0x{:x}", first_func.address))?;

        if disassembly.is_empty() {
            return Ok(serde_json::json!({
                "nodes": [],
                "edges": []
            }));
        }

        let decompiler = Decompiler::new();
        let disasm_instructions: Vec<DisasmInstruction> = disassembly
            .into_iter()
            .map(|i| DisasmInstruction {
                address: i.address,
                bytes: i.bytes,
                mnemonic: i.mnemonic,
                operands: i.operands,
            })
            .collect();

        let cfg = decompiler.build_cfg(&disasm_instructions);

        // Convert petgraph to our graph format
        let mut graph: DiGraph<String, String> = DiGraph::new();
        let mut node_map = HashMap::new();

        for node_idx in cfg.graph.node_indices() {
            let node_id = format!("block_{}", node_idx.index());
            let label = format!("0x{:x}", cfg.graph[node_idx].address);
            let idx = graph.add_node(label);
            node_map.insert(node_id, idx);
        }

        for edge in cfg.graph.edge_indices() {
            let (from, to) = cfg.graph.edge_endpoints(edge).unwrap();
            let edge_type = match cfg.graph[edge] {
                crate::decompiler::EdgeType::Fallthrough => "fallthrough",
                crate::decompiler::EdgeType::Branch => "branch",
                crate::decompiler::EdgeType::Call => "call",
                crate::decompiler::EdgeType::Return => "return",
            };
            graph.add_edge(from, to, edge_type.to_string());
        }

        let graph_data = layout_graph(&graph);
        Ok(serde_json::to_value(graph_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_elf_binary() {
        let mut analyzer = BinaryAnalyzer::new();

        // Use /bin/ls as a test binary (should exist on most Linux systems)
        let result = analyzer.load("/bin/ls").await;
        assert!(result.is_ok(), "Failed to load binary: {:?}", result.err());

        let id = result.unwrap();

        // Test get_functions
        let functions = analyzer.get_functions(&id).unwrap();
        assert!(!functions.is_empty(), "Should find at least one function");

        // Test get_sections
        let sections = analyzer.get_sections(&id).unwrap();
        assert!(!sections.is_empty(), "Should find sections");
        assert!(sections.iter().any(|s| s.name == ".text"), "Should have .text section");

        // Test get_symbols
        let symbols = analyzer.get_symbols(&id).unwrap();
        assert!(!symbols.is_empty(), "Should find symbols");

        // Test disassembly of first function
        let first_func = &functions[0];
        let addr = format!("0x{:x}", first_func.address);
        let instructions = analyzer.disassemble_function(&id, &addr).unwrap();
        assert!(!instructions.is_empty(), "Should disassemble instructions");

        // Verify real capstone output (not placeholder)
        assert!(
            instructions.iter().any(|i| !i.mnemonic.is_empty() && i.mnemonic != "???"),
            "Should have real mnemonics"
        );

        // Test decompilation
        let pseudo = analyzer.decompile_function(&id, &addr).unwrap();
        assert!(!pseudo.is_empty(), "Should generate pseudo-code");
        assert!(pseudo.contains("Decompiled"), "Should contain decompilation header");

        // Test CFG
        let cfg = analyzer.get_cfg(&id).unwrap();
        assert!(cfg.get("nodes").is_some(), "CFG should have nodes");
        assert!(cfg.get("edges").is_some(), "CFG should have edges");
    }

    #[tokio::test]
    async fn test_architecture_detection() {
        let mut analyzer = BinaryAnalyzer::new();
        let id = analyzer.load("/bin/ls").await.unwrap();

        // Get the binary and check architecture
        let binary = analyzer.binaries.get(&id).unwrap();
        assert!(
            binary.architecture == Architecture::X86_64 || binary.architecture == Architecture::X86,
            "Should detect x86 architecture for /bin/ls"
        );
    }
}
