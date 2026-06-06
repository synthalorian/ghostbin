use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::collections::HashMap;

use crate::disasm::DisasmInstruction;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub address: u64,
    pub instructions: Vec<DisasmInstruction>,
    #[allow(dead_code)]
    pub pseudo_code: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum EdgeType {
    Fallthrough,
    Branch,
    Call,
    Return,
}

pub struct ControlFlowGraph {
    pub graph: DiGraph<BasicBlock, EdgeType>,
    pub entry: NodeIndex,
}

/// Inferred type for a register or memory location
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum InferredType {
    Unknown,
    Void,
    Pointer(Box<InferredType>),
    Integer(u8),
    Unsigned(u8),
    Char,
    Bool,
    Function,
    Array(Box<InferredType>, usize),
}

impl std::fmt::Display for InferredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InferredType::Unknown => write!(f, "unknown"),
            InferredType::Void => write!(f, "void"),
            InferredType::Pointer(inner) => write!(f, "{}*", inner),
            InferredType::Integer(8) => write!(f, "int8_t"),
            InferredType::Integer(16) => write!(f, "int16_t"),
            InferredType::Integer(32) => write!(f, "int32_t"),
            InferredType::Integer(64) => write!(f, "int64_t"),
            InferredType::Integer(n) => write!(f, "int{}_t", n),
            InferredType::Unsigned(8) => write!(f, "uint8_t"),
            InferredType::Unsigned(16) => write!(f, "uint16_t"),
            InferredType::Unsigned(32) => write!(f, "uint32_t"),
            InferredType::Unsigned(64) => write!(f, "uint64_t"),
            InferredType::Unsigned(n) => write!(f, "uint{}_t", n),
            InferredType::Char => write!(f, "char"),
            InferredType::Bool => write!(f, "bool"),
            InferredType::Function => write!(f, "func_ptr"),
            InferredType::Array(inner, size) => write!(f, "{}[{}]", inner, size),
        }
    }
}

/// Type inference state for a function
#[derive(Debug, Clone)]
pub struct TypeInference {
    pub register_types: HashMap<String, InferredType>,
    #[allow(dead_code)]
    pub variable_types: HashMap<String, InferredType>,
    pub return_type: InferredType,
    pub parameter_types: Vec<(String, InferredType)>,
}

impl Default for TypeInference {
    fn default() -> Self {
        TypeInference {
            register_types: HashMap::new(),
            variable_types: HashMap::new(),
            return_type: InferredType::Unknown,
            parameter_types: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum RegisterUsage {
    PointerLoad,
    Arithmetic,
    Comparison,
    FunctionCall,
}

pub struct Decompiler;

impl Decompiler {
    pub fn new() -> Self {
        Decompiler
    }

    pub fn build_cfg(&self, instructions: &[DisasmInstruction]) -> ControlFlowGraph {
        let mut graph = DiGraph::new();

        if instructions.is_empty() {
            let entry = graph.add_node(BasicBlock {
                address: 0,
                instructions: Vec::new(),
                pseudo_code: String::new(),
            });
            return ControlFlowGraph { graph, entry };
        }

        // Step 1: Identify basic block leaders
        let mut leaders = std::collections::HashSet::new();
        let mut branch_targets = std::collections::HashSet::new();

        leaders.insert(instructions[0].address);

        for (i, insn) in instructions.iter().enumerate() {
            let is_branch = Self::is_branch(&insn.mnemonic);
            let is_call = Self::is_call(&insn.mnemonic);
            let is_return = Self::is_return(&insn.mnemonic);
            let is_unconditional_jump = Self::is_unconditional_jump(&insn.mnemonic);

            if is_branch || is_call {
                if let Some(target) = Self::extract_address(&insn.operands) {
                    branch_targets.insert(target);
                    leaders.insert(target);
                }
            }

            // Instruction after branch/call/return is a leader
            if (is_branch || is_call || is_return || is_unconditional_jump)
                && i + 1 < instructions.len()
            {
                leaders.insert(instructions[i + 1].address);
            }
        }

        // Step 2: Partition instructions into basic blocks
        let mut blocks: Vec<(u64, Vec<DisasmInstruction>)> = Vec::new();
        let mut current_block: Option<(u64, Vec<DisasmInstruction>)> = None;

        for insn in instructions {
            if leaders.contains(&insn.address) {
                if let Some(block) = current_block.take() {
                    blocks.push(block);
                }
                current_block = Some((insn.address, vec![insn.clone()]));
            } else if let Some(ref mut block) = current_block {
                block.1.push(insn.clone());
            }
        }

        if let Some(block) = current_block {
            blocks.push(block);
        }

        // Step 3: Create nodes for each basic block
        let mut addr_to_node: std::collections::HashMap<u64, NodeIndex> =
            std::collections::HashMap::new();
        let mut first_node = None;

        for (addr, block_insns) in &blocks {
            let node = graph.add_node(BasicBlock {
                address: *addr,
                instructions: block_insns.clone(),
                pseudo_code: String::new(),
            });
            addr_to_node.insert(*addr, node);
            if first_node.is_none() {
                first_node = Some(node);
            }
        }

        let entry = first_node.unwrap_or_else(|| {
            graph.add_node(BasicBlock {
                address: 0,
                instructions: Vec::new(),
                pseudo_code: String::new(),
            })
        });

        // Step 4: Add edges based on control flow
        for (addr, block_insns) in &blocks {
            if let Some(&node) = addr_to_node.get(addr) {
                if let Some(last_insn) = block_insns.last() {
                    let is_branch = Self::is_branch(&last_insn.mnemonic);
                    let is_call = Self::is_call(&last_insn.mnemonic);
                    let is_return = Self::is_return(&last_insn.mnemonic);
                    let is_unconditional_jump = Self::is_unconditional_jump(&last_insn.mnemonic);

                    if is_return {
                        // No outgoing edges
                    } else if is_unconditional_jump {
                        if let Some(target) = Self::extract_address(&last_insn.operands) {
                            if let Some(&target_node) = addr_to_node.get(&target) {
                                graph.add_edge(node, target_node, EdgeType::Branch);
                            }
                        }
                    } else if is_branch {
                        // Conditional branch: edge to target and fallthrough
                        if let Some(target) = Self::extract_address(&last_insn.operands) {
                            if let Some(&target_node) = addr_to_node.get(&target) {
                                graph.add_edge(node, target_node, EdgeType::Branch);
                            }
                        }
                        // Fallthrough edge
                        if let Some(next_addr) = Self::find_next_block_address(&addr_to_node, *addr)
                        {
                            if let Some(&next_node) = addr_to_node.get(&next_addr) {
                                if next_node != node {
                                    graph.add_edge(node, next_node, EdgeType::Fallthrough);
                                }
                            }
                        }
                    } else if is_call {
                        if let Some(target) = Self::extract_address(&last_insn.operands) {
                            if let Some(&target_node) = addr_to_node.get(&target) {
                                graph.add_edge(node, target_node, EdgeType::Call);
                            }
                        }
                        // Fallthrough edge
                        if let Some(next_addr) = Self::find_next_block_address(&addr_to_node, *addr)
                        {
                            if let Some(&next_node) = addr_to_node.get(&next_addr) {
                                if next_node != node {
                                    graph.add_edge(node, next_node, EdgeType::Fallthrough);
                                }
                            }
                        }
                    } else {
                        // Normal fallthrough
                        if let Some(next_addr) = Self::find_next_block_address(&addr_to_node, *addr)
                        {
                            if let Some(&next_node) = addr_to_node.get(&next_addr) {
                                if next_node != node {
                                    graph.add_edge(node, next_node, EdgeType::Fallthrough);
                                }
                            }
                        }
                    }
                }
            }
        }

        ControlFlowGraph { graph, entry }
    }

    /// Infer types from instructions
    pub fn infer_types(&self, instructions: &[DisasmInstruction]) -> TypeInference {
        let mut inference = TypeInference::default();
        let mut register_usage: HashMap<String, Vec<RegisterUsage>> = HashMap::new();

        for insn in instructions {
            let mnem = insn.mnemonic.to_lowercase();
            let ops = insn
                .operands
                .split(',')
                .map(|s| s.trim())
                .collect::<Vec<_>>();

            // Track register usage patterns for type inference
            if ops.len() >= 2 {
                let dest = ops[0].to_string();
                let src = ops[1].to_string();

                // Detect pointer operations (lea)
                if mnem == "lea" {
                    inference
                        .register_types
                        .insert(dest.clone(), InferredType::Pointer(Box::new(InferredType::Unknown)));
                    register_usage
                        .entry(dest.clone())
                        .or_default()
                        .push(RegisterUsage::PointerLoad);
                }

                // Detect string operations
                if mnem.starts_with("movs")
                    || mnem.starts_with("cmps")
                    || mnem == "lods"
                    || mnem == "stos"
                {
                    if dest.contains("rsi") || dest.contains("esi") {
                        inference.register_types.insert(
                            dest.clone(),
                            InferredType::Pointer(Box::new(InferredType::Char)),
                        );
                    }
                    if src.contains("rdi") || src.contains("edi") {
                        inference.register_types.insert(
                            src.clone(),
                            InferredType::Pointer(Box::new(InferredType::Char)),
                        );
                    }
                }

                // Detect function calls through registers
                if mnem == "call" && ops[0].starts_with('r') {
                    inference
                        .register_types
                        .insert(dest.clone(), InferredType::Function);
                }

                // Track arithmetic to infer integer types
                if ["add", "sub", "imul", "mul", "idiv", "div", "and", "or", "xor", "shl", "shr", "sar"]
                    .contains(&mnem.as_str())
                {
                    register_usage
                        .entry(dest.clone())
                        .or_default()
                        .push(RegisterUsage::Arithmetic);
                }
            }

            // Detect comparisons for bool inference
            if (mnem == "cmp" || mnem == "test") && ops.len() >= 2 {
                inference
                    .register_types
                    .insert(ops[0].to_string(), InferredType::Integer(32));
            }

            // Detect return value usage
            if mnem == "mov"
                && ops.len() >= 2
                && (ops[0].contains("rax") || ops[0].contains("eax"))
                && (ops[1].contains("0x") || ops[1].parse::<i64>().is_ok())
            {
                inference.return_type = InferredType::Integer(32);
            }
        }

        // Infer from usage patterns
        for (reg, usages) in &register_usage {
            if usages.contains(&RegisterUsage::PointerLoad)
                && usages.contains(&RegisterUsage::Arithmetic)
            {
                // Likely pointer arithmetic - keep as pointer
                inference.register_types.insert(
                    reg.clone(),
                    InferredType::Pointer(Box::new(InferredType::Unknown)),
                );
            } else if usages.contains(&RegisterUsage::Arithmetic)
                && !usages.contains(&RegisterUsage::PointerLoad)
            {
                // Pure arithmetic - likely integer
                if reg.starts_with('r') {
                    inference
                        .register_types
                        .insert(reg.clone(), InferredType::Integer(64));
                } else if reg.starts_with('e') {
                    inference
                        .register_types
                        .insert(reg.clone(), InferredType::Integer(32));
                }
            }
        }

        inference
    }

    pub fn decompile(&self, cfg: &ControlFlowGraph) -> String {
        let mut output = String::new();

        // Generate function signature from type inference
        output.push_str("// Decompiled function\n");
        output.push_str("// Generated by GhostBin v0.7.0\n\n");

        // Collect all instructions for type inference
        let all_instructions: Vec<DisasmInstruction> = cfg
            .graph
            .node_indices()
            .flat_map(|idx| cfg.graph[idx].instructions.clone())
            .collect();

        let type_info = self.infer_types(&all_instructions);

        // Generate function signature
        output.push_str(&self.generate_function_signature(&type_info));
        output.push_str(" {\n");

        // Generate variable declarations from inferred types
        let mut declared_vars = std::collections::HashSet::new();
        for (reg, ty) in &type_info.register_types {
            let var_name = self.register_to_variable(reg);
            if !declared_vars.contains(&var_name) && !var_name.is_empty() {
                declared_vars.insert(var_name.clone());
                output.push_str(&format!("    {} {};\n", ty, var_name));
            }
        }

        if !type_info.register_types.is_empty() {
            output.push('\n');
        }

        // Generate pseudo-code for each basic block with proper control flow
        let mut visited = std::collections::HashSet::new();
        let mut block_queue = vec![cfg.entry];

        while let Some(node_idx) = block_queue.pop() {
            if visited.contains(&node_idx.index()) {
                continue;
            }
            visited.insert(node_idx.index());

            let block = &cfg.graph[node_idx];

            // Add block label (but skip for first block)
            if node_idx != cfg.entry {
                output.push_str(&format!("\nloc_{:x}:\n", block.address));
            }

            for insn in &block.instructions {
                let pseudo = self.instruction_to_pseudo(insn, &type_info);
                if !pseudo.is_empty() {
                    output.push_str(&format!("    {}\n", pseudo));
                }
            }

            // Handle control flow at end of block
            if let Some(last_insn) = block.instructions.last() {
                let is_branch = Self::is_branch(&last_insn.mnemonic);
                let is_unconditional_jump = Self::is_unconditional_jump(&last_insn.mnemonic);
                let is_return = Self::is_return(&last_insn.mnemonic);

                if is_return {
                    // Already handled by instruction_to_pseudo
                } else if is_unconditional_jump {
                    if let Some(target) = Self::extract_address(&last_insn.operands) {
                        output.push_str(&format!("    goto loc_{:x};\n", target));
                    }
                } else if is_branch {
                    // Conditional branch - add if statement
                    let condition = self.branch_condition(&last_insn.mnemonic, &last_insn.operands);
                    if let Some(target) = Self::extract_address(&last_insn.operands) {
                        output.push_str(&format!(
                            "    if ({}) goto loc_{:x};\n",
                            condition, target
                        ));
                    }
                }
            }

            // Queue successors in order
            let mut successors: Vec<_> =
                cfg.graph.neighbors_directed(node_idx, Direction::Outgoing).collect();
            successors.reverse(); // Process fallthrough first
            for succ in successors {
                block_queue.push(succ);
            }
        }

        output.push_str("}\n");
        output
    }

    fn generate_function_signature(&self, type_info: &TypeInference) -> String {
        let return_type = if type_info.return_type == InferredType::Unknown {
            "void"
        } else {
            "int32_t" // Default to int32_t for now
        };

        if type_info.parameter_types.is_empty() {
            format!("{} func_unk()", return_type)
        } else {
            let params = type_info
                .parameter_types
                .iter()
                .map(|(name, ty)| format!("{} {}", ty, name))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} func_unk({})", return_type, params)
        }
    }

    fn register_to_variable(&self, reg: &str) -> String {
        // Convert register names to variable names
        let clean = reg.trim_start_matches('[').trim_end_matches(']').trim();
        match clean {
            "rax" | "eax" | "ax" | "al" => "var_result".to_string(),
            "rbx" | "ebx" | "bx" | "bl" => "var_b".to_string(),
            "rcx" | "ecx" | "cx" | "cl" => "var_c".to_string(),
            "rdx" | "edx" | "dx" | "dl" => "var_d".to_string(),
            "rsi" | "esi" | "si" | "sil" => "var_src".to_string(),
            "rdi" | "edi" | "di" | "dil" => "var_dst".to_string(),
            "rbp" | "ebp" | "bp" => "var_frame".to_string(),
            "rsp" | "esp" | "sp" => "var_stack".to_string(),
            "r8" | "r8d" | "r8w" | "r8b" => "var_8".to_string(),
            "r9" | "r9d" | "r9w" | "r9b" => "var_9".to_string(),
            "r10" | "r10d" | "r10w" | "r10b" => "var_10".to_string(),
            "r11" | "r11d" | "r11w" | "r11b" => "var_11".to_string(),
            "r12" | "r12d" | "r12w" | "r12b" => "var_12".to_string(),
            "r13" | "r13d" | "r13w" | "r13b" => "var_13".to_string(),
            "r14" | "r14d" | "r14w" | "r14b" => "var_14".to_string(),
            "r15" | "r15d" | "r15w" | "r15b" => "var_15".to_string(),
            _ => {
                if clean.starts_with("xmm") {
                    format!("var_{}", clean)
                } else {
                    String::new()
                }
            }
        }
    }

    fn branch_condition(&self, mnemonic: &str, _operands: &str) -> String {
        let mnem = mnemonic.to_lowercase();
        match mnem.as_str() {
            "je" | "jz" => "var_equal",
            "jne" | "jnz" => "!var_equal",
            "ja" | "jnbe" => "var_above",
            "jae" | "jnb" | "jnc" => "var_above_equal",
            "jb" | "jnae" | "jc" => "var_below",
            "jbe" | "jna" => "var_below_equal",
            "jg" | "jnle" => "var_greater",
            "jge" | "jnl" => "var_greater_equal",
            "jl" | "jnge" => "var_less",
            "jle" | "jng" => "var_less_equal",
            "jo" => "var_overflow",
            "jno" => "!var_overflow",
            "js" => "var_sign",
            "jns" => "!var_sign",
            "jp" | "jpe" => "var_parity",
            "jnp" | "jpo" => "!var_parity",
            // ARM64
            "b.eq" => "var_equal",
            "b.ne" => "!var_equal",
            "b.hs" => "var_above_equal",
            "b.lo" => "var_below",
            "b.mi" => "var_sign",
            "b.pl" => "!var_sign",
            "b.vs" => "var_overflow",
            "b.vc" => "!var_overflow",
            "b.hi" => "var_above",
            "b.ls" => "var_below_equal",
            "b.ge" => "var_greater_equal",
            "b.lt" => "var_less",
            "b.gt" => "var_greater",
            "b.le" => "var_less_equal",
            "cbz" => "var_zero",
            "cbnz" => "!var_zero",
            _ => "var_condition",
        }
        .to_string()
    }

    fn is_branch(mnemonic: &str) -> bool {
        let branches = [
            "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "jo",
            "jno", "js", "jns", "jp", "jnp", "jc", "jnc", "jnbe", "jna", "jnae", "jnb", "jnge",
            "jng", "jnle", "jnl", "jo", "jno", "b.eq", "b.ne", "b.hs", "b.lo", "b.mi", "b.pl",
            "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "cbz", "cbnz",
            "tbz", "tbnz",
        ];
        branches.contains(&mnemonic.to_lowercase().as_str())
    }

    fn is_unconditional_jump(mnemonic: &str) -> bool {
        let jumps = ["jmp", "b", "br"];
        jumps.contains(&mnemonic.to_lowercase().as_str())
    }

    fn is_call(mnemonic: &str) -> bool {
        let calls = ["call", "bl", "blr"];
        calls.contains(&mnemonic.to_lowercase().as_str())
    }

    fn is_return(mnemonic: &str) -> bool {
        let rets = ["ret", "retn", "retf", "eret", "drps"];
        rets.contains(&mnemonic.to_lowercase().as_str())
    }

    fn extract_address(operands: &str) -> Option<u64> {
        for part in operands.split_whitespace() {
            let clean = part
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches(',')
                .trim_end_matches(']');
            if let Some(hex_str) = clean.strip_prefix("0x") {
                if let Ok(addr) = u64::from_str_radix(hex_str, 16) {
                    return Some(addr);
                }
            }
        }
        None
    }

    fn find_next_block_address(
        addr_to_node: &std::collections::HashMap<u64, NodeIndex>,
        current_addr: u64,
    ) -> Option<u64> {
        let mut next_addr = None;
        for &addr in addr_to_node.keys() {
            if addr > current_addr && (next_addr.is_none() || addr < next_addr.unwrap()) {
                next_addr = Some(addr);
            }
        }
        next_addr
    }

    fn instruction_to_pseudo(
        &self,
        insn: &DisasmInstruction,
        _type_info: &TypeInference,
    ) -> String {
        let mnem = insn.mnemonic.to_lowercase();
        match mnem.as_str() {
            "push" => format!("// Save {}", insn.operands),
            "pop" => format!("// Restore {}", insn.operands),
            "mov" | "movabs" | "movzx" | "movsx" | "movsxd" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    let dest = parts[0].trim();
                    let src = parts[1].trim();
                    format!(
                        "{} = {};",
                        self.operand_to_c(dest),
                        self.operand_to_c(src)
                    )
                } else {
                    format!("// {} {}", insn.mnemonic, insn.operands)
                }
            }
            "add" => self.binary_op_to_c("+", &insn.operands),
            "sub" => self.binary_op_to_c("-", &insn.operands),
            "imul" | "mul" => self.binary_op_to_c("*", &insn.operands),
            "idiv" | "div" => self.binary_op_to_c("/", &insn.operands),
            "and" => self.binary_op_to_c("&", &insn.operands),
            "or" => self.binary_op_to_c("|", &insn.operands),
            "xor" => self.binary_op_to_c("^", &insn.operands),
            "shl" | "sal" => self.binary_op_to_c("<<", &insn.operands),
            "shr" => self.binary_op_to_c(">>", &insn.operands),
            "sar" => self.binary_op_to_c(">>", &insn.operands), // Arithmetic right shift
            "cmp" | "test" => format!("// Compare {}", insn.operands),
            "call" | "bl" | "blr" => {
                let func_name = insn.operands.trim();
                if func_name.starts_with("0x") {
                    format!("func_{}();", func_name.trim_start_matches("0x"))
                } else {
                    format!("{}();", self.sanitize_function_name(func_name))
                }
            }
            "ret" | "retn" => "return var_result;".to_string(),
            "nop" => String::new(),
            "lea" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!(
                        "{} = &{};",
                        self.operand_to_c(parts[0].trim()),
                        self.operand_to_c(parts[1].trim())
                    )
                } else {
                    format!("// {} {}", insn.mnemonic, insn.operands)
                }
            }
            "inc" => {
                let op = insn.operands.trim();
                format!("{}++;", self.operand_to_c(op))
            }
            "dec" => {
                let op = insn.operands.trim();
                format!("{}--;", self.operand_to_c(op))
            }
            "neg" => {
                let op = insn.operands.trim();
                format!("{} = -{};", self.operand_to_c(op), self.operand_to_c(op))
            }
            "not" => {
                let op = insn.operands.trim();
                format!("{} = ~{};", self.operand_to_c(op), self.operand_to_c(op))
            }
            _ => format!("// asm: {} {}", insn.mnemonic, insn.operands),
        }
    }

    fn binary_op_to_c(&self, op: &str, operands: &str) -> String {
        let parts: Vec<&str> = operands.split(',').collect();
        if parts.len() == 2 {
            format!(
                "{} {}= {};",
                self.operand_to_c(parts[0].trim()),
                op,
                self.operand_to_c(parts[1].trim())
            )
        } else {
            format!("// {}", operands)
        }
    }

    fn operand_to_c(&self, op: &str) -> String {
        let clean = op.trim();

        // Handle memory references
        if clean.starts_with('[') && clean.ends_with(']') {
            let inner = &clean[1..clean.len() - 1];
            let converted = self.convert_registers_in_expr(inner);
            return format!("*({})", converted);
        }

        // Handle registers - convert to variable names
        if self.is_register(clean) {
            return self.register_to_variable(clean);
        }

        // Return as-is for immediates and other operands
        clean.to_string()
    }

    fn convert_registers_in_expr(&self, expr: &str) -> String {
        let mut result = expr.to_string();
        for word in expr.split_whitespace() {
            let trimmed = word.trim_end_matches(',');
            if self.is_register(trimmed) {
                let var_name = self.register_to_variable(trimmed);
                result = result.replace(trimmed, &var_name);
            }
        }
        result
    }

    fn is_register(&self, op: &str) -> bool {
        let regs = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "ax", "bx", "cx",
            "dx", "si", "di", "bp", "sp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w",
            "r15w", "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b",
            "r11b", "r12b", "r13b", "r14b", "r15b", "x0", "x1", "x2", "x3", "x4", "x5", "x6",
            "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
            "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12",
            "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24",
            "w25", "w26", "w27", "w28", "w29", "w30",
        ];
        regs.contains(&op.to_lowercase().as_str())
    }

    fn sanitize_function_name(&self, name: &str) -> String {
        name.trim()
            .replace(|c: char| !c.is_alphanumeric() && c != '_', "_")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_instruction(mnemonic: &str, operands: &str) -> DisasmInstruction {
        DisasmInstruction {
            address: 0x1000,
            bytes: vec![0x90],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
        }
    }

    #[test]
    fn test_infer_types_pointer() {
        let decompiler = Decompiler::new();
        let instructions = vec![
            create_test_instruction("lea", "rax, [rbx + 0x10]"),
            create_test_instruction("mov", "rcx, rax"),
        ];

        let inference = decompiler.infer_types(&instructions);
        assert!(
            inference.register_types.contains_key("rax"),
            "Should infer rax type"
        );
    }

    #[test]
    fn test_infer_types_arithmetic() {
        let decompiler = Decompiler::new();
        let instructions = vec![
            create_test_instruction("add", "rax, 0x10"),
            create_test_instruction("sub", "rax, 0x5"),
        ];

        let inference = decompiler.infer_types(&instructions);
        assert!(
            inference.register_types.contains_key("rax"),
            "Should infer rax type from arithmetic"
        );
    }

    #[test]
    fn test_instruction_to_pseudo_mov() {
        let decompiler = Decompiler::new();
        let insn = create_test_instruction("mov", "rax, rbx");
        let type_info = TypeInference::default();
        let pseudo = decompiler.instruction_to_pseudo(&insn, &type_info);
        assert_eq!(pseudo, "var_result = var_b;");
    }

    #[test]
    fn test_instruction_to_pseudo_add() {
        let decompiler = Decompiler::new();
        let insn = create_test_instruction("add", "rax, 0x10");
        let type_info = TypeInference::default();
        let pseudo = decompiler.instruction_to_pseudo(&insn, &type_info);
        assert_eq!(pseudo, "var_result += 0x10;");
    }

    #[test]
    fn test_instruction_to_pseudo_call() {
        let decompiler = Decompiler::new();
        let insn = create_test_instruction("call", "printf");
        let type_info = TypeInference::default();
        let pseudo = decompiler.instruction_to_pseudo(&insn, &type_info);
        assert_eq!(pseudo, "printf();");
    }

    #[test]
    fn test_instruction_to_pseudo_ret() {
        let decompiler = Decompiler::new();
        let insn = create_test_instruction("ret", "");
        let type_info = TypeInference::default();
        let pseudo = decompiler.instruction_to_pseudo(&insn, &type_info);
        assert_eq!(pseudo, "return var_result;");
    }

    #[test]
    fn test_instruction_to_pseudo_nop() {
        let decompiler = Decompiler::new();
        let insn = create_test_instruction("nop", "");
        let type_info = TypeInference::default();
        let pseudo = decompiler.instruction_to_pseudo(&insn, &type_info);
        assert!(pseudo.is_empty());
    }

    #[test]
    fn test_branch_condition() {
        let decompiler = Decompiler::new();
        assert_eq!(decompiler.branch_condition("je", ""), "var_equal");
        assert_eq!(decompiler.branch_condition("jne", ""), "!var_equal");
        assert_eq!(decompiler.branch_condition("jg", ""), "var_greater");
        assert_eq!(decompiler.branch_condition("b.eq", ""), "var_equal");
    }

    #[test]
    fn test_register_to_variable() {
        let decompiler = Decompiler::new();
        assert_eq!(decompiler.register_to_variable("rax"), "var_result");
        assert_eq!(decompiler.register_to_variable("rbx"), "var_b");
        assert_eq!(decompiler.register_to_variable("rcx"), "var_c");
        assert_eq!(decompiler.register_to_variable("rsi"), "var_src");
        assert_eq!(decompiler.register_to_variable("rdi"), "var_dst");
    }

    #[test]
    fn test_build_cfg_empty() {
        let decompiler = Decompiler::new();
        let cfg = decompiler.build_cfg(&[]);
        assert_eq!(cfg.graph.node_count(), 1);
    }

    #[test]
    fn test_build_cfg_simple() {
        let decompiler = Decompiler::new();
        let instructions = vec![
            DisasmInstruction {
                address: 0x1000,
                bytes: vec![0x55],
                mnemonic: "push".to_string(),
                operands: "rbp".to_string(),
            },
            DisasmInstruction {
                address: 0x1001,
                bytes: vec![0x48, 0x89, 0xe5],
                mnemonic: "mov".to_string(),
                operands: "rbp, rsp".to_string(),
            },
            DisasmInstruction {
                address: 0x1004,
                bytes: vec![0x5d],
                mnemonic: "pop".to_string(),
                operands: "rbp".to_string(),
            },
            DisasmInstruction {
                address: 0x1005,
                bytes: vec![0xc3],
                mnemonic: "ret".to_string(),
                operands: "".to_string(),
            },
        ];

        let cfg = decompiler.build_cfg(&instructions);
        assert!(cfg.graph.node_count() >= 1);
    }

    #[test]
    fn test_decompile_output() {
        let decompiler = Decompiler::new();
        let instructions = vec![
            DisasmInstruction {
                address: 0x1000,
                bytes: vec![0x55],
                mnemonic: "push".to_string(),
                operands: "rbp".to_string(),
            },
            DisasmInstruction {
                address: 0x1001,
                bytes: vec![0x48, 0x89, 0xe5],
                mnemonic: "mov".to_string(),
                operands: "rbp, rsp".to_string(),
            },
            DisasmInstruction {
                address: 0x1004,
                bytes: vec![0x89, 0xf8],
                mnemonic: "mov".to_string(),
                operands: "eax, edi".to_string(),
            },
            DisasmInstruction {
                address: 0x1006,
                bytes: vec![0x5d],
                mnemonic: "pop".to_string(),
                operands: "rbp".to_string(),
            },
            DisasmInstruction {
                address: 0x1007,
                bytes: vec![0xc3],
                mnemonic: "ret".to_string(),
                operands: "".to_string(),
            },
        ];

        let cfg = decompiler.build_cfg(&instructions);
        let output = decompiler.decompile(&cfg);

        assert!(output.contains("Decompiled function"));
        assert!(output.contains("v0.7.0"));
        assert!(output.contains("func_unk"));
        assert!(output.contains("return var_result"));
    }

    #[test]
    fn test_type_inference_display() {
        assert_eq!(InferredType::Integer(32).to_string(), "int32_t");
        assert_eq!(InferredType::Unsigned(64).to_string(), "uint64_t");
        assert_eq!(
            InferredType::Pointer(Box::new(InferredType::Char)).to_string(),
            "char*"
        );
    }

    #[test]
    fn test_is_register() {
        let decompiler = Decompiler::new();
        assert!(decompiler.is_register("rax"));
        assert!(decompiler.is_register("eax"));
        assert!(decompiler.is_register("r8"));
        assert!(decompiler.is_register("x0"));
        assert!(!decompiler.is_register("0x1000"));
        assert!(!decompiler.is_register("[rax]"));
    }

    #[test]
    fn test_operand_to_c_memory() {
        let decompiler = Decompiler::new();
        assert_eq!(decompiler.operand_to_c("[rax]"), "*(var_result)");
        assert_eq!(decompiler.operand_to_c("[rbx + 0x10]"), "*(var_b + 0x10)");
    }

    #[test]
    fn test_sanitize_function_name() {
        let decompiler = Decompiler::new();
        assert_eq!(decompiler.sanitize_function_name("printf"), "printf");
        assert_eq!(decompiler.sanitize_function_name("func@123"), "func_123");
    }
}
