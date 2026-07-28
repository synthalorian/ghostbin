use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::disasm::DisasmInstruction;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub address: u64,
    pub instructions: Vec<DisasmInstruction>,
    pub pseudo_code: String,
}

#[derive(Debug, Clone)]
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

pub struct Decompiler;

impl Default for Decompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompiler {
    pub fn new() -> Self {
        Decompiler
    }

    pub fn build_cfg(&self,
        instructions: &[DisasmInstruction],
    ) -> ControlFlowGraph {
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
        // Leaders are:
        // - First instruction
        // - Target of any branch/jump/call
        // - Instruction after a branch/jump/call/return
        let mut leaders = std::collections::HashSet::new();
        let mut branch_targets = std::collections::HashSet::new();

        leaders.insert(instructions[0].address);

        for (i, insn) in instructions.iter().enumerate() {
            let is_branch = Self::is_branch(&insn.mnemonic);
            let is_call = Self::is_call(&insn.mnemonic);
            let is_return = Self::is_return(&insn.mnemonic);
            let is_unconditional_jump = Self::is_unconditional_jump(&insn.mnemonic);

            if is_branch || is_call {
                // Extract target address from operands if possible
                if let Some(target) = Self::extract_address(&insn.operands) {
                    branch_targets.insert(target);
                    leaders.insert(target);
                }
            }

            // Instruction after branch/call/return is a leader
            if (is_branch || is_call || is_return || is_unconditional_jump)
                && i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].address);
                }
        }

        // Step 2: Partition instructions into basic blocks
        let mut blocks: Vec<( u64, Vec<DisasmInstruction> )> = Vec::new();
        let mut current_block: Option<( u64, Vec<DisasmInstruction> )> = None;

        for insn in instructions {
            if leaders.contains(&insn.address) {
                // Save previous block
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
        let mut addr_to_node: std::collections::HashMap<u64, NodeIndex> = std::collections::HashMap::new();
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

        let entry = first_node.unwrap_or_else(|| graph.add_node(BasicBlock {
            address: 0,
            instructions: Vec::new(),
            pseudo_code: String::new(),
        }));

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
                        // Jump to target
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
                        if let Some(next_addr) = Self::find_next_block_address(&addr_to_node, *addr
                        ) {
                            if let Some(&next_node) = addr_to_node.get(&next_addr) {
                                if next_node != node {
                                    graph.add_edge(node, next_node, EdgeType::Fallthrough);
                                }
                            }
                        }
                    } else if is_call {
                        // Call edge to target
                        if let Some(target) = Self::extract_address(&last_insn.operands) {
                            if let Some(&target_node) = addr_to_node.get(&target) {
                                graph.add_edge(node, target_node, EdgeType::Call);
                            }
                        }
                        // Fallthrough edge
                        if let Some(next_addr) = Self::find_next_block_address(
                            &addr_to_node,
                            *addr,
                        ) {
                            if let Some(&next_node) = addr_to_node.get(&next_addr) {
                                if next_node != node {
                                    graph.add_edge(node, next_node, EdgeType::Fallthrough);
                                }
                            }
                        }
                    } else {
                        // Normal fallthrough
                        if let Some(next_addr) = Self::find_next_block_address(
                            &addr_to_node,
                            *addr,
                        ) {
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

    pub fn decompile(&self, cfg: &ControlFlowGraph) -> String {
        let mut output = String::new();
        output.push_str("// Decompiled function\n");
        output.push_str("// Generated by GhostBin v1.0.0\n\n");

        // Generate pseudo-code for each basic block
        for node_idx in cfg.graph.node_indices() {
            let block = &cfg.graph[node_idx];
            output.push_str(&format!("// Block 0x{:x}\n", block.address));

            for insn in &block.instructions {
                let pseudo = self.instruction_to_pseudo(insn);
                if !pseudo.is_empty() {
                    output.push_str(&format!("    {}\n", pseudo));
                }
            }

            // Add edges info as comments
            let mut edges = Vec::new();
            for neighbor in cfg.graph.neighbors_directed(node_idx, Direction::Outgoing) {
                let edge = cfg.graph.find_edge(node_idx, neighbor).unwrap();
                let edge_type = match cfg.graph[edge] {
                    EdgeType::Fallthrough => "fallthrough",
                    EdgeType::Branch => "branch",
                    EdgeType::Call => "call",
                    EdgeType::Return => "return",
                };
                edges.push(format!(
                    "0x{:x} ({})",
                    cfg.graph[neighbor].address,
                    edge_type
                ));
            }
            if !edges.is_empty() {
                output.push_str(&format!("    // -> {}\n", edges.join(", ")));
            }
            output.push('\n');
        }

        output
    }

    fn is_branch(mnemonic: &str) -> bool {
        let branches = [
            "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
            "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns",
            "jp", "jnp", "jc", "jnc", "jnbe", "jna", "jnae",
            "jnb", "jnge", "jng", "jnle", "jnl", "jo", "jno",
            "b.eq", "b.ne", "b.hs", "b.lo", "b.mi", "b.pl",
            "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt",
            "b.gt", "b.le", "cbz", "cbnz", "tbz", "tbnz",
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
        // Try to extract hex address from operands
        // e.g., "0x401000" or "[rip + 0x401000]"
        for part in operands.split_whitespace() {
            let clean = part
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches(',')
                .trim_end_matches(']');
            if let Some(hex) = clean.strip_prefix("0x") {
                if let Ok(addr) = u64::from_str_radix(hex, 16) {
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
            if addr > current_addr
                && (next_addr.is_none() || addr < next_addr.unwrap()) {
                    next_addr = Some(addr);
                }
        }
        next_addr
    }

    fn instruction_to_pseudo(&self, insn: &DisasmInstruction) -> String {
        let mnem = insn.mnemonic.to_lowercase();
        match mnem.as_str() {
            "push" => format!("// Save {}", insn.operands),
            "pop" => format!("// Restore {}", insn.operands),
            "mov" | "movabs" | "movzx" | "movsx" | "movsxd" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} = {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "add" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} += {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "sub" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} -= {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "imul" | "mul" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} *= {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "idiv" | "div" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} /= {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "and" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} &= {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "or" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} |= {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "xor" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} ^= {}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            "cmp" | "test" => format!("// Compare {}", insn.operands),
            "call" | "bl" | "blr" => format!("// Call {}", insn.operands),
            "ret" | "retn" => "return".to_string(),
            "nop" => String::new(),
            "lea" => {
                let parts: Vec<&str> = insn.operands.split(',').collect();
                if parts.len() == 2 {
                    format!("{} = &{}", parts[0].trim(), parts[1].trim())
                } else {
                    format!("{} {}", insn.mnemonic, insn.operands)
                }
            }
            _ => format!("asm: {} {}", insn.mnemonic, insn.operands),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::visit::EdgeRef;

    fn insn(address: u64, mnemonic: &str, operands: &str) -> DisasmInstruction {
        DisasmInstruction {
            address,
            bytes: Vec::new(),
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
        }
    }

    // A function with a conditional branch:
    //   0x1000: cmp eax, 0
    //   0x1002: je 0x1010
    //   0x1004: mov eax, 1
    //   0x1009: ret
    //   0x1010: mov eax, 2
    //   0x1015: ret
    fn branchy_function() -> Vec<DisasmInstruction> {
        vec![
            insn(0x1000, "cmp", "eax, 0"),
            insn(0x1002, "je", "0x1010"),
            insn(0x1004, "mov", "eax, 1"),
            insn(0x1009, "ret", ""),
            insn(0x1010, "mov", "eax, 2"),
            insn(0x1015, "ret", ""),
        ]
    }

    #[test]
    fn test_cfg_basic_blocks_with_branch() {
        let d = Decompiler::new();
        let cfg = d.build_cfg(&branchy_function());

        // Expect 3 blocks: entry (cmp+je), then-path (mov;ret), else-path (mov;ret)
        assert_eq!(cfg.graph.node_count(), 3);

        // Entry block should have 2 outgoing edges: branch target + fallthrough
        let entry_edges: Vec<_> = cfg
            .graph
            .edges_directed(cfg.entry, Direction::Outgoing)
            .collect();
        assert_eq!(entry_edges.len(), 2);

        let edge_types: Vec<&EdgeType> = entry_edges.iter().map(|e| e.weight()).collect();
        assert!(edge_types.iter().any(|t| matches!(t, EdgeType::Branch)));
        assert!(edge_types.iter().any(|t| matches!(t, EdgeType::Fallthrough)));

        // Branch target block must start at 0x1010
        let branch_target = entry_edges
            .iter()
            .find(|e| matches!(e.weight(), EdgeType::Branch))
            .map(|e| cfg.graph[e.target()].address)
            .unwrap();
        assert_eq!(branch_target, 0x1010);
    }

    #[test]
    fn test_cfg_linear_function_single_block() {
        let d = Decompiler::new();
        let insns = vec![
            insn(0x2000, "push", "rbp"),
            insn(0x2001, "mov", "rbp, rsp"),
            insn(0x2004, "mov", "eax, 0x2a"),
            insn(0x2009, "pop", "rbp"),
            insn(0x200a, "ret", ""),
        ];
        let cfg = d.build_cfg(&insns);
        assert_eq!(cfg.graph.node_count(), 1);
        assert_eq!(cfg.graph.edge_count(), 0);
    }

    #[test]
    fn test_decompile_sanity_mov_add_ret() {
        let d = Decompiler::new();
        let insns = vec![
            insn(0x3000, "mov", "eax, edi"),
            insn(0x3002, "add", "eax, esi"),
            insn(0x3004, "ret", ""),
        ];
        let cfg = d.build_cfg(&insns);
        let pseudo = d.decompile(&cfg);

        assert!(pseudo.contains("Decompiled function"));
        assert!(pseudo.contains("eax = edi"));
        assert!(pseudo.contains("eax += esi"));
        assert!(pseudo.contains("return"));
    }

    #[test]
    fn test_decompile_branch_produces_blocks_and_edges() {
        let d = Decompiler::new();
        let cfg = d.build_cfg(&branchy_function());
        let pseudo = d.decompile(&cfg);

        assert!(pseudo.contains("Block 0x1000"));
        assert!(pseudo.contains("Block 0x1010"));
        assert!(pseudo.contains("0x1010 (branch)"));
    }

    #[test]
    fn test_empty_instruction_list() {
        let d = Decompiler::new();
        let cfg = d.build_cfg(&[]);
        let pseudo = d.decompile(&cfg);
        assert!(pseudo.contains("Decompiled function"));
    }
}
