//! Fixture-based integration tests for GhostBin.
//!
//! The fixture binary is compiled from tests/fixtures/sample.c with `cc`
//! at test time into CARGO_TARGET_TMPDIR, so tests are fully offline and
//! deterministic on any Linux machine with a C compiler.

use ghostbin::binary::BinaryAnalyzer;

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn fixture_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.c");
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ghostbin_sample");
        let status = Command::new("cc")
            .args(["-O0", "-g", "-o"])
            .arg(&out)
            .arg(src)
            .status()
            .expect("failed to invoke cc to build test fixture");
        assert!(status.success(), "cc failed to build fixture binary");
        out
    })
    .clone()
}

async fn load_fixture() -> (BinaryAnalyzer, String) {
    let mut analyzer = BinaryAnalyzer::new();
    let id = analyzer
        .load(fixture_path().to_str().unwrap())
        .await
        .expect("failed to load fixture binary");
    (analyzer, id)
}

#[tokio::test]
async fn test_elf_parse_sections_symbols() {
    let (analyzer, id) = load_fixture().await;

    let info = analyzer.get_info(&id).unwrap();
    assert_eq!(info.format, "ELF");
    assert_eq!(info.architecture, "x86_64");

    let sections = analyzer.get_sections(&id).unwrap();
    assert!(sections.iter().any(|s| s.name == ".text"), "missing .text");
    assert!(sections.iter().any(|s| s.name == ".symtab"), "missing .symtab");

    let symbols = analyzer.get_symbols(&id).unwrap();
    let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"add"), "symbol 'add' missing");
    assert!(names.contains(&"max2"), "symbol 'max2' missing");
    assert!(names.contains(&"main"), "symbol 'main' missing");
}

#[tokio::test]
async fn test_function_list_from_symbols() {
    let (analyzer, id) = load_fixture().await;
    let functions = analyzer.get_functions(&id).unwrap();

    let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"add"));
    assert!(names.contains(&"max2"));

    let add = functions.iter().find(|f| f.name == "add").unwrap();
    assert!(add.address > 0);
    assert!(add.size > 0, "fixture keeps sizes in symtab at -O0");
}

#[tokio::test]
async fn test_disasm_of_known_function() {
    let (analyzer, id) = load_fixture().await;
    let functions = analyzer.get_functions(&id).unwrap();
    let add = functions.iter().find(|f| f.name == "add").unwrap();

    let insns = analyzer
        .disassemble_function(&id, &format!("0x{:x}", add.address))
        .unwrap();

    assert!(!insns.is_empty());
    let mnemonics: Vec<&str> = insns.iter().map(|i| i.mnemonic.as_str()).collect();
    // -O0: classic prologue + add + ret
    assert!(mnemonics.contains(&"push"), "expected prologue: {:?}", mnemonics);
    assert!(mnemonics.contains(&"mov"));
    assert!(mnemonics.contains(&"add"), "add() must contain an add: {:?}", mnemonics);
    assert!(mnemonics.contains(&"ret"));
    assert_eq!(insns[0].address, add.address);
}

#[tokio::test]
async fn test_decompile_sanity_on_trivial_function() {
    let (analyzer, id) = load_fixture().await;
    let functions = analyzer.get_functions(&id).unwrap();
    let add = functions.iter().find(|f| f.name == "add").unwrap();

    let pseudo = analyzer
        .decompile_function(&id, &format!("0x{:x}", add.address))
        .unwrap();

    assert!(pseudo.contains("Decompiled function"));
    assert!(pseudo.contains("return"), "pseudo-code should contain return:\n{}", pseudo);
    // mov/add patterns from the pattern-matching decompiler
    assert!(pseudo.contains('='), "expected assignment pseudo-code:\n{}", pseudo);
}

#[tokio::test]
async fn test_cfg_endpoint_data_has_branch_edges() {
    let (analyzer, id) = load_fixture().await;
    let functions = analyzer.get_functions(&id).unwrap();
    // max2 has an `if` → at -O0 it must produce a conditional jump
    let max2 = functions.iter().find(|f| f.name == "max2").unwrap();

    let insns = analyzer
        .disassemble_function(&id, &format!("0x{:x}", max2.address))
        .unwrap();
    let mnemonics: Vec<&str> = insns.iter().map(|i| i.mnemonic.as_str()).collect();
    let has_cond_jump = mnemonics
        .iter()
        .any(|m| m.starts_with('j') && *m != "jmp");
    assert!(has_cond_jump, "max2 should contain a conditional jump: {:?}", mnemonics);
}

#[tokio::test]
async fn test_unknown_binary_and_function_errors() {
    let (mut analyzer, id) = load_fixture().await;
    assert!(analyzer.get_functions("bin_999").is_err());
    assert!(analyzer.disassemble_function(&id, "0xdeadbeef").is_err());
    assert!(analyzer.load("/nonexistent/path").await.is_err());
}
