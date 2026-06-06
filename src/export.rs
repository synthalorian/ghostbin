use crate::annotations::AnnotationThread;
use crate::binary::{Function, Import, Export, Section, Symbol};
use genpdf::elements::{Paragraph, Break};
use genpdf::{Document, Element};
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub binary_name: String,
    pub binary_id: String,
    pub architecture: String,
    pub entry_point: String,
    pub functions: Vec<Function>,
    pub sections: Vec<Section>,
    #[allow(dead_code)]
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub annotations: Vec<AnnotationThread>,
    pub analysis_text: Option<String>,
}

pub fn export_markdown(report: &AnalysisReport) -> String {
    let mut md = String::new();

    md.push_str(&format!("# Analysis Report: {}\n\n", report.binary_name));
    md.push_str(&format!("- **Binary ID**: {}\n", report.binary_id));
    md.push_str(&format!("- **Architecture**: {}\n", report.architecture));
    md.push_str(&format!("- **Entry Point**: {}\n\n", report.entry_point));

    md.push_str("## Sections\n\n");
    md.push_str("| Name | Address | Size |\n");
    md.push_str("|------|---------|------|\n");
    for sec in &report.sections {
        md.push_str(&format!(
            "| {} | 0x{:x} | {} |\n",
            sec.name, sec.address, sec.size
        ));
    }
    md.push('\n');

    md.push_str("## Functions\n\n");
    md.push_str("| Address | Name | Size |\n");
    md.push_str("|---------|------|------|\n");
    for func in &report.functions {
        md.push_str(&format!(
            "| 0x{:x} | {} | {} |\n",
            func.address, func.name, func.size
        ));
    }
    md.push('\n');

    if !report.imports.is_empty() {
        md.push_str("## Imports\n\n");
        md.push_str("| DLL | Name | Address |\n");
        md.push_str("|-----|------|---------|\n");
        for imp in &report.imports {
            md.push_str(&format!(
                "| {} | {} | 0x{:x} |\n",
                imp.dll, imp.name, imp.address
            ));
        }
        md.push('\n');
    }

    if !report.exports.is_empty() {
        md.push_str("## Exports\n\n");
        md.push_str("| Name | Address | Ordinal |\n");
        md.push_str("|------|---------|---------|\n");
        for exp in &report.exports {
            md.push_str(&format!(
                "| {} | 0x{:x} | {} |\n",
                exp.name, exp.address, exp.ordinal
            ));
        }
        md.push('\n');
    }

    if !report.annotations.is_empty() {
        md.push_str("## Annotations\n\n");
        for thread in &report.annotations {
            md.push_str(&format!(
                "### {} by {} at {}\n\n{}",
                thread.root.address,
                thread.root.author,
                thread.root.timestamp.format("%Y-%m-%d %H:%M:%S"),
                thread.root.text
            ));
            if !thread.replies.is_empty() {
                md.push_str("\n\n**Replies:**\n\n");
                for reply in &thread.replies {
                    md.push_str(&format!(
                        "- **{}** ({}): {}\n",
                        reply.author,
                        reply.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        reply.text
                    ));
                }
            }
            md.push_str("\n\n");
        }
    }

    if let Some(ref analysis) = report.analysis_text {
        md.push_str("## AI Analysis\n\n");
        md.push_str(analysis);
        md.push('\n');
    }

    md
}

pub fn export_pdf(report: &AnalysisReport) -> anyhow::Result<Vec<u8>> {
    let mut doc = Document::new(genpdf::fonts::from_files(
        "/usr/share/fonts/truetype/dejavu",
        "DejaVuSans",
        None,
    ).unwrap_or_else(|_| {
        genpdf::fonts::from_files(
            "/usr/share/fonts/truetype/liberation",
            "LiberationSans",
            None,
        ).unwrap_or_else(|_| {
            genpdf::fonts::from_files(
                "/usr/share/fonts/truetype/freefont",
                "FreeSans",
                None,
            ).unwrap_or_else(|_| {
                genpdf::fonts::from_files(
                    "/usr/share/fonts",
                    "Arial",
                    None,
                ).unwrap_or_else(|_| {
                    genpdf::fonts::from_files(
                        "/usr/share/fonts/truetype",
                        "DejaVuSans",
                        None,
                    ).unwrap_or_else(|_| {
                        genpdf::fonts::from_files(
                            "/System/Library/Fonts",
                            "Helvetica",
                            None,
                        ).unwrap_or_else(|_| {
                            genpdf::fonts::from_files(
                                "C:\\Windows\\Fonts",
                                "Arial",
                                None,
                            ).unwrap_or_else(|_| {
                                panic!("No suitable font found for PDF generation")
                            })
                        })
                    })
                })
            })
        })
    }));

    doc.set_title(format!("Analysis Report: {}", report.binary_name));

    doc.push(Paragraph::new(format!(
        "Analysis Report: {}",
        report.binary_name
    )).styled(genpdf::style::Style::new().bold().with_font_size(24)));
    doc.push(Break::new(1));

    doc.push(Paragraph::new(format!("Binary ID: {}", report.binary_id)));
    doc.push(Paragraph::new(format!("Architecture: {}", report.architecture)));
    doc.push(Paragraph::new(format!("Entry Point: {}", report.entry_point)));
    doc.push(Break::new(1));

    doc.push(Paragraph::new("Sections").styled(genpdf::style::Style::new().bold().with_font_size(18)));
    for sec in &report.sections {
        doc.push(Paragraph::new(format!(
            "{} - Address: 0x{:x}, Size: {}",
            sec.name, sec.address, sec.size
        )));
    }
    doc.push(Break::new(1));

    doc.push(Paragraph::new("Functions").styled(genpdf::style::Style::new().bold().with_font_size(18)));
    for func in &report.functions[..report.functions.len().min(100)] {
        doc.push(Paragraph::new(format!(
            "0x{:x} - {} (size: {})",
            func.address, func.name, func.size
        )));
    }
    if report.functions.len() > 100 {
        doc.push(Paragraph::new(format!(
            "... and {} more functions",
            report.functions.len() - 100
        )));
    }
    doc.push(Break::new(1));

    if !report.annotations.is_empty() {
        doc.push(Paragraph::new("Annotations").styled(genpdf::style::Style::new().bold().with_font_size(18)));
        for thread in &report.annotations {
            doc.push(Paragraph::new(format!(
                "{} by {}: {}",
                thread.root.address,
                thread.root.author,
                thread.root.text
            )));
            for reply in &thread.replies {
                doc.push(Paragraph::new(format!(
                    "  Reply by {}: {}",
                    reply.author, reply.text
                )));
            }
        }
        doc.push(Break::new(1));
    }

    if let Some(ref analysis) = report.analysis_text {
        doc.push(Paragraph::new("AI Analysis").styled(genpdf::style::Style::new().bold().with_font_size(18)));
        for line in analysis.lines() {
            doc.push(Paragraph::new(line.to_string()));
        }
    }

    let mut cursor = Cursor::new(Vec::new());
    doc.render(&mut cursor)?;
    Ok(cursor.into_inner())
}
