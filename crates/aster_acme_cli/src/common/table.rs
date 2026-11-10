//! Shared terminal table layout. Cells are padded before any ANSI styling is applied.
use super::output::safe;
use unicode_width::UnicodeWidthStr;

/// Render equally shaped rows, preserving Unicode display width and escaping controls.
/// Callers own headers, row highlighting and column semantics.
pub(crate) fn align<const N: usize>(rows: &[[String; N]]) -> Vec<String> {
    let rows = rows
        .iter()
        .map(|row| row.each_ref().map(|cell| safe(cell)))
        .collect::<Vec<_>>();
    let widths: [usize; N] = std::array::from_fn(|column| {
        rows.iter()
            .map(|row| row[column].width())
            .max()
            .unwrap_or(0)
    });
    rows.iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(column, cell)| {
                    if column + 1 == N {
                        cell.clone()
                    } else {
                        format!(
                            "{cell}{}",
                            " ".repeat(widths[column].saturating_sub(cell.width()))
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join("  ")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_cells_controls_empty_tables_and_last_column_have_consistent_widths() {
        let rows = [
            ["NAME".into(), "STATUS".into()],
            ["猫猫".into(), "valid".into()],
            ["x\n".into(), "pending".into()],
        ];
        let lines = align(&rows);
        assert_eq!(lines[0], "NAME  STATUS");
        assert_eq!(lines[1], "猫猫  valid");
        assert_eq!(lines[2], "x\\n   pending");
        assert_eq!(align::<2>(&[]), [] as [String; 0]);
        assert_eq!(align(&[[String::new()]]), [String::new()]);
    }
}
