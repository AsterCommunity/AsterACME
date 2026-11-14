//! Shared terminal table layout. Cells are padded before any ANSI styling is applied.
use crate::common::output::{self, Style, safe};
use unicode_width::UnicodeWidthStr;

/// A style callback receives row/column indices and escaped plain cell text.
type CellStyle<'a> = &'a dyn Fn(usize, usize, &str) -> String;

/// Render equally shaped rows. Styles are applied after escaping and measuring;
/// None emits plain cells without a forwarding wrapper or a second layout path.
pub(crate) fn align<const N: usize>(
    rows: &[[String; N]],
    style: Option<CellStyle<'_>>,
) -> Vec<String> {
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
        .enumerate()
        .map(|(row_index, row)| {
            row.iter()
                .enumerate()
                .map(|(column, cell)| {
                    let styled = match style {
                        Some(style) => style(row_index, column, cell),
                        None => cell.clone(),
                    };
                    if column + 1 == N {
                        styled
                    } else {
                        format!(
                            "{styled}{}",
                            " ".repeat(widths[column].saturating_sub(cell.width()))
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join("  ")
        })
        .collect()
}

/// Shared inventory/batch presentation: cyan headers, domain-owned cell styles.
/// The callback receives a zero-based data-row index (the header is excluded).
/// Escaping and display-width padding remain in `align` before color is applied.
pub(crate) fn listing<const N: usize>(
    rows: &[[String; N]],
    color: bool,
    cell_style: impl Fn(usize, usize) -> Style,
) -> Vec<String> {
    align(
        rows,
        Some(&|row, column, cell| {
            let style = if row == 0 {
                Style::BoldCyan
            } else {
                cell_style(row - 1, column)
            };
            output::styled(cell, style, color)
        }),
    )
}

#[cfg(test)]
mod tests {
    use crate::common::output::Style;
    use crate::common::table::*;
    #[test]
    fn unicode_cells_controls_empty_tables_and_last_column_have_consistent_widths() {
        let rows = [
            ["NAME".into(), "STATUS".into()],
            ["猫猫".into(), "valid".into()],
            ["x\n".into(), "pending".into()],
        ];
        let lines = align(&rows, None);
        assert_eq!(lines[0], "NAME  STATUS");
        assert_eq!(lines[1], "猫猫  valid");
        assert_eq!(lines[2], "x\\n   pending");
        assert_eq!(align::<2>(&[], None), [] as [String; 0]);
        assert_eq!(align(&[[String::new()]], None), [String::new()]);
    }
    #[test]
    fn cell_colors_preserve_plain_widths_and_independent_semantic_styles() {
        let rows = [
            ["STATUS".into(), "ORDER STATUS".into()],
            ["failed (CSR rejected)".into(), "ready".into()],
        ];
        let styled = align(
            &rows,
            Some(&|row, column, cell| match (row, column) {
                (1, 0) => super::super::output::styled(cell, Style::Red, true),
                (1, 1) => super::super::output::styled(cell, Style::Yellow, true),
                _ => cell.to_owned(),
            }),
        );
        assert_eq!(
            styled[1],
            "\x1b[31mfailed (CSR rejected)\x1b[0m  \x1b[33mready\x1b[0m"
        );
        assert_eq!(styled[0], align(&rows, None)[0]);
    }

    #[test]
    fn listing_owns_headers_and_preserves_plain_layout_and_escaped_cells() {
        let rows = [
            ["NAME".into(), "STATUS".into()],
            ["猫猫".into(), "failed\nstate".into()],
        ];
        let select = |row, column| {
            assert_eq!(row, 0);
            if column == 1 {
                Style::Red
            } else {
                Style::Plain
            }
        };
        assert_eq!(listing(&rows, false, select), align(&rows, None));
        let colored = listing(&rows, true, select);
        assert!(colored[0].contains("\u{001b}[1;36mNAME\u{001b}[0m"));
        assert!(colored[1].contains("\u{001b}[31mfailed\\nstate\u{001b}[0m"));
        assert_eq!(
            listing::<2>(&[], true, |_, _| panic!("empty table")),
            Vec::<String>::new()
        );
        assert_eq!(
            listing(&[["HEADER".into()]], false, |_, _| panic!(
                "header must not call domain style"
            )),
            vec!["HEADER"]
        );
    }
}
