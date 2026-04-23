//! Minimal unified-diff-ish output for two canonical JSON strings.
//!
//! We're not chasing diff minimality here — each side's output is already
//! deterministic (sorted keys, pretty-printed), so a naive line-by-line
//! diff is informative enough. If we find cases where this is noisy we can
//! swap in the `similar` crate.

/// Returns a unified-diff-ish string. If the inputs are equal, returns
/// an empty string (callers should check equality before calling).
pub fn unified(a: &str, b: &str, a_label: &str, b_label: &str) -> String {
    let a_lines: Vec<&str> = a.lines().collect();
    let b_lines: Vec<&str> = b.lines().collect();

    let mut out = String::new();
    out.push_str(&format!("--- {a_label}\n"));
    out.push_str(&format!("+++ {b_label}\n"));

    let max = a_lines.len().max(b_lines.len());
    let mut prev_ctx: Option<usize> = None;
    for i in 0..max {
        let a_line = a_lines.get(i).copied();
        let b_line = b_lines.get(i).copied();
        if a_line == b_line {
            continue;
        }
        // Emit a minimal context marker when jumping lines.
        if prev_ctx.map(|p| i > p + 1).unwrap_or(true) {
            out.push_str(&format!("@@ line {} @@\n", i + 1));
        }
        if let Some(l) = a_line {
            out.push_str(&format!("-{l}\n"));
        }
        if let Some(l) = b_line {
            out.push_str(&format!("+{l}\n"));
        }
        prev_ctx = Some(i);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn equal_inputs_produce_header_only() {
        let d = unified("a\nb\n", "a\nb\n", "x", "y");
        // The only content is the two header lines; no hunk markers or
        // +/- diff lines are emitted.
        assert_eq!(d, "--- x\n+++ y\n");
    }

    #[test]
    fn shows_changed_line() {
        let d = unified("a\nB\nc\n", "a\nb\nc\n", "ref", "loc");
        assert!(d.contains("-B"));
        assert!(d.contains("+b"));
    }
}
