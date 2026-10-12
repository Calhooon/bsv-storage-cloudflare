// Cargo lock package fields only; refuse missing or ambiguous entries.
pub fn lock_version(lock: &str, wanted: &str) -> Result<String, String> {
    let mut versions = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut name = None;
        let mut version = None;
        for line in block
            .lines()
            .take_while(|l| !l.trim_start().starts_with('['))
        {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("name = ") {
                name = Some(value.trim_matches('"'));
            }
            if let Some(value) = line.strip_prefix("version = ") {
                version = Some(value.trim_matches('"'));
            }
        }
        if name == Some(wanted) {
            versions.push(version.ok_or_else(|| format!("{wanted}: missing version"))?);
        }
    }
    match versions.as_slice() {
        [version] => Ok((*version).to_owned()),
        _ => Err(format!(
            "{wanted}: expected one lock entry, found {}",
            versions.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_and_duplicate_lock_entries_are_refused() {
        let one = "[[package]]\nname = \"bsv-overlay-engine\"\nversion = \"0.1.0\"\n";
        assert_eq!(
            super::lock_version(one, "bsv-overlay-engine").as_deref(),
            Ok("0.1.0")
        );
        for lock in [
            String::new(),
            format!("{one}{one}"),
            one.replace("version =", "other ="),
        ] {
            assert!(super::lock_version(&lock, "bsv-overlay-engine").is_err());
        }
    }
}
