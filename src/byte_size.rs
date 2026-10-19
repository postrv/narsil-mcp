//! Byte sizes as given on the command line: `<N>`, `<N>K`, `<N>M`, `<N>G`.

/// Bytes in `text`; a suffix is a power of 1024, either case.
pub fn parse_byte_size(text: &str) -> Result<usize, String> {
    let text = text.trim();
    let invalid = || format!("invalid size '{}': expected <N>, <N>K, <N>M or <N>G", text);
    let (number, unit_bytes): (&str, usize) = match text.chars().last() {
        Some('k' | 'K') => (&text[..text.len() - 1], 1 << 10),
        Some('m' | 'M') => (&text[..text.len() - 1], 1 << 20),
        Some('g' | 'G') => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    let count: usize = number.parse().map_err(|_| invalid())?;
    match count.checked_mul(unit_bytes) {
        Some(bytes) if bytes > 0 => Ok(bytes),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_size_accepts_every_suffix() {
        assert_eq!(parse_byte_size("4096"), Ok(4096));
        assert_eq!(parse_byte_size("8K"), Ok(8 << 10));
        assert_eq!(parse_byte_size("10m"), Ok(10 << 20));
        assert_eq!(parse_byte_size(" 2G "), Ok(2 << 30));
    }

    #[test]
    fn parse_byte_size_rejects_zero_and_garbage() {
        for text in ["", "0", "0M", "M", "-1K", "1.5M", "10T", "ten"] {
            assert!(parse_byte_size(text).is_err(), "{:?} accepted", text);
        }
    }
}
