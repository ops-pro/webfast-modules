//! The proof-of-work check: the client searched a `counter` such that
//! `sha256(nonce || ":" || counter)` starts with `difficulty` zero bits; the server computes that
//! one hash. `difficulty` 18 is 2^18 hashes on average: a third of a second on a laptop, one or
//! two on a phone; the bounds (12..=28) keep it between "a blink" and "a minute".

use aws_lc_rs::digest::{SHA256, digest};

/// The least and the most `difficulty` may be.
pub const MIN_DIFFICULTY: u8 = 12;
pub const MAX_DIFFICULTY: u8 = 28;
/// The default: 2^18 hashes.
pub const DEFAULT_DIFFICULTY: u8 = 18;
/// A counter longer than this is no counter of a search a browser made.
const MAX_COUNTER: usize = 20;

/// Whether `counter` answers `nonce` at `difficulty`.
pub fn check(nonce: &[u8], counter: &[u8], difficulty: u8) -> bool {
    if counter.is_empty() || counter.len() > MAX_COUNTER || !counter.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut input = Vec::with_capacity(nonce.len() + 1 + counter.len());
    input.extend_from_slice(nonce);
    input.push(b':');
    input.extend_from_slice(counter);
    leading_zero_bits(digest(&SHA256, &input).as_ref()) >= u32::from(difficulty)
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

/// The counter that answers `nonce` at `difficulty`, searched as the client does (tests).
#[cfg(test)]
pub fn search(nonce: &[u8], difficulty: u8) -> u64 {
    (0u64..)
        .find(|c| check(nonce, c.to_string().as_bytes(), difficulty))
        .expect("a counter")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bits_are_counted_and_one_short_is_not_enough() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x0f]), 20);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
        let nonce = b"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let counter = search(nonce, 12);
        let text = counter.to_string();
        assert!(check(nonce, text.as_bytes(), 12));
        let bits = leading_zero_bits(digest(&SHA256, &[&nonce[..], b":", text.as_bytes()].concat()).as_ref());
        assert!(check(nonce, text.as_bytes(), bits as u8));
        assert!(!check(nonce, text.as_bytes(), bits as u8 + 1), "one bit short");
        assert!(!check(nonce, b"", 12));
        assert!(!check(nonce, b"12a", 12), "not a number");
        assert!(!check(nonce, b"123456789012345678901", 12), "too long");
        assert!((MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&DEFAULT_DIFFICULTY));
    }
}
