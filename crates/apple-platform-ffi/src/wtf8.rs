//! Minimal WTF-8 codec: UTF-8 extended so unpaired UTF-16 surrogates get
//! their own 3-byte sequences. This is exactly the encoding Python's
//! `os.fsencode` produces on Windows (UTF-8 with `surrogatepass`), which is
//! how byte paths cross the FFI boundary there. Unix never needs it: path
//! bytes are passed through verbatim.

/// UTF-16 code units (what Windows `OsStr::encode_wide` yields) -> WTF-8.
/// Well-formed surrogate pairs become 4-byte sequences; lone surrogates get
/// the 3-byte encoding of their code point.
pub(crate) fn encode(units: impl Iterator<Item = u16>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut units = units.peekable();
    while let Some(unit) = units.next() {
        match unit {
            0x0000..=0x007F => out.push(unit as u8),
            0x0080..=0x07FF => {
                out.push(0xC0 | (unit >> 6) as u8);
                out.push(0x80 | (unit & 0x3F) as u8);
            }
            0xD800..=0xDBFF if units.peek().is_some_and(|u| (0xDC00..=0xDFFF).contains(u)) => {
                let low = units.next().expect("peeked");
                let scalar = 0x10000u32 + (((unit as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                out.push(0xF0 | (scalar >> 18) as u8);
                out.push(0x80 | ((scalar >> 12) & 0x3F) as u8);
                out.push(0x80 | ((scalar >> 6) & 0x3F) as u8);
                out.push(0x80 | (scalar & 0x3F) as u8);
            }
            // Everything else — including lone surrogates — is 3 bytes.
            _ => {
                out.push(0xE0 | (unit >> 12) as u8);
                out.push(0x80 | ((unit >> 6) & 0x3F) as u8);
                out.push(0x80 | (unit & 0x3F) as u8);
            }
        }
    }
    out
}

/// WTF-8 -> UTF-16 code units. Permissive the way Python's `surrogatepass`
/// decoder is: an adjacent pair of 3-byte-encoded surrogates decodes to two
/// units (which `OsString::from_wide` then treats as a pair), so
/// `encode(decode(x)?) != x` is possible for such non-canonical input.
/// Rejects overlong forms, truncated/invalid sequences, and anything above
/// U+10FFFF.
pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<u16>, String> {
    fn cont(bytes: &[u8], i: usize) -> Result<u32, String> {
        match bytes.get(i) {
            Some(&b) if (0x80..=0xBF).contains(&b) => Ok(b as u32 & 0x3F),
            Some(&b) => Err(format!("invalid continuation byte 0x{b:02x} at offset {i}")),
            None => Err(format!("truncated multi-byte sequence at offset {i}")),
        }
    }

    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let scalar = match b0 {
            0x00..=0x7F => {
                i += 1;
                b0 as u32
            }
            0xC2..=0xDF => {
                let b1 = cont(bytes, i + 1)?;
                i += 2;
                ((b0 as u32 & 0x1F) << 6) | b1
            }
            0xE0..=0xEF => {
                let b1 = cont(bytes, i + 1)?;
                // The one deliberate deviation from strict UTF-8: 0xED with
                // b1 in 0xA0..=0xBF (surrogates) is accepted here.
                if b0 == 0xE0 && b1 < 0x20 {
                    return Err(format!("overlong 3-byte sequence at offset {i}"));
                }
                let b2 = cont(bytes, i + 2)?;
                i += 3;
                ((b0 as u32 & 0x0F) << 12) | (b1 << 6) | b2
            }
            0xF0..=0xF4 => {
                let b1 = cont(bytes, i + 1)?;
                if b0 == 0xF0 && b1 < 0x10 {
                    return Err(format!("overlong 4-byte sequence at offset {i}"));
                }
                if b0 == 0xF4 && b1 > 0x0F {
                    return Err(format!("code point above U+10FFFF at offset {i}"));
                }
                let b2 = cont(bytes, i + 2)?;
                let b3 = cont(bytes, i + 3)?;
                i += 4;
                ((b0 as u32 & 0x07) << 18) | (b1 << 12) | (b2 << 6) | b3
            }
            _ => return Err(format!("invalid lead byte 0x{b0:02x} at offset {i}")),
        };
        if scalar < 0x10000 {
            out.push(scalar as u16);
        } else {
            let v = scalar - 0x10000;
            out.push(0xD800 + (v >> 10) as u16);
            out.push(0xDC00 + (v & 0x3FF) as u16);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(units: &[u16]) {
        let encoded = encode(units.iter().copied());
        assert_eq!(decode(&encoded).unwrap(), units, "units {units:04x?}");
    }

    #[test]
    fn roundtrips() {
        roundtrip(&[]);
        roundtrip(&[0x61, 0x62, 0x63]); // ascii
        roundtrip(&[0x00E9]); // 2-byte
        roundtrip(&[0x4E2D]); // 3-byte
        roundtrip(&[0xD83D, 0xDE00]); // astral pair
        roundtrip(&[0xD800]); // lone high surrogate
        roundtrip(&[0xDC00]); // lone low surrogate
        roundtrip(&[0xD800, 0x0041]); // high not followed by low
        roundtrip(&[0xDC00, 0xD800]); // low then high
        roundtrip(&[0x2F, 0x74, 0xDCE9, 0xD83D, 0xDE00, 0xFFFF]); // mixed
    }

    #[test]
    fn matches_utf8_for_valid_unicode() {
        let text = "café/中文/😀";
        let units = text.encode_utf16().collect::<Vec<_>>();
        assert_eq!(encode(units.iter().copied()), text.as_bytes());
    }

    #[test]
    fn byte_exact_vectors() {
        assert_eq!(encode([0xD83D, 0xDE00].into_iter()), "😀".as_bytes());
        // Lone low surrogate U+DCE9 -> its own 3-byte sequence, exactly what
        // Python emits: b"\xe9".decode("utf-8", "surrogateescape") -> U+DCE9.
        assert_eq!(encode([0xDCE9].into_iter()), vec![0xED, 0xB3, 0xA9]);
    }

    #[test]
    fn decode_rejects_malformed() {
        for bad in [
            &[0xC0, 0x80][..],         // overlong 2-byte lead
            &[0xC1, 0xBF],             // overlong 2-byte lead
            &[0xE0, 0x80, 0x80],       // overlong 3-byte
            &[0xF0, 0x80, 0x80, 0x80], // overlong 4-byte
            &[0xF4, 0x90, 0x80, 0x80], // above U+10FFFF
            &[0xF5, 0x80, 0x80, 0x80], // invalid lead
            &[0xE4, 0xB8],             // truncated
            &[0x80],                   // bare continuation
            &[0xE4, 0x41, 0x41],       // non-continuation byte
        ] {
            assert!(decode(bad).is_err(), "expected rejection of {bad:02x?}");
        }
    }

    #[test]
    fn decode_accepts_adjacent_encoded_surrogates() {
        // Python surrogatepass compatibility: U+D83D U+DE00 each encoded as
        // 3 bytes decodes to the same units the canonical 4-byte form yields.
        let non_canonical = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode(&non_canonical).unwrap(), vec![0xD83D, 0xDE00]);
        // ...but re-encoding produces the canonical 4-byte form.
        assert_eq!(
            encode(decode(&non_canonical).unwrap().into_iter()),
            "😀".as_bytes()
        );
    }
}
