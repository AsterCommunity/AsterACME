//! Lossless DNS TXT presentation shared by `RRset` providers.
pub(in crate::provider) fn txt_encode(value: &str) -> String {
    use std::fmt::Write;
    let mut output = String::from("\"");
    for byte in value.bytes() {
        match byte {
            b'"' | b'\\' => {
                output.push('\\');
                output.push(char::from(byte));
            }
            0x20..=0x7e => output.push(char::from(byte)),
            _ => {
                let _ = write!(output, "\\{byte:03}");
            }
        }
    }
    output.push('"');
    output
}

pub(in crate::provider) fn txt_decode(value: &str) -> Option<Vec<u8>> {
    let mut input = value.bytes().peekable();
    let mut output = Vec::new();
    let mut chunks = 0;
    while input.peek().is_some() {
        while input.peek().is_some_and(u8::is_ascii_whitespace) {
            input.next();
        }
        if input.peek().is_none() {
            break;
        }
        if input.next()? != b'"' {
            return None;
        }
        chunks += 1;
        let start = output.len();
        loop {
            match input.next()? {
                b'"' => break,
                b'\\' => {
                    let byte = input.next()?;
                    if byte.is_ascii_digit() {
                        let next = input.next()?;
                        let last = input.next()?;
                        if !next.is_ascii_digit() || !last.is_ascii_digit() {
                            return None;
                        }
                        let number = u16::from(byte - b'0') * 100
                            + u16::from(next - b'0') * 10
                            + u16::from(last - b'0');
                        output.push(u8::try_from(number).ok()?);
                    } else {
                        output.push(byte);
                    }
                }
                byte => output.push(byte),
            }
        }
        if output.len() - start > 255 {
            return None;
        }
    }
    (chunks > 0).then_some(output)
}
