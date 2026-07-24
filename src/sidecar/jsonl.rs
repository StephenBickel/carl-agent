use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LineReadError {
    Io,
    MissingTerminator,
    TooLong,
}

pub(super) async fn read_bounded_line<R>(
    reader: &mut R,
    maximum_bytes: usize,
) -> Result<Option<Vec<u8>>, LineReadError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::with_capacity(maximum_bytes.min(8 * 1_024));

    loop {
        let available = reader.fill_buf().await.map_err(|_| LineReadError::Io)?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(LineReadError::MissingTerminator)
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(consumed) > maximum_bytes {
            return Err(LineReadError::TooLong);
        }
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);

        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

pub(super) fn encode_line(value: &serde_json::Value, maximum_bytes: usize) -> Result<Vec<u8>, ()> {
    let mut line = serde_json::to_vec(value).map_err(|_| ())?;
    if line.len().saturating_add(1) > maximum_bytes {
        return Err(());
    }
    line.push(b'\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::{LineReadError, encode_line, read_bounded_line};

    #[tokio::test]
    async fn bounded_reader_preserves_following_lines() {
        let mut reader = BufReader::new(&b"one\ntwo\r\n"[..]);
        assert_eq!(
            read_bounded_line(&mut reader, 16).await,
            Ok(Some(b"one".to_vec()))
        );
        assert_eq!(
            read_bounded_line(&mut reader, 16).await,
            Ok(Some(b"two".to_vec()))
        );
        assert_eq!(read_bounded_line(&mut reader, 16).await, Ok(None));
    }

    #[tokio::test]
    async fn bounded_reader_rejects_missing_terminator_and_oversize() {
        let mut unterminated = BufReader::new(&b"unterminated"[..]);
        assert_eq!(
            read_bounded_line(&mut unterminated, 64).await,
            Err(LineReadError::MissingTerminator)
        );

        let mut oversized = BufReader::new(&b"12345\n"[..]);
        assert_eq!(
            read_bounded_line(&mut oversized, 5).await,
            Err(LineReadError::TooLong)
        );
    }

    #[test]
    fn encoder_counts_the_newline_in_the_bound() {
        assert!(encode_line(&serde_json::json!({"id": 1}), 9).is_ok());
        assert!(encode_line(&serde_json::json!({"id": 1}), 8).is_err());
    }
}
