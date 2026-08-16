//! Length-prefixed framing for the control stream.
//!
//! QUIC gives us a reliable ordered byte stream, not messages, so frames carry
//! their own length: a little-endian `u32` followed by that many [`postcard`]
//! bytes. The prefix is checked against [`MAX_FRAME_LEN`] *before* allocating,
//! so a hostile peer cannot make us reserve gigabytes by lying about a length.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound on a single control frame. Generous for text and channel lists,
/// small enough that a bogus prefix cannot exhaust memory.
pub const MAX_FRAME_LEN: u32 = 1 << 20;

const LEN_PREFIX_LEN: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("control stream i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not encode control frame: {0}")]
    Encode(#[source] postcard::Error),
    #[error("could not decode control frame: {0}")]
    Decode(#[source] postcard::Error),
    #[error("control frame of {len} bytes exceeds the {max} byte limit")]
    FrameTooLarge { len: u32, max: u32 },
    #[error("peer closed the control stream")]
    Closed,
}

impl CodecError {
    /// True when the peer hung up cleanly, which is normal at shutdown and
    /// should not be logged as an error.
    pub fn is_clean_close(&self) -> bool {
        matches!(self, CodecError::Closed)
    }
}

/// Write one frame.
///
/// The prefix and payload go out in a single `write_all`, so a frame is never
/// left half-written behind another writer's bytes.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), CodecError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = postcard::to_stdvec(message).map_err(CodecError::Encode)?;
    if payload.len() > MAX_FRAME_LEN as usize {
        return Err(CodecError::FrameTooLarge {
            len: payload.len() as u32,
            max: MAX_FRAME_LEN,
        });
    }

    let mut framed = Vec::with_capacity(LEN_PREFIX_LEN + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(&payload);
    writer.write_all(&framed).await?;
    Ok(())
}

/// Read one frame, waiting for it to arrive in full.
///
/// Returns [`CodecError::Closed`] when the peer shuts the stream down at a
/// frame boundary; a truncation mid-frame surfaces as an I/O error instead,
/// because those two cases warrant different handling.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, CodecError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_bytes = [0u8; LEN_PREFIX_LEN];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(CodecError::Closed),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_FRAME_LEN {
        return Err(CodecError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    postcard::from_bytes(&payload).map_err(CodecError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientControl, ErrorCode, ServerControl};

    #[tokio::test]
    async fn frames_roundtrip_in_order() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &ClientControl::Ping { nonce: 1 })
            .await
            .unwrap();
        write_frame(&mut buf, &ClientControl::LeaveChannel)
            .await
            .unwrap();
        write_frame(&mut buf, &ClientControl::Ping { nonce: 2 })
            .await
            .unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let a: ClientControl = read_frame(&mut cursor).await.unwrap();
        let b: ClientControl = read_frame(&mut cursor).await.unwrap();
        let c: ClientControl = read_frame(&mut cursor).await.unwrap();

        assert!(matches!(a, ClientControl::Ping { nonce: 1 }));
        assert!(matches!(b, ClientControl::LeaveChannel));
        assert!(matches!(c, ClientControl::Ping { nonce: 2 }));
    }

    #[tokio::test]
    async fn a_clean_close_at_a_frame_boundary_is_distinguishable() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let result: Result<ClientControl, _> = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::Closed)));
        assert!(result.unwrap_err().is_clean_close());
    }

    #[tokio::test]
    async fn a_truncated_frame_is_an_io_error_not_a_clean_close() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &ClientControl::Ping { nonce: 7 })
            .await
            .unwrap();
        buf.truncate(buf.len() - 1);

        let mut cursor = std::io::Cursor::new(buf);
        let result: Result<ClientControl, _> = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::Io(_))));
    }

    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused_before_allocating() {
        // The defence against a peer claiming a 4 GiB frame.
        let mut buf = (MAX_FRAME_LEN + 1).to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]);

        let mut cursor = std::io::Cursor::new(buf);
        let result: Result<ClientControl, _> = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::FrameTooLarge { .. })));
    }

    #[tokio::test]
    async fn garbage_payload_fails_to_decode_without_panicking() {
        let mut buf = 4u32.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);

        let mut cursor = std::io::Cursor::new(buf);
        let result: Result<ClientControl, _> = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(CodecError::Decode(_))));
    }

    #[tokio::test]
    async fn server_frames_roundtrip_too() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(
            &mut buf,
            &ServerControl::Error {
                code: ErrorCode::RateLimited,
                detail: "slow down".into(),
            },
        )
        .await
        .unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let back: ServerControl = read_frame(&mut cursor).await.unwrap();
        assert!(matches!(
            back,
            ServerControl::Error {
                code: ErrorCode::RateLimited,
                ..
            }
        ));
    }
}
