use bytes::{Bytes, BytesMut};

/// Defines the direction of the gRPC message stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcDirection {
    /// Request flowing from the client to the upstream server.
    ClientToUpstream,
    /// Response flowing from the upstream server back to the client.
    UpstreamToClient,
}

/// Represents a single length-prefixed gRPC message payload.
#[derive(Debug, Clone)]
pub struct GrpcMessage {
    /// Whether the message is compressed, indicated by the first byte of the Length-Prefixed-Message header.
    pub compressed: bool,
    /// The actual message payload (compressed or uncompressed, depending on flags).
    pub payload: Bytes,
}

/// Actions a middleware can take after intercepting a gRPC message.
#[derive(Debug)]
pub enum GrpcMessageAction {
    /// Forward the message along the processing chain. It can be potentially modified.
    Forward(GrpcMessage),
    /// Silently drop the message, meaning it won't reach its intended destination.
    Drop,
    /// Return an immediate gRPC error to the client with the specified status code and message.
    Error(u32, String),
}

/// Parses a single gRPC message out of a `BytesMut` buffer.
/// Returns `Ok(Some(message))` if a full message is available, consuming those bytes from the buffer.
/// Returns `Ok(None)` if more data is needed to complete the next message.
/// Returns `Err(String)` if the message exceeds `max_size` (if provided).
pub fn parse_grpc_message(
    buf: &mut BytesMut,
    max_size: Option<usize>,
) -> Result<Option<GrpcMessage>, String> {
    if buf.len() < 5 {
        return Ok(None);
    }

    let compressed_flag = buf[0];
    let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    if let Some(max) = max_size {
        if length > max {
            return Err(format!(
                "gRPC message size {} exceeds maximum allowed {}",
                length, max
            ));
        }
    }

    if buf.len() < 5 + length {
        return Ok(None);
    }

    // We have a full message
    let compressed = compressed_flag == 1;

    // Discard the 5-byte header
    let _ = buf.split_to(5);

    // Extract the payload
    let payload = buf.split_to(length).freeze();

    Ok(Some(GrpcMessage {
        compressed,
        payload,
    }))
}

/// Encodes a `GrpcMessage` back into length-prefixed bytes.
pub fn encode_grpc_message(msg: &GrpcMessage) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + msg.payload.len());
    let compressed_flag: u8 = if msg.compressed { 1 } else { 0 };
    out.extend_from_slice(&[compressed_flag]);
    out.extend_from_slice(&(msg.payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&msg.payload);
    out.freeze()
}
