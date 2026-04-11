#![no_main]

use homa::network::p2p::{
    decode_snapshot_chunk_request, decode_snapshot_chunk_response, decode_sync_wire_message,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_sync_wire_message(data);
    let _ = decode_snapshot_chunk_request(data);
    let _ = decode_snapshot_chunk_response(data);
});
