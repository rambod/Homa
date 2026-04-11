#![no_main]

use homa::core::block::Block;
use homa::network::p2p::validate_block_gossip_payload_bounds;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if validate_block_gossip_payload_bounds(data).is_err() {
        return;
    }
    let decoded = Block::decode(data);
    if let Ok(block) = decoded {
        let _ = block.validate_basic();
    }
});
