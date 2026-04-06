#![no_main]

use homa::network::p2p::decode_transaction_gossip_payload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_transaction_gossip_payload(data);
});
