use homa::consensus::leader::record_slot_observation;
use homa::core::block::{Block, BlockHeader, HASH_LENGTH};
use homa::core::fork_choice::{ForkPreference, reconcile_partition};
use homa::core::state::ChainState;
use homa::core::sync::{compute_sync_lag, record_sync_lag};
use homa::core::transaction::Transaction;
use homa::crypto::address::{Network, derive_address};
use homa::crypto::keys::Keypair;
use homa::observability::Observability;

#[derive(Debug)]
struct SimNode {
    state: ChainState,
    chain: Vec<Block>,
    tip_hash: [u8; 32],
    observability: Observability,
}

impl SimNode {
    fn new(network: Network, allocations: Vec<(String, u64)>) -> Self {
        let mut state = ChainState::new(network);
        let initialized = state.initialize_genesis(allocations);
        assert!(initialized.is_ok(), "genesis state should initialize");

        Self {
            state,
            chain: Vec::new(),
            tip_hash: [0_u8; 32],
            observability: Observability::new(256),
        }
    }

    fn height(&self) -> u64 {
        self.chain.last().map_or(0, |block| block.header.height)
    }

    fn produce_block(
        &mut self,
        proposer: &str,
        transactions: Vec<Transaction>,
        timestamp_unix_ms: u64,
    ) -> Block {
        let height = self.height().saturating_add(1);

        let provisional_header = BlockHeader::new(
            height,
            self.tip_hash,
            [0_u8; HASH_LENGTH],
            timestamp_unix_ms,
            proposer.to_owned(),
        );
        let provisional = Block::new_unsigned(provisional_header, transactions.clone());
        assert!(provisional.is_ok(), "provisional block should construct");
        let provisional = provisional.unwrap_or_else(|_| unreachable!());

        let mut projected_state = self.state.clone();
        let projected_apply = projected_state.apply_block(&provisional);
        assert!(projected_apply.is_ok(), "projected state should apply");
        let projected_root = projected_state.state_root();

        let final_header = BlockHeader::new(
            height,
            self.tip_hash,
            projected_root,
            timestamp_unix_ms,
            proposer.to_owned(),
        );
        let block = Block::new_unsigned(final_header, transactions);
        assert!(block.is_ok(), "final block should construct");
        let block = block.unwrap_or_else(|_| unreachable!());

        let applied = self.state.apply_block(&block);
        assert!(applied.is_ok(), "local block should apply");
        let hashed = block.hash();
        assert!(hashed.is_ok(), "block hash should compute");
        self.tip_hash = hashed.unwrap_or_else(|_| unreachable!());
        self.chain.push(block.clone());
        block
    }

    fn apply_external_block(&mut self, block: &Block) {
        assert_eq!(
            block.header.previous_block_hash, self.tip_hash,
            "external block must link to local tip"
        );
        assert_eq!(
            block.header.height,
            self.height().saturating_add(1),
            "external block height should increment by one"
        );
        let applied = self.state.apply_block(block);
        assert!(applied.is_ok(), "external block should apply");
        let hashed = block.hash();
        assert!(hashed.is_ok(), "external block hash should compute");
        self.tip_hash = hashed.unwrap_or_else(|_| unreachable!());
        self.chain.push(block.clone());
    }

    fn adopt_chain(&mut self, chain: &[Block]) {
        self.chain = chain.to_vec();
        self.tip_hash = self.chain.last().map_or([0_u8; 32], |block| {
            let hashed = block.hash();
            assert!(hashed.is_ok(), "adopted tip hash should compute");
            hashed.unwrap_or_else(|_| unreachable!())
        });
    }
}

fn deterministic_address(network: Network, seed: u8) -> String {
    let keypair_result = Keypair::from_secret_key(&[seed; 32]);
    assert!(keypair_result.is_ok(), "seeded keypair should be valid");
    let keypair = keypair_result.unwrap_or_else(|_| unreachable!());
    let derived = derive_address(&keypair.public_key_bytes(), network);
    assert!(derived.is_ok(), "address derivation should succeed");
    derived.unwrap_or_else(|_| unreachable!())
}

fn transfer(
    network: Network,
    sender_seed: u8,
    sender: &str,
    receiver: &str,
    nonce: u64,
    fee: u64,
) -> Transaction {
    let keypair_result = Keypair::from_secret_key(&[sender_seed; 32]);
    assert!(keypair_result.is_ok(), "seeded keypair should be valid");
    let keypair = keypair_result.unwrap_or_else(|_| unreachable!());

    let unsigned =
        Transaction::new_unsigned(sender.to_owned(), receiver.to_owned(), 25, fee, nonce, 0)
            .with_sender_public_key(keypair.public_key_bytes());
    let signing_bytes = unsigned.signing_bytes_for_network(network);
    assert!(
        signing_bytes.is_ok(),
        "chaos transfer signing bytes should encode"
    );
    unsigned.with_signature(keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
}

fn base_allocations(network: Network) -> (Vec<(String, u64)>, String, String, String, String) {
    let proposer_a = deterministic_address(network, 1);
    let proposer_b = deterministic_address(network, 2);
    let sender = deterministic_address(network, 3);
    let receiver = deterministic_address(network, 4);

    let allocations = vec![
        (sender.clone(), 1_000_000),
        (receiver.clone(), 0),
        (proposer_a.clone(), 0),
        (proposer_b.clone(), 0),
    ];
    (allocations, proposer_a, proposer_b, sender, receiver)
}

#[test]
fn delayed_links_eventually_converge_and_sync_lag_recovers() {
    let network = Network::Testnet;
    let (allocations, proposer_a, _, sender, receiver) = base_allocations(network);
    let mut node_a = SimNode::new(network, allocations.clone());
    let mut node_b = SimNode::new(network, allocations);
    let mut delayed_queue = Vec::<(u64, Block)>::new();

    for slot in 1_u64..=4_u64 {
        let block = node_a.produce_block(
            &proposer_a,
            vec![transfer(network, 3, &sender, &receiver, slot, 1)],
            1_950_000_000_000 + slot,
        );
        delayed_queue.push((slot.saturating_add(2), block));

        let _ = record_slot_observation(&node_b.observability, slot, &proposer_a, None);
        let _ = record_sync_lag(&node_b.observability, node_b.height(), node_a.height());

        let mut ready = Vec::new();
        let mut pending = Vec::new();
        let queued = std::mem::take(&mut delayed_queue);
        for (deliver_at, queued_block) in queued {
            if deliver_at <= slot {
                ready.push(queued_block);
            } else {
                pending.push((deliver_at, queued_block));
            }
        }
        delayed_queue = pending;

        for delivered in ready {
            node_b.apply_external_block(&delivered);
        }
    }

    let mut remainder = delayed_queue;
    remainder.sort_by_key(|(deliver_at, _)| *deliver_at);
    for (_, block) in remainder {
        node_b.apply_external_block(&block);
    }

    let lag = record_sync_lag(&node_b.observability, node_b.height(), node_a.height());
    assert_eq!(lag, 0, "node should have zero lag after delayed delivery");
    assert_eq!(
        compute_sync_lag(node_b.height(), node_a.height()),
        0,
        "helper lag computation should be zero after convergence"
    );
    assert_eq!(
        node_b.state.state_root(),
        node_a.state.state_root(),
        "both nodes must converge to same final state root"
    );
    assert!(
        node_b.observability.slot_miss_total() >= 1,
        "delay phase should register at least one slot miss"
    );
}

#[test]
fn temporary_partition_reconciles_three_nodes_to_single_state() {
    let network = Network::Testnet;
    let (allocations, proposer_a, proposer_b, sender, receiver) = base_allocations(network);
    let mut node_a = SimNode::new(network, allocations.clone());
    let mut node_b = SimNode::new(network, allocations.clone());
    let mut node_c = SimNode::new(network, allocations);
    let pre_fork_state = node_a.state.clone();

    let mut local_branch = Vec::new();
    for nonce in 1_u64..=2_u64 {
        let block = node_a.produce_block(
            &proposer_a,
            vec![transfer(network, 3, &sender, &receiver, nonce, 1)],
            1_960_000_000_000 + nonce,
        );
        node_c.apply_external_block(&block);
        local_branch.push(block);
    }

    let mut remote_branch = Vec::new();
    for nonce in 1_u64..=3_u64 {
        let block = node_b.produce_block(
            &proposer_b,
            vec![transfer(network, 3, &sender, &receiver, nonce, 2)],
            1_960_000_010_000 + nonce,
        );
        remote_branch.push(block);
    }

    let lag_before = record_sync_lag(&node_c.observability, node_c.height(), node_b.height());
    assert_eq!(
        lag_before, 1,
        "partitioned follower should lag by one block"
    );

    let reconciled_a = reconcile_partition(&pre_fork_state, &local_branch, &remote_branch);
    let reconciled_b = reconcile_partition(&pre_fork_state, &remote_branch, &local_branch);
    let reconciled_c = reconcile_partition(&pre_fork_state, &local_branch, &remote_branch);
    assert!(reconciled_a.is_ok(), "node A reconciliation should succeed");
    assert!(reconciled_b.is_ok(), "node B reconciliation should succeed");
    assert!(reconciled_c.is_ok(), "node C reconciliation should succeed");
    let reconciled_a = reconciled_a.unwrap_or_else(|_| unreachable!());
    let reconciled_b = reconciled_b.unwrap_or_else(|_| unreachable!());
    let reconciled_c = reconciled_c.unwrap_or_else(|_| unreachable!());

    assert_eq!(reconciled_a.preference, ForkPreference::SwitchToRemote);
    assert_eq!(reconciled_b.preference, ForkPreference::KeepLocal);
    assert_eq!(reconciled_c.preference, ForkPreference::SwitchToRemote);

    node_a.state = reconciled_a.resulting_state;
    node_b.state = reconciled_b.resulting_state;
    node_c.state = reconciled_c.resulting_state;

    let chain_for_a = if reconciled_a.preference == ForkPreference::KeepLocal {
        &local_branch
    } else {
        &remote_branch
    };
    let chain_for_b = if reconciled_b.preference == ForkPreference::KeepLocal {
        &remote_branch
    } else {
        &local_branch
    };
    let chain_for_c = if reconciled_c.preference == ForkPreference::KeepLocal {
        &local_branch
    } else {
        &remote_branch
    };
    node_a.adopt_chain(chain_for_a);
    node_b.adopt_chain(chain_for_b);
    node_c.adopt_chain(chain_for_c);

    let lag_after = record_sync_lag(&node_c.observability, node_c.height(), node_b.height());
    assert_eq!(
        lag_after, 0,
        "lag must be zero after partition heal + re-sync"
    );

    assert_eq!(
        node_a.state.state_root(),
        node_b.state.state_root(),
        "node A and B must converge after reconciliation"
    );
    assert_eq!(
        node_b.state.state_root(),
        node_c.state.state_root(),
        "all three nodes must converge to one deterministic state root"
    );
}
