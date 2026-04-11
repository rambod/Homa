use homa::core::block::{Block, BlockHeader, HASH_LENGTH};
use homa::core::fork_choice::{ForkPreference, reconcile_partition};
use homa::core::state::ChainState;
use homa::core::sync::record_sync_lag;
use homa::core::transaction::Transaction;
use homa::crypto::address::{Network, derive_address};
use homa::crypto::keys::Keypair;
use homa::observability::Observability;

const PROPOSER_A_SEED: u8 = 1;
const PROPOSER_B_SEED: u8 = 2;
const SENDER_SEED: u8 = 3;
const RECEIVER_SEED: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChaosRunSummary {
    seed: u64,
    slots: u64,
    produced_on_a: usize,
    produced_on_b: usize,
    delivered_to_c: usize,
    dropped_before_delivery: usize,
    rejected_on_delivery: usize,
    reorder_batches: usize,
    max_observed_lag: u64,
    pre_reconcile_height: u64,
    final_height: u64,
    final_sync_lag: u64,
    final_state_root: [u8; 32],
    winner: ForkPreference,
}

#[derive(Debug, Clone)]
struct QueuedBlock {
    deliver_at: u64,
    block: Block,
}

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
            observability: Observability::new(1024),
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
        let applied = projected_state.apply_block(&provisional);
        assert!(applied.is_ok(), "projected state should apply");

        let final_header = BlockHeader::new(
            height,
            self.tip_hash,
            projected_state.state_root(),
            timestamp_unix_ms,
            proposer.to_owned(),
        );
        let block = Block::new_unsigned(final_header, transactions);
        assert!(block.is_ok(), "final block should construct");
        let block = block.unwrap_or_else(|_| unreachable!());

        let finalized = self.state.apply_block(&block);
        assert!(finalized.is_ok(), "local block should apply");
        let hash = block.hash();
        assert!(hash.is_ok(), "block hash should compute");
        self.tip_hash = hash.unwrap_or_else(|_| unreachable!());
        self.chain.push(block.clone());
        block
    }

    fn apply_external_block(&mut self, block: &Block) -> bool {
        if block.header.previous_block_hash != self.tip_hash {
            return false;
        }
        if block.header.height != self.height().saturating_add(1) {
            return false;
        }
        if self.state.apply_block(block).is_err() {
            return false;
        }
        let hash = block.hash();
        if hash.is_err() {
            return false;
        }
        self.tip_hash = hash.unwrap_or_else(|_| unreachable!());
        self.chain.push(block.clone());
        true
    }

    fn adopt_reconciled(&mut self, branch: &[Block], resulting_state: ChainState) {
        self.state = resulting_state;
        self.chain = branch.to_vec();
        self.tip_hash = self.chain.last().map_or([0_u8; 32], |block| {
            let hash = block.hash();
            assert!(hash.is_ok(), "adopted tip hash should compute");
            hash.unwrap_or_else(|_| unreachable!())
        });
    }
}

#[derive(Debug, Clone, Copy)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    const fn new(seed: u64) -> Self {
        let normalized = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state: normalized }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    const fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    fn next_index(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive <= 1 {
            return 0;
        }
        let upper = u64::try_from(upper_exclusive).unwrap_or_else(|_| unreachable!());
        let sampled = self.next_u64() % upper;
        usize::try_from(sampled).unwrap_or_else(|_| unreachable!())
    }

    fn chance_per_thousand(&mut self, per_thousand: u16) -> bool {
        (self.next_u64() % 1000) < u64::from(per_thousand)
    }

    const fn range_u64(&mut self, upper_inclusive: u64) -> u64 {
        if upper_inclusive == 0 {
            return 0;
        }
        self.next_u64() % upper_inclusive.saturating_add(1)
    }
}

fn deterministic_address(network: Network, seed: u8) -> String {
    let keypair_result = Keypair::from_secret_key(&[seed; 32]);
    assert!(keypair_result.is_ok(), "seeded keypair should be valid");
    let keypair = keypair_result.unwrap_or_else(|_| unreachable!());
    let address_result = derive_address(&keypair.public_key_bytes(), network);
    assert!(address_result.is_ok(), "address derivation should succeed");
    address_result.unwrap_or_else(|_| unreachable!())
}

fn signed_transfer(
    network: Network,
    sender: &str,
    receiver: &str,
    nonce: u64,
    amount: u64,
    fee: u64,
) -> Transaction {
    let sender_keypair_result = Keypair::from_secret_key(&[SENDER_SEED; 32]);
    assert!(
        sender_keypair_result.is_ok(),
        "sender keypair should be valid"
    );
    let sender_keypair = sender_keypair_result.unwrap_or_else(|_| unreachable!());

    let unsigned = Transaction::new_unsigned(
        sender.to_owned(),
        receiver.to_owned(),
        amount,
        fee,
        nonce,
        0,
    )
    .with_sender_public_key(sender_keypair.public_key_bytes());
    let signing_bytes = unsigned.signing_bytes_for_network(network);
    assert!(
        signing_bytes.is_ok(),
        "transfer signing bytes should encode"
    );
    unsigned.with_signature(sender_keypair.sign(&signing_bytes.unwrap_or_else(|_| unreachable!())))
}

fn base_allocations(network: Network) -> (Vec<(String, u64)>, String, String, String, String) {
    let proposer_a = deterministic_address(network, PROPOSER_A_SEED);
    let proposer_b = deterministic_address(network, PROPOSER_B_SEED);
    let sender = deterministic_address(network, SENDER_SEED);
    let receiver = deterministic_address(network, RECEIVER_SEED);

    let allocations = vec![
        (sender.clone(), 5_000_000),
        (receiver.clone(), 0),
        (proposer_a.clone(), 0),
        (proposer_b.clone(), 0),
    ];
    (allocations, proposer_a, proposer_b, sender, receiver)
}

const fn choose_branch<'a>(
    local: &'a [Block],
    remote: &'a [Block],
    preference: ForkPreference,
) -> &'a [Block] {
    match preference {
        ForkPreference::KeepLocal => local,
        ForkPreference::SwitchToRemote => remote,
    }
}

const fn drop_rate_per_thousand(in_partition: bool, produced_on_a: bool) -> u16 {
    if !in_partition {
        return 120;
    }
    if produced_on_a { 700 } else { 450 }
}

fn enqueue_delivery(
    queue: &mut Vec<QueuedBlock>,
    rng: &mut DeterministicRng,
    slot: u64,
    block: &Block,
    in_partition: bool,
    produced_on_a: bool,
    dropped_before_delivery: &mut usize,
) {
    if rng.chance_per_thousand(drop_rate_per_thousand(in_partition, produced_on_a)) {
        *dropped_before_delivery = dropped_before_delivery.saturating_add(1);
        return;
    }

    let max_delay = if in_partition { 6 } else { 2 };
    queue.push(QueuedBlock {
        deliver_at: slot.saturating_add(rng.range_u64(max_delay)),
        block: block.clone(),
    });
}

fn shuffle_due_blocks(due: &mut [QueuedBlock], rng: &mut DeterministicRng) {
    if due.len() < 2 {
        return;
    }
    let mut index = due.len();
    while index > 1 {
        index -= 1;
        let swap_with = rng.next_index(index + 1);
        due.swap(index, swap_with);
    }
}

fn deliver_due_blocks(
    node_c: &mut SimNode,
    queue: &mut Vec<QueuedBlock>,
    slot: u64,
    rng: &mut DeterministicRng,
    delivered_to_c: &mut usize,
    rejected_on_delivery: &mut usize,
    reorder_batches: &mut usize,
) {
    let mut due = Vec::new();
    let mut pending = Vec::new();

    for queued in std::mem::take(queue) {
        if queued.deliver_at <= slot {
            due.push(queued);
        } else {
            pending.push(queued);
        }
    }
    *queue = pending;

    if due.len() > 1 && rng.next_bool() {
        shuffle_due_blocks(&mut due, rng);
        *reorder_batches = reorder_batches.saturating_add(1);
    }

    for queued in due {
        if node_c.apply_external_block(&queued.block) {
            *delivered_to_c = delivered_to_c.saturating_add(1);
        } else {
            *rejected_on_delivery = rejected_on_delivery.saturating_add(1);
        }
    }
}

#[derive(Debug)]
struct ChaosEnv {
    network: Network,
    proposer_a: String,
    proposer_b: String,
    sender: String,
    receiver: String,
    node_a: SimNode,
    node_b: SimNode,
    node_c: SimNode,
    pre_fork_state: ChainState,
    rng: DeterministicRng,
    branch_a: Vec<Block>,
    branch_b: Vec<Block>,
    queue: Vec<QueuedBlock>,
    nonce_a: u64,
    nonce_b: u64,
    produced_on_a: usize,
    produced_on_b: usize,
    delivered_to_c: usize,
    dropped_before_delivery: usize,
    rejected_on_delivery: usize,
    reorder_batches: usize,
    max_observed_lag: u64,
}

impl ChaosEnv {
    fn new(seed: u64) -> Self {
        let network = Network::Testnet;
        let (allocations, proposer_a, proposer_b, sender, receiver) = base_allocations(network);
        let node_a = SimNode::new(network, allocations.clone());
        let node_b = SimNode::new(network, allocations.clone());
        let node_c = SimNode::new(network, allocations);
        let pre_fork_state = node_a.state.clone();

        Self {
            network,
            proposer_a,
            proposer_b,
            sender,
            receiver,
            node_a,
            node_b,
            node_c,
            pre_fork_state,
            rng: DeterministicRng::new(seed),
            branch_a: Vec::new(),
            branch_b: Vec::new(),
            queue: Vec::new(),
            nonce_a: 1,
            nonce_b: 1,
            produced_on_a: 0,
            produced_on_b: 0,
            delivered_to_c: 0,
            dropped_before_delivery: 0,
            rejected_on_delivery: 0,
            reorder_batches: 0,
            max_observed_lag: 0,
        }
    }

    fn bootstrap_branches(&mut self) {
        let initial_a = self.node_a.produce_block(
            &self.proposer_a,
            vec![signed_transfer(
                self.network,
                &self.sender,
                &self.receiver,
                self.nonce_a,
                10,
                1,
            )],
            2_150_000_000_000,
        );
        self.branch_a.push(initial_a);
        self.nonce_a = self.nonce_a.saturating_add(1);
        self.produced_on_a = self.produced_on_a.saturating_add(1);

        let initial_b = self.node_b.produce_block(
            &self.proposer_b,
            vec![signed_transfer(
                self.network,
                &self.sender,
                &self.receiver,
                self.nonce_b,
                10,
                2,
            )],
            2_150_000_000_001,
        );
        self.branch_b.push(initial_b);
        self.nonce_b = self.nonce_b.saturating_add(1);
        self.produced_on_b = self.produced_on_b.saturating_add(1);
    }

    fn run_slot(&mut self, slot: u64, slots: u64) {
        let in_partition = slot > (slots / 3) && slot <= ((slots * 2) / 3);
        let choose_branch_a = self.rng.next_bool();
        let fee = 1_u64.saturating_add(self.rng.range_u64(3));
        let amount = 5_u64.saturating_add(self.rng.range_u64(10));

        let block = if choose_branch_a {
            let block = self.node_a.produce_block(
                &self.proposer_a,
                vec![signed_transfer(
                    self.network,
                    &self.sender,
                    &self.receiver,
                    self.nonce_a,
                    amount,
                    fee,
                )],
                2_150_000_001_000_u64.saturating_add(slot),
            );
            self.nonce_a = self.nonce_a.saturating_add(1);
            self.branch_a.push(block.clone());
            self.produced_on_a = self.produced_on_a.saturating_add(1);
            block
        } else {
            let block = self.node_b.produce_block(
                &self.proposer_b,
                vec![signed_transfer(
                    self.network,
                    &self.sender,
                    &self.receiver,
                    self.nonce_b,
                    amount,
                    fee,
                )],
                2_150_000_101_000_u64.saturating_add(slot),
            );
            self.nonce_b = self.nonce_b.saturating_add(1);
            self.branch_b.push(block.clone());
            self.produced_on_b = self.produced_on_b.saturating_add(1);
            block
        };

        enqueue_delivery(
            &mut self.queue,
            &mut self.rng,
            slot,
            &block,
            in_partition,
            choose_branch_a,
            &mut self.dropped_before_delivery,
        );
        deliver_due_blocks(
            &mut self.node_c,
            &mut self.queue,
            slot,
            &mut self.rng,
            &mut self.delivered_to_c,
            &mut self.rejected_on_delivery,
            &mut self.reorder_batches,
        );
        self.update_sync_lag();
    }

    fn drain_delivery_queue(&mut self, slots: u64) {
        let mut drain_slot = slots;
        while !self.queue.is_empty() && drain_slot < slots.saturating_add(16) {
            drain_slot = drain_slot.saturating_add(1);
            deliver_due_blocks(
                &mut self.node_c,
                &mut self.queue,
                drain_slot,
                &mut self.rng,
                &mut self.delivered_to_c,
                &mut self.rejected_on_delivery,
                &mut self.reorder_batches,
            );
            self.update_sync_lag();
        }
    }

    fn update_sync_lag(&mut self) {
        let target_height = self.node_a.height().max(self.node_b.height());
        let lag = record_sync_lag(
            &self.node_c.observability,
            self.node_c.height(),
            target_height,
        );
        self.max_observed_lag = self.max_observed_lag.max(lag);
    }

    fn reconcile(self, seed: u64, slots: u64) -> ChaosRunSummary {
        let mut node_a = self.node_a;
        let mut node_b = self.node_b;
        let mut node_c = self.node_c;
        let pre_reconcile_height = node_c.height();

        let reconciled_a =
            reconcile_partition(&self.pre_fork_state, &self.branch_a, &self.branch_b);
        let reconciled_b =
            reconcile_partition(&self.pre_fork_state, &self.branch_b, &self.branch_a);
        let reconciled_c =
            reconcile_partition(&self.pre_fork_state, &self.branch_a, &self.branch_b);
        assert!(reconciled_a.is_ok(), "node A reconciliation should succeed");
        assert!(reconciled_b.is_ok(), "node B reconciliation should succeed");
        assert!(reconciled_c.is_ok(), "node C reconciliation should succeed");
        let reconciled_a = reconciled_a.unwrap_or_else(|_| unreachable!());
        let reconciled_b = reconciled_b.unwrap_or_else(|_| unreachable!());
        let reconciled_c = reconciled_c.unwrap_or_else(|_| unreachable!());

        let chain_a = choose_branch(&self.branch_a, &self.branch_b, reconciled_a.preference);
        let chain_b = choose_branch(&self.branch_b, &self.branch_a, reconciled_b.preference);
        let chain_c = choose_branch(&self.branch_a, &self.branch_b, reconciled_c.preference);
        node_a.adopt_reconciled(chain_a, reconciled_a.resulting_state);
        node_b.adopt_reconciled(chain_b, reconciled_b.resulting_state);
        node_c.adopt_reconciled(chain_c, reconciled_c.resulting_state);

        let final_height = node_a.height();
        assert_eq!(
            node_b.height(),
            final_height,
            "all nodes should converge to one height after reconciliation"
        );
        assert_eq!(
            node_c.height(),
            final_height,
            "all nodes should converge to one height after reconciliation"
        );
        assert_eq!(
            node_a.state.state_root(),
            node_b.state.state_root(),
            "node A/B state roots should match after reconciliation"
        );
        assert_eq!(
            node_b.state.state_root(),
            node_c.state.state_root(),
            "node B/C state roots should match after reconciliation"
        );

        let final_sync_lag = record_sync_lag(
            &node_c.observability,
            node_c.height(),
            node_a.height().max(node_b.height()),
        );
        assert_eq!(
            final_sync_lag, 0,
            "sync lag should return to zero after partition heal and reconciliation"
        );

        ChaosRunSummary {
            seed,
            slots,
            produced_on_a: self.produced_on_a,
            produced_on_b: self.produced_on_b,
            delivered_to_c: self.delivered_to_c,
            dropped_before_delivery: self.dropped_before_delivery,
            rejected_on_delivery: self.rejected_on_delivery,
            reorder_batches: self.reorder_batches,
            max_observed_lag: self.max_observed_lag,
            pre_reconcile_height,
            final_height,
            final_sync_lag,
            final_state_root: node_a.state.state_root(),
            winner: reconciled_a.preference,
        }
    }
}

fn simulate_partition_chaos(seed: u64, slots: u64) -> ChaosRunSummary {
    let mut env = ChaosEnv::new(seed);
    env.bootstrap_branches();
    for slot in 1_u64..=slots {
        env.run_slot(slot, slots);
    }
    env.drain_delivery_queue(slots);
    env.reconcile(seed, slots)
}

#[test]
fn partition_chaos_seed_replay_is_deterministic() {
    let first = simulate_partition_chaos(1_337, 48);
    let second = simulate_partition_chaos(1_337, 48);
    assert_eq!(
        first, second,
        "running with the same seed should produce identical deterministic summary"
    );
}

#[test]
fn partition_chaos_fuzzer_converges_across_seed_matrix() {
    let seeds = [3_u64, 7_u64, 42_u64, 99_u64, 512_u64, 2_026_u64, 65_535_u64];
    for seed in seeds {
        let summary = simulate_partition_chaos(seed, 40);
        assert!(
            summary.produced_on_a > 0 && summary.produced_on_b > 0,
            "both branches must receive traffic in fuzz run"
        );
        assert!(
            summary.max_observed_lag >= summary.final_sync_lag,
            "max lag should dominate final lag in summary"
        );
        assert!(
            summary.final_height > 0,
            "fuzz run should produce non-empty winning branch"
        );
    }
}

#[test]
fn partition_chaos_soak_meets_operational_slos() {
    let seeds = [11_u64, 29_u64, 101_u64];
    let slots = 180_u64;
    for seed in seeds {
        let summary = simulate_partition_chaos(seed, slots);
        let produced_total = summary.produced_on_a.saturating_add(summary.produced_on_b);

        assert_eq!(
            summary.final_sync_lag, 0,
            "soak run must converge to zero lag (seed={seed})"
        );
        assert!(
            summary.final_height >= (slots / 3),
            "winning branch should retain sufficient throughput under soak load (seed={seed})"
        );
        assert!(
            summary.max_observed_lag >= 1,
            "partition window should manifest non-zero lag before reconciliation (seed={seed})"
        );
        assert!(
            summary
                .delivered_to_c
                .saturating_add(summary.dropped_before_delivery)
                > 0,
            "soak run should exercise delivery/drop paths before reconciliation (seed={seed})"
        );
        assert!(
            summary.produced_on_a > 0 && summary.produced_on_b > 0,
            "soak run should produce blocks on both fork branches (seed={seed})"
        );
        assert!(
            summary.rejected_on_delivery <= produced_total,
            "rejected deliveries should stay bounded by produced traffic volume (seed={seed})"
        );
    }
}
