//! Wallet command-line interface.

use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use argon2::Argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::consensus::pow::{PowError, leading_zero_bits, transaction_pow_hash};
use crate::core::state::MICRO_HOMA_PER_HMA;
use crate::core::transaction::{Amount, Transaction, TransactionError};
use crate::crypto::address::{AddressError, Network, derive_address, validate_address_for_network};
use crate::crypto::keys::{CryptoError, Keypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use crate::network::p2p::{BroadcastReport, NetworkError, broadcast_transaction_bytes};

const WALLET_FILE_VERSION: u8 = 1;
const WALLET_KEY_NONCE_LENGTH: usize = 12;
const WALLET_KEY_SALT_LENGTH: usize = 16;
const WALLET_KEY_DERIVATION_OUTPUT_LENGTH: usize = 32;
const DEFAULT_POW_TIME_MS: u64 = 1_500;
const DEFAULT_MIN_POW_BITS: u16 = 10;
const DEFAULT_BROADCAST_TIMEOUT_MS: u64 = 8_000;
const DEFAULT_SEED_DOMAIN: &str = "seed1.homanetwork.io";

/// Executes wallet CLI command parsing and dispatch.
pub fn run() -> Result<(), WalletCliError> {
    let cli = Cli::parse();

    match cli.command {
        TopLevelCommand::Keys(keys) => match keys.command {
            KeysCommand::Generate(args) => run_keys_generate(args),
        },
        TopLevelCommand::Tx(tx) => match tx.command {
            TxCommand::Send(args) => run_tx_send(args),
        },
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "homa-cli",
    version,
    about = "Homa wallet command-line interface"
)]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
enum TopLevelCommand {
    /// Key management commands.
    Keys(KeysArgs),
    /// Transaction commands.
    Tx(TxArgs),
}

#[derive(Debug, Args)]
struct KeysArgs {
    #[command(subcommand)]
    command: KeysCommand,
}

#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Generates and persists an encrypted wallet keypair.
    Generate(KeysGenerateArgs),
}

#[derive(Debug, Args)]
struct KeysGenerateArgs {
    /// Target network used for derived address encoding.
    #[arg(long, value_enum, default_value_t = CliNetwork::Mainnet)]
    network: CliNetwork,
    /// Wallet file path.
    #[arg(long)]
    wallet_path: Option<PathBuf>,
    /// Local wallet state path for next nonce tracking.
    #[arg(long)]
    state_path: Option<PathBuf>,
    /// Passphrase used for encryption (omit to prompt securely).
    #[arg(long, env = "HOMA_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct TxArgs {
    #[command(subcommand)]
    command: TxCommand,
}

#[derive(Debug, Subcommand)]
enum TxCommand {
    /// Builds, solves `PoW`, signs, and broadcasts a transaction.
    Send(TxSendArgs),
}

#[derive(Debug, Args)]
struct TxSendArgs {
    /// Receiver address.
    address: String,
    /// Transfer amount in HMA units (`12` or `0.125`).
    amount: String,
    /// Wallet file path.
    #[arg(long)]
    wallet_path: Option<PathBuf>,
    /// Local wallet state path for nonce tracking.
    #[arg(long)]
    state_path: Option<PathBuf>,
    /// Passphrase used for wallet unlock (omit to prompt securely).
    #[arg(long, env = "HOMA_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Network expected by sender/receiver addresses.
    #[arg(long, value_enum, default_value_t = CliNetwork::Mainnet)]
    network: CliNetwork,
    /// Explicit nonce override (otherwise local state `next_nonce` is used).
    #[arg(long)]
    nonce: Option<u64>,
    /// Fee in micro-homas.
    #[arg(long, default_value_t = 1)]
    fee_micro: u64,
    /// Minimum required `PoW` leading-zero bits.
    #[arg(long, default_value_t = DEFAULT_MIN_POW_BITS)]
    min_pow_bits: u16,
    /// Target local compute time for client-side `PoW`.
    #[arg(long, default_value_t = DEFAULT_POW_TIME_MS)]
    pow_time_ms: u64,
    /// DNS seed domain for peer discovery.
    #[arg(long, default_value = DEFAULT_SEED_DOMAIN)]
    seed_domain: String,
    /// Fallback bootstrap entries (`IP`, `IP:PORT`, or full multiaddr).
    #[arg(long = "fallback-bootstrap")]
    fallback_bootstrap: Vec<String>,
    /// Max wait time for broadcast to succeed.
    #[arg(long, default_value_t = DEFAULT_BROADCAST_TIMEOUT_MS)]
    broadcast_timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliNetwork {
    /// Main production network.
    Mainnet,
    /// Public testing network.
    Testnet,
    /// Local developer network.
    Devnet,
}

impl CliNetwork {
    #[must_use]
    const fn into_network(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Testnet => Network::Testnet,
            Self::Devnet => Network::Devnet,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedWalletFile {
    version: u8,
    network: u8,
    address: String,
    public_key: [u8; PUBLIC_KEY_LENGTH],
    salt: [u8; WALLET_KEY_SALT_LENGTH],
    nonce: [u8; WALLET_KEY_NONCE_LENGTH],
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct WalletLocalState {
    next_nonce: u64,
}

impl Default for WalletLocalState {
    fn default() -> Self {
        Self { next_nonce: 1 }
    }
}

#[derive(Debug)]
struct UnlockedWallet {
    network: Network,
    address: String,
    keypair: Keypair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PowComputation {
    nonce: u64,
    leading_zero_bits: u16,
    elapsed: Duration,
    attempts: u64,
}

/// Errors returned by CLI commands.
#[derive(Debug, Error)]
pub enum WalletCliError {
    /// Home directory is unavailable in current environment.
    #[error("unable to determine home directory")]
    HomeDirectoryUnavailable,
    /// IO error during file operations.
    #[error("file operation failed")]
    Io,
    /// Passphrase prompt failed.
    #[error("passphrase prompt failed")]
    PassphrasePrompt,
    /// Two prompted passphrases did not match.
    #[error("passphrase confirmation mismatch")]
    PassphraseMismatch,
    /// Passphrase is empty.
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    /// Wallet file has unsupported version.
    #[error("unsupported wallet file version: {0}")]
    UnsupportedWalletVersion(u8),
    /// Wallet file network byte is invalid.
    #[error("invalid wallet network byte: {0}")]
    InvalidWalletNetwork(u8),
    /// Amount string is malformed.
    #[error("invalid amount format")]
    InvalidAmountFormat,
    /// Amount value overflowed supported range.
    #[error("amount overflow")]
    AmountOverflow,
    /// Amount must be greater than zero.
    #[error("amount must be greater than zero")]
    ZeroAmount,
    /// Key derivation failed.
    #[error("wallet key derivation failed")]
    KeyDerivation,
    /// Wallet encryption failed.
    #[error("wallet encryption failed")]
    Encryption,
    /// Wallet decryption failed.
    #[error("wallet decryption failed")]
    Decryption,
    /// Wallet serialization failed.
    #[error("wallet serialization failed")]
    WalletSerialization,
    /// Wallet deserialization failed.
    #[error("wallet deserialization failed")]
    WalletDeserialization,
    /// Wallet public data does not match decrypted keypair.
    #[error("wallet integrity check failed")]
    WalletIntegrity,
    /// Provided network does not match wallet network.
    #[error("wallet network mismatch: expected {expected}, got {actual}")]
    WalletNetworkMismatch {
        /// Caller-selected network.
        expected: Network,
        /// Network encoded in wallet file.
        actual: Network,
    },
    /// Address validation failure.
    #[error("address validation failed")]
    AddressValidation {
        /// Inner address error.
        source: AddressError,
    },
    /// Crypto-level key handling failed.
    #[error("cryptographic key handling failed")]
    Crypto {
        /// Inner crypto error.
        source: CryptoError,
    },
    /// Transaction-level validation/encoding failed.
    #[error("transaction operation failed")]
    Transaction {
        /// Inner transaction error.
        source: TransactionError,
    },
    /// `PoW` computation failed.
    #[error("pow computation failed")]
    Pow {
        /// Inner pow error.
        source: PowError,
    },
    /// Network broadcast failed.
    #[error("network broadcast failed")]
    Network {
        /// Inner network error.
        source: NetworkError,
    },
    /// Runtime initialization failed.
    #[error("runtime initialization failed")]
    Runtime,
    /// Nonce override must be greater than zero.
    #[error("nonce must be greater than zero")]
    InvalidNonce,
    /// Fee arithmetic overflow.
    #[error("fee overflow")]
    FeeOverflow,
}

fn run_keys_generate(args: KeysGenerateArgs) -> Result<(), WalletCliError> {
    let network = args.network.into_network();
    let wallet_path = resolve_wallet_path(args.wallet_path.as_deref())?;
    let state_path = resolve_state_path(args.state_path.as_deref())?;
    let mut passphrase = resolve_passphrase(args.passphrase, true)?;

    let keypair = Keypair::generate();
    let public_key = keypair.public_key_bytes();
    let address = derive_address(&public_key, network)
        .map_err(|source| WalletCliError::AddressValidation { source })?;
    let encrypted = encrypt_wallet_file(&keypair, &address, network, &passphrase)?;

    let encoded = bincode::serde::encode_to_vec(
        &encrypted,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map_err(|_| WalletCliError::WalletSerialization)?;

    write_secure_file(&wallet_path, &encoded)?;
    let wallet_state = WalletLocalState::default();
    save_wallet_state(&state_path, wallet_state)?;

    passphrase.zeroize();

    println!("wallet generated");
    println!("network: {network}");
    println!("address: {address}");
    println!("wallet_path: {}", wallet_path.display());
    println!("state_path: {}", state_path.display());

    Ok(())
}

fn run_tx_send(args: TxSendArgs) -> Result<(), WalletCliError> {
    let network = args.network.into_network();
    let wallet_path = resolve_wallet_path(args.wallet_path.as_deref())?;
    let state_path = resolve_state_path(args.state_path.as_deref())?;
    let mut passphrase = resolve_passphrase(args.passphrase, false)?;

    let wallet = load_wallet(&wallet_path, &passphrase)?;
    passphrase.zeroize();

    if wallet.network != network {
        return Err(WalletCliError::WalletNetworkMismatch {
            expected: network,
            actual: wallet.network,
        });
    }

    validate_address_for_network(&args.address, network)
        .map_err(|source| WalletCliError::AddressValidation { source })?;

    let amount_micro = parse_hma_amount_to_micro(&args.amount)?;
    if amount_micro == 0 {
        return Err(WalletCliError::ZeroAmount);
    }

    let mut local_state = load_wallet_state(&state_path)?;
    let nonce = args.nonce.unwrap_or(local_state.next_nonce);
    if nonce == 0 {
        return Err(WalletCliError::InvalidNonce);
    }

    let mut transaction = Transaction::new_unsigned(
        wallet.address.clone(),
        args.address,
        amount_micro,
        args.fee_micro,
        nonce,
        0,
    )
    .with_sender_public_key(wallet.keypair.public_key_bytes());

    let pow_result = mine_pow_for_duration(
        &mut transaction,
        args.min_pow_bits,
        Duration::from_millis(args.pow_time_ms),
    )?;

    let signing_bytes = transaction
        .signing_bytes_for_network(network)
        .map_err(|source| WalletCliError::Transaction { source })?;
    let signature = wallet.keypair.sign(&signing_bytes);
    let signed_transaction = transaction.with_signature(signature);
    signed_transaction
        .validate_basic()
        .map_err(|source| WalletCliError::Transaction { source })?;

    let encoded_transaction = signed_transaction
        .encode()
        .map_err(|source| WalletCliError::Transaction { source })?;

    let fallback_refs = args
        .fallback_bootstrap
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| WalletCliError::Runtime)?;

    let report = runtime
        .block_on(broadcast_transaction_bytes(
            encoded_transaction,
            &args.seed_domain,
            &fallback_refs,
            Duration::from_millis(args.broadcast_timeout_ms),
        ))
        .map_err(|source| WalletCliError::Network { source })?;

    local_state.next_nonce = nonce.checked_add(1).ok_or(WalletCliError::FeeOverflow)?;
    save_wallet_state(&state_path, local_state)?;

    print_send_summary(&wallet.address, amount_micro, nonce, pow_result, report);

    Ok(())
}

fn print_send_summary(
    sender: &str,
    amount_micro: Amount,
    nonce: u64,
    pow: PowComputation,
    report: BroadcastReport,
) {
    println!("transaction broadcasted");
    println!("sender: {sender}");
    println!("amount_micro: {amount_micro}");
    println!("nonce: {nonce}");
    println!("pow_nonce: {}", pow.nonce);
    println!("pow_bits: {}", pow.leading_zero_bits);
    println!("pow_attempts: {}", pow.attempts);
    println!("pow_elapsed_ms: {}", pow.elapsed.as_millis());
    println!("dial_attempts: {}", report.dial_attempts);
    println!("publish_attempts: {}", report.publish_attempts);
}

fn parse_hma_amount_to_micro(input: &str) -> Result<u64, WalletCliError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(WalletCliError::InvalidAmountFormat);
    }

    let mut segments = trimmed.split('.');
    let whole_part = segments.next().ok_or(WalletCliError::InvalidAmountFormat)?;
    let fractional_part = segments.next();

    if segments.next().is_some() {
        return Err(WalletCliError::InvalidAmountFormat);
    }

    if whole_part.is_empty()
        || !whole_part
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return Err(WalletCliError::InvalidAmountFormat);
    }

    let whole = whole_part
        .parse::<u64>()
        .map_err(|_| WalletCliError::InvalidAmountFormat)?;
    let mut total = whole
        .checked_mul(MICRO_HOMA_PER_HMA)
        .ok_or(WalletCliError::AmountOverflow)?;

    if let Some(raw_fraction) = fractional_part {
        if raw_fraction.is_empty() || raw_fraction.len() > 8 {
            return Err(WalletCliError::InvalidAmountFormat);
        }
        if !raw_fraction
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            return Err(WalletCliError::InvalidAmountFormat);
        }

        let mut padded = raw_fraction.to_owned();
        while padded.len() < 8 {
            padded.push('0');
        }

        let fraction = padded
            .parse::<u64>()
            .map_err(|_| WalletCliError::InvalidAmountFormat)?;
        total = total
            .checked_add(fraction)
            .ok_or(WalletCliError::AmountOverflow)?;
    }

    Ok(total)
}

fn mine_pow_for_duration(
    transaction: &mut Transaction,
    min_pow_bits: u16,
    target_duration: Duration,
) -> Result<PowComputation, WalletCliError> {
    let start = Instant::now();
    let max_duration = target_duration.saturating_add(Duration::from_secs(20));

    let mut nonce = 0_u64;
    let mut attempts = 0_u64;
    let mut best_nonce = 0_u64;
    let mut best_bits = 0_u16;

    loop {
        transaction.pow_nonce = nonce;
        let hash =
            transaction_pow_hash(transaction).map_err(|source| WalletCliError::Pow { source })?;
        let bits = leading_zero_bits(&hash);
        attempts = attempts.saturating_add(1);

        if bits > best_bits {
            best_bits = bits;
            best_nonce = nonce;
        }

        let elapsed = start.elapsed();
        if elapsed >= target_duration && best_bits >= min_pow_bits {
            transaction.pow_nonce = best_nonce;
            return Ok(PowComputation {
                nonce: best_nonce,
                leading_zero_bits: best_bits,
                elapsed,
                attempts,
            });
        }

        if elapsed >= max_duration {
            return Err(WalletCliError::Pow {
                source: PowError::NonceExhausted,
            });
        }

        nonce = nonce.wrapping_add(1);
    }
}

fn resolve_passphrase(
    passphrase_argument: Option<String>,
    confirm: bool,
) -> Result<String, WalletCliError> {
    if let Some(passphrase) = passphrase_argument {
        if passphrase.is_empty() {
            return Err(WalletCliError::EmptyPassphrase);
        }
        return Ok(passphrase);
    }

    let passphrase = rpassword::prompt_password("Enter wallet passphrase: ")
        .map_err(|_| WalletCliError::PassphrasePrompt)?;
    if passphrase.is_empty() {
        return Err(WalletCliError::EmptyPassphrase);
    }

    if confirm {
        let confirmation = rpassword::prompt_password("Confirm wallet passphrase: ")
            .map_err(|_| WalletCliError::PassphrasePrompt)?;
        if passphrase != confirmation {
            return Err(WalletCliError::PassphraseMismatch);
        }
    }

    Ok(passphrase)
}

fn resolve_wallet_path(path: Option<&Path>) -> Result<PathBuf, WalletCliError> {
    if let Some(explicit) = path {
        return Ok(explicit.to_path_buf());
    }

    Ok(default_homa_dir()?.join("wallet.key"))
}

fn resolve_state_path(path: Option<&Path>) -> Result<PathBuf, WalletCliError> {
    if let Some(explicit) = path {
        return Ok(explicit.to_path_buf());
    }

    Ok(default_homa_dir()?.join("wallet_state.json"))
}

fn default_homa_dir() -> Result<PathBuf, WalletCliError> {
    let home = env::var_os("HOME").ok_or(WalletCliError::HomeDirectoryUnavailable)?;
    Ok(PathBuf::from(home).join(".homa"))
}

const fn network_to_byte(network: Network) -> u8 {
    network.as_byte()
}

const fn network_from_byte(byte: u8) -> Result<Network, WalletCliError> {
    match byte {
        0x01 => Ok(Network::Mainnet),
        0x02 => Ok(Network::Testnet),
        0x03 => Ok(Network::Devnet),
        _ => Err(WalletCliError::InvalidWalletNetwork(byte)),
    }
}

fn encrypt_wallet_file(
    keypair: &Keypair,
    address: &str,
    network: Network,
    passphrase: &str,
) -> Result<EncryptedWalletFile, WalletCliError> {
    let mut salt = [0_u8; WALLET_KEY_SALT_LENGTH];
    let mut nonce = [0_u8; WALLET_KEY_NONCE_LENGTH];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut wallet_key = derive_wallet_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&wallet_key).into());

    let mut secret_key = keypair.secret_key_bytes();
    let ciphertext = cipher
        .encrypt((&nonce).into(), secret_key.as_slice())
        .map_err(|_| WalletCliError::Encryption)?;

    secret_key.zeroize();
    wallet_key.zeroize();

    Ok(EncryptedWalletFile {
        version: WALLET_FILE_VERSION,
        network: network_to_byte(network),
        address: address.to_owned(),
        public_key: keypair.public_key_bytes(),
        salt,
        nonce,
        ciphertext,
    })
}

fn load_wallet(wallet_path: &Path, passphrase: &str) -> Result<UnlockedWallet, WalletCliError> {
    let encoded = fs::read(wallet_path).map_err(|_| WalletCliError::Io)?;
    let wallet_file: EncryptedWalletFile = bincode::serde::decode_from_slice(
        &encoded,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_little_endian(),
    )
    .map(|(wallet, _)| wallet)
    .map_err(|_| WalletCliError::WalletDeserialization)?;

    if wallet_file.version != WALLET_FILE_VERSION {
        return Err(WalletCliError::UnsupportedWalletVersion(
            wallet_file.version,
        ));
    }

    let network = network_from_byte(wallet_file.network)?;
    validate_address_for_network(&wallet_file.address, network)
        .map_err(|source| WalletCliError::AddressValidation { source })?;

    let mut wallet_key = derive_wallet_key(passphrase, &wallet_file.salt)?;
    let cipher = ChaCha20Poly1305::new((&wallet_key).into());
    let mut plaintext = cipher
        .decrypt((&wallet_file.nonce).into(), wallet_file.ciphertext.as_ref())
        .map_err(|_| WalletCliError::Decryption)?;
    wallet_key.zeroize();

    if plaintext.len() != SECRET_KEY_LENGTH {
        plaintext.zeroize();
        return Err(WalletCliError::WalletIntegrity);
    }

    let keypair =
        Keypair::from_secret_key(&plaintext).map_err(|source| WalletCliError::Crypto { source })?;
    plaintext.zeroize();

    if keypair.public_key_bytes() != wallet_file.public_key {
        return Err(WalletCliError::WalletIntegrity);
    }

    let derived_address = derive_address(&wallet_file.public_key, network)
        .map_err(|source| WalletCliError::AddressValidation { source })?;
    if derived_address != wallet_file.address {
        return Err(WalletCliError::WalletIntegrity);
    }

    Ok(UnlockedWallet {
        network,
        address: wallet_file.address,
        keypair,
    })
}

fn derive_wallet_key(
    passphrase: &str,
    salt: &[u8; WALLET_KEY_SALT_LENGTH],
) -> Result<[u8; WALLET_KEY_DERIVATION_OUTPUT_LENGTH], WalletCliError> {
    let mut output = [0_u8; WALLET_KEY_DERIVATION_OUTPUT_LENGTH];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|_| WalletCliError::KeyDerivation)?;
    Ok(output)
}

fn load_wallet_state(state_path: &Path) -> Result<WalletLocalState, WalletCliError> {
    if !state_path.exists() {
        return Ok(WalletLocalState::default());
    }

    let raw = fs::read_to_string(state_path).map_err(|_| WalletCliError::Io)?;
    serde_json::from_str(&raw).map_err(|_| WalletCliError::WalletDeserialization)
}

fn save_wallet_state(state_path: &Path, state: WalletLocalState) -> Result<(), WalletCliError> {
    let encoded =
        serde_json::to_string_pretty(&state).map_err(|_| WalletCliError::WalletSerialization)?;
    write_secure_file(state_path, encoded.as_bytes())
}

fn write_secure_file(path: &Path, bytes: &[u8]) -> Result<(), WalletCliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| WalletCliError::Io)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        let mut file = options.open(path).map_err(|_| WalletCliError::Io)?;
        file.write_all(bytes).map_err(|_| WalletCliError::Io)
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes).map_err(|_| WalletCliError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_hma_amount_to_micro;

    #[test]
    fn parses_integer_hma_amount() {
        let parsed = parse_hma_amount_to_micro("2");
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap_or_default(), 200_000_000);
    }

    #[test]
    fn parses_fractional_hma_amount() {
        let parsed = parse_hma_amount_to_micro("1.00000001");
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap_or_default(), 100_000_001);
    }

    #[test]
    fn rejects_more_than_eight_decimal_places() {
        let parsed = parse_hma_amount_to_micro("0.000000001");
        assert!(parsed.is_err());
    }

    #[test]
    fn rejects_non_numeric_amount() {
        let parsed = parse_hma_amount_to_micro("abc");
        assert!(parsed.is_err());
    }
}
