fn main() {
    if let Err(error) = homa::wallet::cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
