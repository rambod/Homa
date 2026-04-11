fn main() {
    if let Err(error) = homa::node::cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
