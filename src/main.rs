use ironguard_ai::cli;

#[tokio::main(flavor = "multi_thread")] 
async fn main() -> anyhow::Result<()> {
    cli::run()
}
