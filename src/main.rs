use ironguard::cli; // remove when dir name is changed from ironguard_ai to ironguard

#[tokio::main(flavor = "multi_thread")] 
async fn main() -> anyhow::Result<()> {
    cli::run()
}
