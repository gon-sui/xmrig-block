use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // Bpf::load の代わりに Ebpf::load を使用
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("eBPFロガーの初期化に失敗しました: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_log").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;

    info!("Ctrl-C waiting...");
    signal::ctrl_c().await?;
    info!("finish...");

    Ok(())
}
