use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
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

    // eBPFオブジェクトファイルをコンパイル時に生のバイトとして含め、実行時にロードします。
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // EbpfLogger::init() の代わりに、以下のようにログを初期化します
        warn!("eBPFロガーの初期化に失敗しました: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_log").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;

    info!("Ctrl-C waitng...");
    signal::ctrl_c().await?;
    info!("finish...");

    Ok(())
}
