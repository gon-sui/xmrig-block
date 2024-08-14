use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya::util::online_cpus;
use aya_log::BpfLogger;
use anyhow::Context;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // コマンドライン引数からインターフェース名を取得
    let interface = std::env::args()
        .nth(1)
        .context("No interface specified")?;

    // Compile-time generated eBPF code を読み込む
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // eBPF プログラムをロード
    let program: &mut Xdp = bpf.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;

    // 指定されたインターフェースに XDP プログラムをアタッチ
    program.attach(&interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Waiting for Ctrl-C...");
    info!("eBPF program is filtering TCP packets.");
    info!("It will drop packets with payload size 56-76 bytes containing '{{' (0x7b) and 'jsonrpc' in hex.");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
