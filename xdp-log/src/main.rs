use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
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

    // 指定されたインターフェースに XDP プログラムをアタッチ（SKB_MODEを使用）
    program.attach(&interface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with SKB_MODE")?;

    info!("eBPF program loaded and attached to {} in SKB_MODE", interface);
    info!("Filtering TCP packets with payload size 56-76 bytes");
    info!("Press Ctrl+C to exit");

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
