use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, error};
use tokio::signal;
use anyhow::Context;

/// コマンドライン引数を定義する構造体
#[derive(Debug, Parser)]
struct Opt {
    /// 対象のネットワークインターフェース名（デフォルト: ens18）
    #[clap(short, long, default_value = "ens18")]
    iface: String,
    /// SKBモードを使用するかどうかのフラグ
    #[clap(long)]
    use_skb_mode: bool,
}

/// メインエントリーポイント
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // 環境ロガーの初期化
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    // コマンドライン引数の解析
    let opt = Opt::parse();

    // デバッグビルドの場合のeBPFプログラムのロード
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    // リリースビルドの場合のeBPFプログラムのロード
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;

    // eBPFロガーの初期化（失敗しても警告のみで続行）
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // XDPプログラムの取得とロード
    let program: &mut Xdp = bpf.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;

    // XDPフラグの設定
    let mut xdp_flags = XdpFlags::default();
    if opt.use_skb_mode {
        xdp_flags |= XdpFlags::SKB_MODE;
    }

    // XDPプログラムのアタッチ試行
    info!("Attempting to attach XDP program to {}", opt.iface);
    match program.attach(&opt.iface, xdp_flags) {
        Ok(_) => info!("XDP program attached successfully"),
        Err(e) => {
            error!("Failed to attach XDP program: {}", e);
            // SKBモードでの再試行
            if !opt.use_skb_mode {
                warn!("Retrying with SKB_MODE...");
                xdp_flags |= XdpFlags::SKB_MODE;
                program.attach(&opt.iface, xdp_flags)
                    .context("Failed to attach XDP program even with SKB_MODE")?;
                info!("XDP program attached successfully with SKB_MODE");
            } else {
                return Err(anyhow::anyhow!("Failed to attach XDP program"));
            }
        }
    }

    // Ctrl-C待機とクリーンアップ
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
