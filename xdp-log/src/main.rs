use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, error};
use tokio::signal;
use anyhow::Context;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(long)]
    use_skb_mode: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let opt = Opt::parse();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;

    let mut xdp_flags = XdpFlags::default();
    if opt.use_skb_mode {
        xdp_flags |= XdpFlags::SKB_MODE;
    }

    info!("Attempting to attach XDP program to {}", opt.iface);
    match program.attach(&opt.iface, xdp_flags) {
        Ok(_) => info!("XDP program attached successfully"),
        Err(e) => {
            error!("Failed to attach XDP program: {}", e);
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

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
