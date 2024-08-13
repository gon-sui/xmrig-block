use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use anyhow::{Context, Result};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    info!("Starting XDP program");
    debug!("Parsed options: {:?}", opt);

    // Load the eBPF program
    let mut bpf = load_bpf_program().context("Failed to load eBPF program")?;

    // Initialize the eBPF logger
    if let Err(e) = init_bpf_logger(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Load and attach the XDP program
    let program: &mut Xdp = bpf.program_mut("xdp_log")
        .context("Failed to find 'xdp_log' program")?
        .try_into()
        .context("Failed to convert program to XDP")?;
    program.load().context("Failed to load XDP program")?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("Failed to attach XDP program")?;

    info!("Successfully started XDP program. Waiting for Ctrl-C...");
    wait_for_ctrl_c().await.context("Error while waiting for Ctrl-C")?;
    info!("Received Ctrl-C, shutting down...");
    Ok(())
}

fn load_bpf_program() -> Result<Bpf> {
    debug!("Loading eBPF program");
    #[cfg(debug_assertions)]
    let program = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/xdp-log");
    #[cfg(not(debug_assertions))]
    let program = include_bytes_aligned!("../../target/bpfel-unknown-none/release/xdp-log");
    Bpf::load(program).context("Failed to load eBPF program bytes")
}

fn init_bpf_logger(bpf: &mut Bpf) -> Result<()> {
    debug!("Initializing eBPF logger");
    BpfLogger::init(bpf).context("Failed to initialize eBPF logger")?;
    Ok(())
}

async fn wait_for_ctrl_c() -> Result<()> {
    debug!("Waiting for Ctrl-C signal");
    signal::ctrl_c().await.context("Failed to wait for Ctrl-C")
}
