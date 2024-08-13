use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
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
    let mut ebpf_program = load_ebpf_program().context("Failed to load eBPF program")?;

    // Initialize the eBPF logger
    if let Err(e) = init_ebpf_logger(&mut ebpf_program) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Load and attach the XDP program
    let program = load_xdp_program(&mut ebpf_program).context("Failed to load XDP program")?;
    attach_xdp_program(program, &opt.iface).context("Failed to attach XDP program")?;

    info!("Successfully started XDP program. Waiting for Ctrl-C...");
    wait_for_ctrl_c().await.context("Error while waiting for Ctrl-C")?;

    info!("Received Ctrl-C, shutting down...");
    Ok(())
}

fn load_ebpf_program() -> Result<Ebpf> {
    debug!("Loading eBPF program");
    #[cfg(debug_assertions)]
    let program = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/xdp-log");
    #[cfg(not(debug_assertions))]
    let program = include_bytes_aligned!("../../target/bpfel-unknown-none/release/xdp-log");

    Ebpf::load(program).context("Failed to load eBPF program bytes")
}

fn init_ebpf_logger(ebpf: &mut Ebpf) -> Result<()> {
    debug!("Initializing eBPF logger");
    EbpfLogger::init(ebpf).context("Failed to initialize eBPF logger")?;
    Ok(())
}

fn load_xdp_program(ebpf: &mut Ebpf) -> Result<Xdp> {
    debug!("Loading XDP program");
    let program: &mut Xdp = ebpf.program_mut("xdp_log")
        .context("Failed to find 'xdp_log' program")?
        .try_into()
        .context("Failed to convert program to XDP")?;

    program.load().context("Failed to load XDP program")?;
    Ok(program.take())
}

fn attach_xdp_program(mut program: Xdp, iface: &str) -> Result<()> {
    debug!("Attaching XDP program to interface {}", iface);
    program.attach(iface, XdpFlags::default())
        .context("Failed to attach XDP program")?;
    Ok(())
}

async fn wait_for_ctrl_c() -> Result<()> {
    debug!("Waiting for Ctrl-C signal");
    signal::ctrl_c().await.context("Failed to wait for Ctrl-C")
}
