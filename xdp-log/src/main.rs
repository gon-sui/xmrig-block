use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn, error};
use tokio::{signal, task};
use xdp_log_common::PacketInfo;
use aya::util::online_cpus;
use anyhow::Context;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let opt = Opt::parse();

    // Load the eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_log").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;

    // Use Box::leak to create a 'static reference
    let bpf = Box::leak(Box::new(bpf));

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").ok_or_else(|| anyhow::anyhow!("Failed to get EVENTS map"))?)?;

    for cpu_id in online_cpus().context("Failed to get online CPUs")? {
        let mut buf = perf_array.open(cpu_id, None).context("Failed to open perf buffer")?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let data_buf = &buffers[i];
                            let ptr = data_buf.as_ptr() as *const PacketInfo;
                            let data = unsafe { ptr.read_unaligned() };
                            info!(
                                "CPU: {} | Packet: size={}, tcp={}",
                                cpu_id,
                                data.size,
                                if data.is_tcp == 1 { "Yes" } else { "No" }
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to read events: {}", e);
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
