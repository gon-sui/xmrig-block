use aya::{include_bytes_aligned, Bpf};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use bytes::BytesMut;
use clap::Parser;
use log::info;
use std::sync::Arc;
use tokio::{signal, task};
use xdp_log_common::PacketData;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let opt = Opt::parse();

    #[cfg(debug_assertions)]
    let bpf = Arc::new(Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?);
    #[cfg(not(debug_assertions))]
    let bpf = Arc::new(Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?);

    // Set up and load the XDP program
    let program = bpf.program("xdp_log").unwrap();
    let mut xdp_program: &mut Xdp = program.try_into_mut()?; // Changed this line
    xdp_program.load()?;
    xdp_program.attach(&opt.iface, XdpFlags::default())?;

    // Create the AsyncPerfEventArray
    let map = bpf.map_mut("EVENTS").unwrap();
    let perf_array = Arc::new(AsyncPerfEventArray::try_from(map)?); // Changed this line

    // Spawn async tasks for each CPU
    for cpu_id in online_cpus()? {
        let perf_array = Arc::clone(&perf_array);

        task::spawn(async move {
            let mut buf = perf_array.open(cpu_id, None).unwrap();
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &mut buffers[i];
                            let ptr = buf.as_ptr() as *const PacketData;
                            let data = unsafe { ptr.read_unaligned() };

                            let src_ip = data.src_addr.to_ne_bytes();
                            let dst_ip = data.dst_addr.to_ne_bytes();

                            println!(
                                "CPU: {} | {}.{}.{}.{}:{} -> {}.{}.{}.{}:{} | Size: {} bytes | Payload: {:?}",
                                cpu_id,
                                src_ip[0], src_ip[1], src_ip[2], src_ip[3], data.src_port,
                                dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], data.dst_port,
                                data.size,
                                &data.payload[..core::cmp::min(data.size as usize, data.payload.len())]
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading events: {}", e);
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

