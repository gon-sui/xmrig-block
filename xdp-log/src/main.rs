use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{Xdp, XdpFlags};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use tokio::signal;
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

    // eBPFオブジェクトをロード
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-log"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-log"
    ))?;

    // XDPプログラムをロードおよびアタッチ
    let program: &mut Xdp = bpf.program_mut("xdp_log").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;

    // イベントマップを取得
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;

    // シングルコア用の処理
    let cpu_id = 0;
    let mut buf = perf_array.open(cpu_id, None)?;

    // バッファを準備
    let mut buffers = (0..10)
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();

    info!("Listening for events...");

    loop {
        let events = buf.read_events(&mut buffers).await?;

        for i in 0..events.read {
            let buf = &buffers[i];
            let ptr = buf.as_ptr() as *const PacketData;
            let data = unsafe { ptr.read_unaligned() };
            
            let src_ip = data.src_addr.to_ne_bytes();
            let dst_ip = data.dst_addr.to_ne_bytes();
            
            println!(
                "{}.{}.{}.{}:{} -> {}.{}.{}.{}:{} | Size: {} bytes | Payload: {:?}",
                src_ip[0], src_ip[1], src_ip[2], src_ip[3], data.src_port,
                dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], data.dst_port,
                data.size,
                &data.payload[..core::cmp::min(data.size as usize, data.payload.len())]
            );
        }

        // Ctrl+Cが押されたかチェック
        if signal::ctrl_c().await.is_ok() {
            info!("Exiting...");
            break;
        }
    }

    Ok(())
}
