#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr};

/// マイニングプールのポート番号
const MINING_PORTS: [u16; 3] = [3333, 14444, 14433];

/// XDPプログラムのエントリーポイント
#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// パケットフィルタリングのメインロジック
fn try_xdp_filter(ctx: &XdpContext) -> Result<u32, ()> {
    // イーサネットヘッダーの検証
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv4ヘッダーの検証
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    // TCPヘッダーの取得
    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let dest_port = u16::from_be(unsafe { (*tcphdr).dest });
    let src_port = u16::from_be(unsafe { (*tcphdr).source });

    // マイニングプールのポート番号をチェック
    if !MINING_PORTS.contains(&dest_port) && !MINING_PORTS.contains(&src_port) {
        return Ok(xdp_action::XDP_PASS);
    }

    // パケットサイズの計算
    let tot_len = u16::from_be(unsafe { (*ipv4hdr).tot_len });
    let headers_len = EthHdr::LEN as u16 + Ipv4Hdr::LEN as u16 + TcpHdr::LEN as u16;
    let payload_size = (tot_len - headers_len) as usize;

    info!(ctx, "マイニング通信を検出: ポート {} -> {} のパケットをドロップ (サイズ={} バイト)", src_port, dest_port, payload_size);
    Ok(xdp_action::XDP_DROP)
}

/// メモリ安全なポインタアクセス
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// パニックハンドラー
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
