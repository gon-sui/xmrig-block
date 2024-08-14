#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr};

const MAX_INSPECT_BYTES: usize = 20; // 検査する最大バイト数

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let tot_len = u16::from_be(unsafe { (*ipv4hdr).tot_len });
    let headers_len = EthHdr::LEN as u16 + Ipv4Hdr::LEN as u16 + TcpHdr::LEN as u16;
    
    if tot_len < headers_len {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let payload_size = (tot_len - headers_len) as usize;
    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
    
    // サーバーからのパケットサイズチェック (430 ± 10 バイト)
    if payload_size >= 420 && payload_size <= 440 {
        if check_payload_for_jsonrpc_hex(&ctx, payload_offset, payload_size)? {
            info!(&ctx, "Dropping server packet containing 'jsonrpc' in hex");
            return Ok(xdp_action::XDP_DROP);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // クライアントからのパケットサイズチェック (66 ± 10 バイト)
    if payload_size >= 56 && payload_size <= 76 {
        info!(&ctx, "Passing client packet with size: {}", payload_size);
        return Ok(xdp_action::XDP_PASS);
    }
    
    // サイズ条件に合致しないパケットはドロップ
    info!(&ctx, "Dropping packet with unexpected size: {}", payload_size);
    Ok(xdp_action::XDP_DROP)
}

#[inline(always)]
fn check_payload_for_jsonrpc_hex(ctx: &XdpContext, offset: usize, size: usize) -> Result<bool, ()> {
    let jsonrpc_hex = [0x6a, 0x73, 0x6f, 0x6e, 0x72, 0x70, 0x63]; // "jsonrpc" in hex
    let mut match_index = 0;
    let inspect_bytes = core::cmp::min(size, MAX_INSPECT_BYTES);

    for i in 0..inspect_bytes {
        let byte: u8 = unsafe { *ptr_at::<u8>(ctx, offset + i)? };
        
        if byte == jsonrpc_hex[match_index] {
            match_index += 1;
            if match_index == jsonrpc_hex.len() {
                return Ok(true);
            }
        } else {
            match_index = 0;
        }
    }

    Ok(false)
}

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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
