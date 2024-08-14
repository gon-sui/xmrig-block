#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr};

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let tot_len = u16::from_be(unsafe { (*ipv4hdr).tot_len });
    let headers_len = EthHdr::LEN as u16 + Ipv4Hdr::LEN as u16 + TcpHdr::LEN as u16;

    if tot_len < headers_len {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_size = (tot_len - headers_len) as usize;

    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;

    // サーバーからのパケットサイズチェック (430 ± 10 バイト)
    if payload_size >= 420 && payload_size <= 440 {
        return Ok(xdp_action::XDP_PASS);
    }

    // クライアントからのパケットサイズチェック (66 ± 10 バイト)
    if payload_size >= 56 && payload_size <= 76 {
        // ペイロードに '7b' ('{' の16進数) が含まれているか確認
        if unsafe { check_payload_for_hex(&ctx, payload_offset, payload_size, 0x7b) }? {
            // "jsonrpc" 文字列の16進数表現を検索
            let jsonrpc_hex = [0x6a, 0x73, 0x6f, 0x6e, 0x72, 0x70, 0x63];
            if unsafe { check_payload_for_hex_string(&ctx, payload_offset, payload_size, &jsonrpc_hex) }? {
                info!(&ctx, "Dropping packet containing 'jsonrpc'");
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
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

#[inline(always)]
unsafe fn check_payload_for_hex(ctx: &XdpContext, offset: usize, size: usize, target: u8) -> Result<bool, ()> {
    for i in 0..size {
        let byte: *const u8 = ptr_at(ctx, offset + i)?;
        if *byte == target {
            return Ok(true);
        }
    }
    Ok(false)
}

#[inline(always)]
unsafe fn check_payload_for_hex_string(ctx: &XdpContext, offset: usize, size: usize, target: &[u8]) -> Result<bool, ()> {
    if size < target.len() {
        return Ok(false);
    }
    for i in 0..=(size - target.len()) {
        let mut found = true;
        for (j, &t) in target.iter().enumerate() {
            let byte: *const u8 = ptr_at(ctx, offset + i + j)?;
            if *byte != t {
                found = false;
                break;
            }
        }
        if found {
            return Ok(true);
        }
    }
    Ok(false)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
