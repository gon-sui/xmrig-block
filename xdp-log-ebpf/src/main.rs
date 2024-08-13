#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr};

const TARGET_SIZE_1: usize = 430;
const TARGET_SIZE_2: usize = 60;
const SIZE_TOLERANCE: usize = 5;
const MAX_PAYLOAD_OUTPUT: usize = 32;  // 出力するペイロードの最大バイト数

#[xdp]
pub fn xdp_log(ctx: XdpContext) -> u32 {
    match try_xdp_log(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_log(ctx: &XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let ether_type = unsafe { (*ethhdr).ether_type };

    if ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let proto = unsafe { (*ipv4hdr).proto };

    if proto != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS);
    }

    let packet_size = ctx.data_end() - ctx.data();
    if !is_target_size(packet_size) {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let src_port = u16::from_be(unsafe { (*tcphdr).source });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dest });

    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
    let payload_size = core::cmp::min(packet_size.saturating_sub(payload_offset), MAX_PAYLOAD_OUTPUT);

    let mut payload = [0u8; MAX_PAYLOAD_OUTPUT * 2];
    for i in 0..payload_size {
        let byte = unsafe { *ptr_at::<u8>(ctx, payload_offset + i)? };
        payload[i*2] = hex_char(byte >> 4);
        payload[i*2 + 1] = hex_char(byte & 0xf);
    }

    info!(
        ctx,
        "{:i}:{} → {:i}:{} TCP Size: {} bytes, Payload: {}{}",
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        packet_size,
        unsafe { core::str::from_utf8_unchecked(&payload[..payload_size*2]) },
        if payload_size < packet_size.saturating_sub(payload_offset) { "..." } else { "" }
    );

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn is_target_size(size: usize) -> bool {
    (size >= TARGET_SIZE_1.saturating_sub(SIZE_TOLERANCE) && size <= TARGET_SIZE_1.saturating_add(SIZE_TOLERANCE)) ||
    (size >= TARGET_SIZE_2.saturating_sub(SIZE_TOLERANCE) && size <= TARGET_SIZE_2.saturating_add(SIZE_TOLERANCE))
}

#[inline(always)]
fn hex_char(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10),
        _ => b'0',
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
