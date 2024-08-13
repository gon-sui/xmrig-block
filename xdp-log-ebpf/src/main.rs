#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr, udp::UdpHdr};
use xdp_log_common::PacketInfo;

#[xdp]
pub fn xdp_log(ctx: XdpContext) -> u32 {
    match try_xdp_log(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_log(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let ethhdr = unsafe { &*ethhdr };

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let ipv4hdr = unsafe { &*ipv4hdr };

            let mut packet_info = PacketInfo {
                src_ip: u32::from_be(ipv4hdr.src_addr),
                dst_ip: u32::from_be(ipv4hdr.dst_addr),
                src_port: 0,
                dst_port: 0,
                protocol: ipv4hdr.proto as u8,
                len: ctx.data_end() - ctx.data(),
            };

            let transport_header = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            let mut payload_offset = EthHdr::LEN + Ipv4Hdr::LEN;

            match ipv4hdr.proto {
                IpProto::Tcp => {
                    let tcphdr = unsafe { &*(transport_header as *const TcpHdr) };
                    packet_info.src_port = u16::from_be(tcphdr.source);
                    packet_info.dst_port = u16::from_be(tcphdr.dest);
                    payload_offset += TcpHdr::LEN;
                },
                IpProto::Udp => {
                    let udphdr = unsafe { &*(transport_header as *const UdpHdr) };
                    packet_info.src_port = u16::from_be(udphdr.source);
                    packet_info.dst_port = u16::from_be(udphdr.dest);
                    payload_offset += UdpHdr::LEN;
                },
                _ => {}
            }

            // Get payload (up to 64 bytes)
            let mut payload = [0u8; 64];
            let payload_len = core::cmp::min(64, packet_info.len.saturating_sub(payload_offset));
            for i in 0..payload_len {
                payload[i] = unsafe { *ptr_at::<u8>(&ctx, payload_offset + i)? };
            }

            // Convert payload to hex string
            let mut hex_payload = [0u8; 128];
            for i in 0..payload_len {
                let byte = payload[i];
                hex_payload[i*2] = hex_char(byte >> 4);
                hex_payload[i*2 + 1] = hex_char(byte & 0xf);
            }

            // Log packet information with payload
            info!(
                &ctx,
                "{:i} → {:i} {} {} → {} {}",
                packet_info.src_ip,
                packet_info.dst_ip,
                match packet_info.protocol {
                    6 => "TCP",
                    17 => "UDP",
                    _ => "Unknown",
                },
                packet_info.src_port,
                packet_info.dst_port,
                core::str::from_utf8(&hex_payload[..payload_len*2]).unwrap_or("Invalid UTF-8")
            );
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
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
