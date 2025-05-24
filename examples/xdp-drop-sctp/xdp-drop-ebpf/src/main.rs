#![no_std]
#![no_main]
#![allow(nonstandard_style)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// Define SCTP common header structure
#[repr(C)]
struct SctpCommonHdr {
    src_port: u16,
    dst_port: u16,
    verif_tag: u32,
    checksum: u32,
}

// Define SCTP chunk header structure
#[repr(C)]
struct SctpChunkHdr {
    chunk_type: u8,
    chunk_flags: u8,
    length: u16,
}

// Constants
const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>(); // 14 bytes for Ethernet header
const MIN_IP_HDR_LEN: usize = mem::size_of::<Ipv4Hdr>(); // 20 bytes for minimum IPv4 header
const MAX_IP_HDR_LEN: usize = 60; // Maximum IPv4 header length (including options)
const SCTP_PROTOCOL: u8 = 132; // SCTP protocol number
const SCTP_COMMON_LEN: usize = mem::size_of::<SctpCommonHdr>(); // 12 bytes for SCTP common header
const SCTP_DATA_CHUNK_TYPE: u8 = 0; // SCTP DATA chunk type
const SCTP_DATA_HDR_EXTRA_LEN: usize = 12; // TSN(4), Stream(2), SSN(2), PPID(4) bytes
const NGAP_GLOBAL_NGENB_OFFSET: usize = 11; // Offset of globalNgENB-ID in NGAP payload
const GLOBAL_NGENB_MARKER: u8 = 0x40; // Marker for globalNgENB-ID (value 1)

// Logging map for AYA_LOGS
#[map] // (1)
static BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

// Panic handler for no_std environment
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Safe pointer access function
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}
/*unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(()); // Out of bounds
    }

    Ok((start + offset) as *const T)
}*/

// XDP program entry point
#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
/*pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_drop_ngap(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}*/

// (2)
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

// Packet drop logic: try_xdp_drop_ngap
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parse Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS); // Not IPv4, pass the packet
    }

    // 2. Parse IPv4 header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // (3)
    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    // info!(&ctx, "SRC: {:i}, ACTION: {}", source, action);

    let ip_ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let ip_len = ip_ihl * 4;
/*
    if ip_ihl < 5 || ip_ihl > 15 {
        return Ok(xdp_action::XDP_PASS); // Invalid Internet Header Length (IHL)
    }
    if ip_len < MIN_IP_HDR_LEN || ip_len > MAX_IP_HDR_LEN {
        return Ok(xdp_action::XDP_PASS); // Invalid header length
    }
*/

    info!(&ctx, "SRC: {:i}, ACTION: {}", source, action);
    // 3. Check protocol (SCTP)
    let proto_offset = ETH_HDR_LEN + 9; // Protocol field at 9th byte in IPv4 header
    //if proto_offset >= ctx.data_end() {
    //    return Ok(xdp_action::XDP_PASS); // Out of bounds
    //}
    let proto_ptr = unsafe { ptr_at::<u8>(&ctx, proto_offset)? };
    let proto = unsafe { *proto_ptr };
    if proto != SCTP_PROTOCOL {
        return Ok(xdp_action::XDP_PASS); // Not SCTP, pass the packet
    }

    // info!(&ctx, "SCTP: {:i}", source);
    // info!(&ctx, "SCTP");

    // 4. Parse SCTP common header
    let sctp_base = ETH_HDR_LEN + ip_len;
    if sctp_base + SCTP_COMMON_LEN > ctx.data_end() {
        return Ok(xdp_action::XDP_PASS); // Out of bounds
    }
    let _sctp_common: *const SctpCommonHdr = unsafe { ptr_at(&ctx, sctp_base)? };

    // 5. Parse SCTP DATA chunk header
    let chunk_hdr_offset = sctp_base + SCTP_COMMON_LEN;
    if chunk_hdr_offset + mem::size_of::<SctpChunkHdr>() > ctx.data_end() {
        return Ok(xdp_action::XDP_PASS); // Out of bounds
    }
    let chunk: *const SctpChunkHdr = unsafe { ptr_at(&ctx, chunk_hdr_offset)? };
    let ctype = unsafe { (*chunk).chunk_type };
    if ctype != SCTP_DATA_CHUNK_TYPE {
        return Ok(xdp_action::XDP_PASS); // Not a DATA chunk, pass the packet
    }

    // 6. Calculate NGAP payload start
    let data_offset = chunk_hdr_offset + mem::size_of::<SctpChunkHdr>() + SCTP_DATA_HDR_EXTRA_LEN;
    if data_offset + NGAP_GLOBAL_NGENB_OFFSET + 1 > ctx.data_end() {
        return Ok(xdp_action::XDP_PASS); // Out of bounds
    }
    // info!(&ctx, "NGAP: {:i}", source);
    // info!(&ctx, "NGAP");

    // 7. Check globalNgENB-ID marker
    let marker_ptr = unsafe { ptr_at::<u8>(&ctx, data_offset + NGAP_GLOBAL_NGENB_OFFSET)? };
    let marker = unsafe { *marker_ptr };
    if marker == GLOBAL_NGENB_MARKER {
        info!(&ctx, "Dropping packet: globalNgENB-ID(1) detected");
        return Ok(xdp_action::XDP_DROP); // Drop packet if globalNgENB-ID is 0x40
    }

    // Ok(xdp_action::XDP_PASS) // Pass all other packets

    Ok(action)
}
