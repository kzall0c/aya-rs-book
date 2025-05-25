use std::io;
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use libc::{
    sockaddr, sockaddr_in, socket, sendto,
    AF_INET, IPPROTO_SCTP, SOCK_STREAM, htons, in_addr
};

fn main() -> io::Result<()> {
    unsafe {
        // SCTP 소켓 생성
        let sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if sock < 0 {
            panic!("Failed to create socket");
        }

        // 서버 주소 설정
        let server_ip = Ipv4Addr::new(192, 168, 67, 15);
        let server_port = 38412;
        let server_addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: htons(server_port),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes(server_ip.octets()),
            },
            sin_zero: [0; 8],
        };

        let ret = libc::connect(
            sock,
            &server_addr as *const sockaddr_in as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        );
        if ret < 0 {
            panic!("Failed to connect");
        }

        println!("SCTP connection established");

        let ngap_payload = vec![
            0x00, 0x15, 0x00, 0x50, 0x00, 0x00, 0x04, 0x00,
            0x1b, 0x00, 0x08, 0x40, 0x21, 0x43, 0x65, 0x40,
            0x00, 0x00, 0x40, 0x00, 0x52, 0x40, 0x1d, 0x0d,
            0x00, 0x67, 0x4e, 0x6f, 0x64, 0x65, 0x42, 0x5f,
            0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x5f,
            0x75, 0x6c, 0x74, 0x72, 0x61, 0x5f, 0x6d, 0x61,
            0x78, 0x5f, 0x37, 0x37, 0x00, 0x66, 0x00, 0x17,
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x21, 0x43,
            0x65, 0x00, 0x02, 0x10, 0x08, 0x00, 0x00, 0x01,
            0x10, 0x08, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00,
            0x15, 0x40, 0x01, 0x20,
        ];

        let sent = libc::send(
            sock,
            ngap_payload.as_ptr() as *const c_void,
            ngap_payload.len(),
            0,
        );
        if sent < 0 {
            panic!("Failed to send NGAP payload");
        }

        println!("Sent {} bytes NGAP payload", sent);
        libc::close(sock);
    }

    Ok(())
}

