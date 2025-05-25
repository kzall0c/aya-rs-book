use std::io;
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use libc::{
    sockaddr, sockaddr_in, socket, connect, send, shutdown, close,
    AF_INET, IPPROTO_SCTP, SOCK_STREAM, htons, in_addr,
    SHUT_WR,
};

fn main() -> io::Result<()> {
    unsafe {
        // 1. SCTP 소켓 생성
        let sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if sock < 0 {
            panic!("❌ 소켓 생성 실패");
        }

        // 2. 서버 주소 설정 (예: 192.168.67.15:38412)
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

        // 3. 서버와 연결
        let ret = connect(
            sock,
            &server_addr as *const sockaddr_in as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as u32,
        );
        if ret < 0 {
            panic!("❌ 서버 연결 실패");
        }
        println!("✅ SCTP 연결 성공");

        // 4. NGAP 페이로드 준비
        let ngap_payload: Vec<u8> = vec![
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

        // 5. 페이로드 전송
        let sent = send(
            sock,
            ngap_payload.as_ptr() as *const c_void,
            ngap_payload.len(),
            0,
        );
        if sent < 0 {
            panic!("❌ NGAP 페이로드 전송 실패");
        }
        println!("📤 NGAP 페이로드 전송 완료: {} 바이트", sent);

        // 6. 쓰기 종료 (서버에게 더 이상 데이터 없음 알림)
        if shutdown(sock, SHUT_WR) < 0 {
            panic!("❌ shutdown(SHUT_WR) 실패");
        }

        // 7. 소켓 닫기
        close(sock);
        println!("🔒 소켓 종료 완료");
    }

    Ok(())
}

