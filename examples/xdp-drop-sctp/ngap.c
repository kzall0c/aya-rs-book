#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// NGAP 페이로드 정의
unsigned char ngap_payload[] = {
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
    0x15, 0x40, 0x01, 0x20
};
int ngap_payload_len = sizeof(ngap_payload);

int main(int argc, char *argv[]) {
    int fd;
    struct sockaddr_in servaddr;
    int port = 30810; // NGAP에서 일반적으로 사용되는 포트
    char *server_ip;

    // 명령줄 인자 확인
    if (argc != 2) {
        fprintf(stderr, "사용법: %s <server_ip>\n", argv[0]);
        exit(1);
    }
    server_ip = argv[1];

    // SCTP 소켓 생성
    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0) {
        perror("소켓 생성 실패");
        exit(1);
    }

    // 서버 주소 설정
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &servaddr.sin_addr) <= 0) {
        perror("IP 주소 변환 실패");
        close(fd);
        exit(1);
    }

    // 서버에 연결
    if (connect(fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("연결 실패");
        close(fd);
        exit(1);
    }

    // NGAP 페이로드 전송
    if (sctp_sendmsg(fd, ngap_payload, ngap_payload_len, NULL, 0, htonl(1234), 0, 0, 0, 0) < 0) {
        perror("페이로드 전송 실패");
        close(fd);
        exit(1);
    }

    // 소켓 닫기
    close(fd);

    printf("NGAP 패킷이 성공적으로 전송되었습니다.\n");
    return 0;
}
