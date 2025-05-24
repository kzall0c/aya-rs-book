#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#define SERVER_PORT 30810
#define BUFFER_SIZE 1024

int main() {
    int listen_fd, conn_fd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    char buffer[BUFFER_SIZE];

    // 1. SCTP 소켓 생성
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (listen_fd < 0) {
        perror("socket");
        exit(1);
    }

    // 2. 서버 주소 구조체 초기화
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERVER_PORT);

    // 3. 바인드
    if (bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(listen_fd);
        exit(1);
    }

    // 4. 리슨
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        exit(1);
    }

    printf("SCTP 에코 서버가 %d 포트에서 대기 중입니다...\n", SERVER_PORT);

    while (1) {
        len = sizeof(cliaddr);
        // 5. 클라이언트 연결 수락
        conn_fd = accept(listen_fd, (struct sockaddr *)&cliaddr, &len);
        if (conn_fd < 0) {
            perror("accept");
            continue;
        }

        // 6. 데이터 수신 및 에코
        ssize_t n = sctp_recvmsg(conn_fd, buffer, BUFFER_SIZE, NULL, 0, NULL, NULL);
        if (n > 0) {
            buffer[n] = '\0';
            printf("수신: %s\n", buffer);
            sctp_sendmsg(conn_fd, buffer, n, NULL, 0, 0, 0, 0, 0, 0);
        }

        close(conn_fd);
    }

    close(listen_fd);
    return 0;
}
