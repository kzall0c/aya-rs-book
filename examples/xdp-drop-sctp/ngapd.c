#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#define SERVER_PORT 30000
#define BUFFER_SIZE 1024

int main() {
    int listen_fd, conn_fd, ret;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;

    struct sctp_sndrcvinfo sinfo;
    int flags;

    struct sctp_initmsg initmsg = {
        .sinit_num_ostreams = 5,
        .sinit_max_instreams = 5,
        .sinit_max_attempts = 4,
    };

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

    ret = setsockopt(listen_fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg));
    if (ret < 0)
            perror("setsockopt SCTP_INITMSG failed");

    // 4. 리슨
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        exit(1);
    }

    printf("SCTP 에코 서버가 %d 포트에서 대기 중입니다...\n", SERVER_PORT);

    while (1) {
        char buffer[BUFFER_SIZE];
        len = sizeof(cliaddr);
        // 5. 클라이언트 연결 수락
        conn_fd = accept(listen_fd, (struct sockaddr *)&cliaddr, &len);
        if (conn_fd < 0) {
            perror("accept");
            continue;
        }

        // 6. 데이터 수신 및 에코
        // ssize_t n = sctp_recvmsg(conn_fd, buffer, BUFFER_SIZE, NULL, 0, NULL, NULL);

        flags = 0;
        memset(&sinfo, 0, sizeof(sinfo));
        sinfo.sinfo_stream = 0; // 기본 스트림 사용
        sinfo.sinfo_flags = SCTP_UNORDERED; // 순서 없는 메시지 전송

        if (setsockopt(conn_fd, IPPROTO_SCTP, SCTP_RCVINFO, &sinfo, sizeof(sinfo)) < 0) {
            perror("setsockopt SCTP_RCVINFO failed");
            close(conn_fd);
            continue;
       }

        printf("New client connected\n");
        fflush(stdout);

        ssize_t n = sctp_recvmsg(conn_fd, buffer, sizeof(buffer) - 1,
        (struct sockaddr*)&cliaddr, &len,
        &sinfo, &flags);

        if (n > 0) {
            buffer[n] = '\0';
            for (int i = 0; i < sizeof(buffer); i++) {
                printf("%02x ", buffer[i]);
            }
            printf("\n");
            printf("From stream: %d\n", sinfo.sinfo_stream);
            printf("From port: %d\n", ntohs(cliaddr.sin_port));
            // sctp_sendmsg(conn_fd, buffer, n, NULL, 0, 0, 0, 0, 0, 0);
        }
        else {
            perror("sctp_recvmsg failed or no data");
        }

        // close(conn_fd);
    }

    close(listen_fd);
    return 0;
}
