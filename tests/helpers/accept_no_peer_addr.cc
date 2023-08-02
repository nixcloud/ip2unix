#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstdlib>

int main(void)
{
    int fd, accfd;
    char buf[3];
    struct sockaddr_in addr;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(1234);

    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr),
             sizeof addr) == -1) {
        perror("bind");
        close(fd);
        return EXIT_FAILURE;
    }

    if (listen(fd, 10) == -1) {
        perror("listen");
        close(fd);
        return EXIT_FAILURE;
    }

    if ((accfd = accept(fd, nullptr, nullptr)) == -1) {
        perror("accept");
        close(fd);
        return EXIT_FAILURE;
    }

    if (recv(accfd, buf, 3, 0) == -1) {
        perror("recv");
        close(accfd);
        close(fd);
        return EXIT_FAILURE;
    }

    if (buf[0] == 'f') buf[0] = 'b';
    if (buf[1] == 'o') buf[1] = 'a';
    if (buf[2] == 'o') buf[2] = 'r';

    if (send(accfd, buf, 3, 0) == -1) {
        perror("send");
        close(accfd);
        close(fd);
        return EXIT_FAILURE;
    }

    close(accfd);
    close(fd);
    return EXIT_SUCCESS;
}
