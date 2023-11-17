#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

int main() {

    char* filename = "test_file.txt";
    int fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    write(fd, "Hello, World!\n", 13);
    close(fd);

    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process
        printf("Child process\n");
        exit(0);
    } else if (child_pid > 0) {
        // Parent process
        printf("Parent process\n");
        wait(NULL);
    } else {
        perror("fork");
        exit(EXIT_FAILURE);
    }


    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);
    bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_socket, 5);

    signal(SIGINT, SIG_IGN);

    if (remove(filename) == 0)
        printf("Deleted successfully");
    else
        printf("Unable to delete the file");

    exit(0);

    return 0;
}
