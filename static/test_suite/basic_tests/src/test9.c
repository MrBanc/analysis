#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

int main() {
    char *filename = "example_file.txt";
    int file_descriptor = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (file_descriptor == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    struct stat sb;
	struct passwd *pwuser;
	struct group *grpnam;
	
    if (stat(filename, &sb) == -1){
        perror("stat()");
        exit(EXIT_FAILURE);
    }

    if ((pwuser = getpwuid(sb.st_uid)) == NULL){
        perror("getpwuid()");
        exit(EXIT_FAILURE);
    }

    if ((grpnam = getgrgid(sb.st_gid)) == NULL){
        perror("getgrgid()");
        exit(EXIT_FAILURE);
    }

    printf("\tinode: %u\n", sb.st_ino);
    printf("\towner: %u (%s)\n", sb.st_uid, pwuser->pw_name);
    printf("\tgroup: %u (%s)\n", sb.st_gid, grpnam->gr_name);
    printf("\tperms: %o\n", sb.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO));
    printf("\tlinks: %d\n", sb.st_nlink);
    printf("\tsize: %ld\n", sb.st_size);
    printf("\tatime: %s", ctime(&sb.st_atim.tv_sec));
    printf("\tmtime: %s", ctime(&sb.st_mtim.tv_sec));
    printf("\tctime: %s", ctime(&sb.st_ctim.tv_sec));
	
    const char *data = "Hello, System Calls!\n";
    ssize_t bytes_written = write(file_descriptor, data, strlen(data));
    if (bytes_written == -1) {
        perror("write");
        close(file_descriptor);
        exit(EXIT_FAILURE);
    }

    off_t offset = lseek(file_descriptor, 0, SEEK_SET);
    if (offset == -1) {
        perror("lseek");
        close(file_descriptor);
        exit(EXIT_FAILURE);
    }

    char buffer[1024];
    ssize_t bytes_read = read(file_descriptor, buffer, sizeof(buffer));
    if (bytes_read == -1) {
        perror("read");
        close(file_descriptor);
        exit(EXIT_FAILURE);
    }

    printf("Read from file: %.*s", (int)bytes_read, buffer);

    if (close(file_descriptor) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    if (unlink(filename) == -1) {
        perror("unlink");
        exit(EXIT_FAILURE);
    }

    pid_t process_id = getpid();
    printf("Process ID: %d\n", process_id);

    printf("Sleeping for 0.3 seconds...\n");
    nanosleep((const struct timespec[]){{0, 300000000L}}, NULL);
    printf("Awake!\n");

    if (remove(filename) == 0)
        printf("Deleted successfully");

    exit(0);
}
