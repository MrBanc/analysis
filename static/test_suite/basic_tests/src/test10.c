#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_WRITE 8192

void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s size\n", __progname);
	exit(1);
}	

int main(int argc, char *argv[])
{
  	char filename[] = "/tmp/syscall.XXXXXXXXXX";
	int count = 5000000;
	u_long wsize = MAX_WRITE;
	char *buf, *ep;
	ssize_t w;
	int i, j, fd;

    if ((errno == ERANGE && wsize == ULONG_MAX) || (wsize > MAX_WRITE)) {
		fprintf(stderr, "%d - value out of range\n", wsize);
		usage();	
	}

	buf = malloc(wsize * sizeof(char));
	if (buf == NULL)
		err(1, "malloc failed");
	memset(buf, 'a', wsize);

	if ((fd = mkstemp(filename)) == -1)
		err(1, "can't open a temporary file");

	printf("Writing %d 'a' to my output\n", count);
	
	w = 0;
	j = 0;
	for (i=0; i < count; i+=w) {
		if ((w = write(fd, buf, wsize)) == -1) {
			if (errno != EINTR)
				err(1, "write failed"); 
			else
				w = 0;
		}
		j++;
	}	
	printf("I did %d system calls\n", j);
	unlink(filename);
	return(0);
}