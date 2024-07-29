#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

int main(int argc, char** argv) {
	printf("PID: %d\n", getpid());

	int fd = syscall(SYS_openat, -100, "testfile", O_RDWR);
	printf("Openat ret: %d\n", fd);

	if (fd == -1) {
		printf("Opneat error: %s\n", strerror(errno));
	}

	int ret = syscall(SYS_write, fd, "I'm writing this :) pls.", 24);
	printf("Write ret: %d\n", ret);

	if (ret == -1) {
		printf("Write error: %s\n", strerror(errno));
	}
	
	ret = syscall(SYS_write, fd, "\nplease", 7);
	printf("Write ret: %d\n", ret);

	if (ret == -1) {
		printf("Write error: %s\n", strerror(errno));
	}
	
	ret = syscall(SYS_close, fd);
	printf("Close ret: %d\n", ret);

	if (ret == -1) {
		printf("Close error: %s\n", strerror(errno));
	}

	return 0;
}
