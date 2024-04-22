#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

int main(int argc, char** argv) {
	printf("PID: %d\n", getpid());

	int ret = syscall(SYS_openat, -100, "testfile", O_RDWR);
	printf("Openat ret: %d\n", ret);

	if (ret == -1) {
		printf("Opneat error: %s\n", strerror(errno));
	}

	ret = syscall(SYS_write, ret, "writing this :)", 14);
	printf("Write ret: %d\n", ret);

	if (ret == -1) {
		printf("Write error: %s\n", strerror(errno));
	}

	return 0;
}
