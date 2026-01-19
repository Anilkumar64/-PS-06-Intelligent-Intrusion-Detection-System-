#include <fcntl.h>
#include <unistd.h>
#include <iostream>

int openInputDevice(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        perror("open");
    }
    return fd;
}
