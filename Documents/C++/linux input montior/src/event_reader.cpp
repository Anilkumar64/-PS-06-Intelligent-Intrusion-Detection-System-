#include <unistd.h>
#include <linux/input.h>
#include <iostream>

bool readInputEvent(int fd, struct input_event &ev)
{
    ssize_t n = read(fd, &ev, sizeof(ev));
    if (n == -1)
    {
        perror("read");
        return false;
    }
    if (n != sizeof(ev))
    {
        std::cerr << "Partial read\n";
        return false;
    }
    return true;
}
