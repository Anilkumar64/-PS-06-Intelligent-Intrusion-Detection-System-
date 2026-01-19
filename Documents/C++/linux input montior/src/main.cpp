#include <iostream>
#include <linux/input.h>
#include <unistd.h>

#include "input_event_parser.hpp"

int openInputDevice(const char *path);
bool readInputEvent(int fd, struct input_event &ev);

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " /dev/input/eventX\n";
        return 1;
    }

    int fd = openInputDevice(argv[1]);
    if (fd == -1)
        return 1;

    std::cout << "Listening on " << argv[1] << "\n";

    struct input_event ev;

    while (true)
    {
        if (!readInputEvent(fd, ev))
            break;

        std::cout << "Time: " << ev.time.tv_sec
                  << "." << ev.time.tv_usec << " ";

        std::cout << "[" << eventTypeToString(ev.type) << "] ";

        if (ev.type == EV_KEY)
        {
            std::cout << keyCodeToString(ev.code)
                      << " " << valueToString(ev.value);
        }
        else if (ev.type == EV_REL)
        {
            std::cout << "Code: " << ev.code
                      << " Value: " << ev.value;
        }

        std::cout << "\n";
    }

    close(fd);
    return 0;
}
