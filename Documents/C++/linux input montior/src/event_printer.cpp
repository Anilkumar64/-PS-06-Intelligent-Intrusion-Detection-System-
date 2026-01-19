#include "input_event_parser.hpp"
#include <iostream>

std::string eventTypeToString(__u16 type)
{
    switch (type)
    {
    case EV_KEY:
        return "EV_KEY";
    case EV_REL:
        return "EV_REL";
    case EV_ABS:
        return "EV_ABS";
    case EV_SYN:
        return "EV_SYN";
    default:
        return "EV_OTHER";
    }
}

std::string keyCodeToString(__u16 code)
{
    switch (code)
    {
    case KEY_A:
        return "KEY_A";
    case KEY_B:
        return "KEY_B";
    case KEY_C:
        return "KEY_C";
    case KEY_ENTER:
        return "KEY_ENTER";
    case KEY_ESC:
        return "KEY_ESC";
    case BTN_LEFT:
        return "BTN_LEFT";
    case BTN_RIGHT:
        return "BTN_RIGHT";
    default:
        return "UNKNOWN_CODE";
    }
}

std::string valueToString(__s32 value)
{
    switch (value)
    {
    case 0:
        return "RELEASED";
    case 1:
        return "PRESSED";
    case 2:
        return "HELD";
    default:
        return "UNKNOWN_VALUE";
    }
}
