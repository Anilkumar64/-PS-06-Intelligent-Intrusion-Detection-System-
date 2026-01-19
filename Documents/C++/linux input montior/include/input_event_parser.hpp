#ifndef INPUT_EVENT_PARSER_HPP
#define INPUT_EVENT_PARSER_HPP

#include <linux/input.h>
#include <string>

std::string eventTypeToString(__u16 type);
std::string keyCodeToString(__u16 code);
std::string valueToString(__s32 value);

#endif
