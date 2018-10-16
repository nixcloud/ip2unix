// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_RULES_HH
#define IP2UNIX_RULES_HH

#include <iostream>
#include <optional>
#include <vector>

enum class RuleIpType { TCP, UDP };
enum class RuleDir { INCOMING, OUTGOING };

struct UdsmapRule {
    RuleDir direction = RuleDir::INCOMING;
    std::optional<RuleIpType> type = std::nullopt;
    std::optional<std::string> address = std::nullopt;
    std::optional<uint16_t> port = std::nullopt;
#ifdef SOCKET_ACTIVATION
    bool socket_activation = false;
    std::optional<std::string> fd_name = std::nullopt;
#endif
    std::optional<std::string> socket_path = std::nullopt;
};

std::optional<std::vector<UdsmapRule>> parse_rules(std::string file, bool);
std::string encode_rules(std::vector<UdsmapRule>);
void print_rules(std::vector<UdsmapRule>&, std::ostream&);

#endif
