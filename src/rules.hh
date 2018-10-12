// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_RULES_HH
#define IP2UNIX_RULES_HH

#include <optional>
#include <vector>

enum class RuleIpType { TCP, UDP };
enum class RuleDir { INCOMING, OUTGOING };

struct UdsmapRule {
    RuleDir direction;
    std::optional<RuleIpType> type;
    std::optional<std::string> address;
    std::optional<uint16_t> port;
#ifdef SOCKET_ACTIVATION
    bool socket_activation;
    std::optional<std::string> fd_name;
#endif
    std::optional<std::string> socket_path;
};

std::optional<std::vector<UdsmapRule>> parse_rules(std::string file);
void print_rules(std::vector<UdsmapRule>&);

#endif
