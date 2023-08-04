// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_RULES_HH
#define IP2UNIX_RULES_HH

#include "types.hh"

#include <iostream>
#include <optional>
#include <vector>

#include <netinet/in.h>

enum class RuleDir { INCOMING, OUTGOING };

struct Rule {
    std::optional<RuleDir> direction = std::nullopt;
    std::optional<SocketType> type = std::nullopt;
    std::optional<std::string> address = std::nullopt;
    std::optional<uint16_t> port = std::nullopt;
    std::optional<uint16_t> port_end = std::nullopt;

#ifdef SYSTEMD_SUPPORT
    bool socket_activation = false;
    std::optional<std::string> fd_name = std::nullopt;
#endif

    std::optional<std::string> socket_path = std::nullopt;

    bool reject = false;
    std::optional<int> reject_errno = std::nullopt;

    bool blackhole = false;
    bool ignore = false;
};

bool is_yaml_rule_file(const std::string&);
std::optional<std::vector<Rule>> parse_rules(const std::string&, bool);
std::optional<Rule> parse_rule_arg(size_t, const std::string&);
void print_rules(std::vector<Rule>&, std::ostream&);

#endif
