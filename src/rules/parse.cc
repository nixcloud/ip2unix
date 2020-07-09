// SPDX-License-Identifier: LGPL-3.0-only
#include <algorithm>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <unordered_map>

#include <arpa/inet.h>
#include <unistd.h>

#include "../rules.hh"

#include "errno_list.hh"

static std::optional<std::string> validate_rule(Rule &rule)
{
    if (rule.address) {
        char buf[INET6_ADDRSTRLEN];
        const char *addr = rule.address.value().c_str();
        if (
            !inet_pton(AF_INET, addr, buf) &&
            !inet_pton(AF_INET6, addr, buf)
        ) {
            return "Address \"" + rule.address.value() + "\""
                   " is not a valid IPv4 or IPv6 address.";
        }
    }

    if (!rule.port && rule.port_end)
        return "Port range has an ending port but no starting port.";

    if (rule.port && rule.port_end) {
        if (rule.port.value() > rule.port_end.value())
            return "Starting port in port range is bigger than end port.";
        if (rule.port.value() == rule.port_end.value())
            return "Ending port in port range has the same value as the"
                   " starting port.";
    }

    if (rule.socket_path) {
        if (rule.socket_path.value().empty())
            return "Socket path has to be non-empty.";
        if (rule.socket_path.value()[0] != '/')
            return "Socket path has to be absolute.";

#ifdef SYSTEMD_SUPPORT
        if (rule.socket_activation)
            return "Can't enable socket activation in conjunction with a"
                   " socket path.";
#endif
        if (rule.reject)
            return "Using a reject action in conjuction with a socket"
                   " path is not allowed.";

        if (rule.ignore)
            return "Using an ignore action in conjuction with a socket"
                   " path is not allowed.";

        if (rule.blackhole)
            return "Using a blackhole action in conjuction with a socket"
                   " path is not allowed.";
    } else if (rule.reject && rule.blackhole) {
        return "Reject and blackhole actions are mutually exclusive.";
    } else if (rule.ignore && (rule.blackhole || rule.reject)) {
        return "Ignore action can't be used in conjunction with blackhole"
               " or reject.";
#ifdef SYSTEMD_SUPPORT
    } else if (rule.ignore && rule.socket_activation) {
        return "Ignore action can't be used in conjunction with socket"
               " activation.";
#endif
    } else if (rule.reject || rule.ignore) {
        return std::nullopt;
    } else if (rule.blackhole) {
        if (rule.direction != RuleDir::INCOMING)
            return "Blackhole rules are only valid for incoming connections.";
        return std::nullopt;
#ifdef SYSTEMD_SUPPORT
    } else if (!rule.socket_activation) {
        return "Socket activation is disabled and no socket"
               " path, reject, ignore or blackhole action was specified.";
#else
    } else {
        return "No socket path, reject, ignore or blackhole action specified.";
#endif
    }

    return std::nullopt;
}

/* Convert a string into a port number, checking whether it satisfies bounds of
 * an uint16_t. First we convert to string, check whether everything is just
 * digits and whether the length is short enough for a 16 bit unsigned int and
 * then convert to uint32_t and check the upper bound.
 */
static std::optional<uint16_t> string2port(const std::string &str)
{
    std::string value(str);
    value.erase(0, str.find_first_not_of('0'));

    if (str.size() > 0 && value.empty())
        return 0;

    if (value.empty())
        return std::nullopt;

    if (std::all_of(value.begin(), value.end(), isdigit)) {
        uint32_t intval = std::stoul(value);
        if (value.length() <= 6 && intval <= 65535)
            return static_cast<uint16_t>(intval);
        else
            return std::nullopt;
    }

    return std::nullopt;
}

static std::optional<int> parse_errno(const std::string &str)
{
    if (str.empty())
        return std::nullopt;

    if (std::all_of(str.begin(), str.end(), isdigit))
        return std::stoi(str);

    return name2errno(str);
}

static void print_arg_error(size_t rulepos, const std::string &arg, size_t pos,
                            size_t len, const std::string &msg)
{
    std::string pos_str = std::to_string(rulepos);
    std::string pos_spc = std::string(pos_str.size(), ' ');

    std::cerr << "In rule #" << pos_str << ": " << arg << std::endl
              << "         " << pos_spc << "  ";

    if (pos == 0 && len == 0)
        std::cerr << msg << std::endl;
    else
        std::cerr << std::string(pos, ' ')
                  << std::string(std::max(len, static_cast<size_t>(1)), '^')
                  << ' ' << msg << std::endl;
}

std::string make_absolute(const std::string &path)
{
    if (path.empty() || path[0] == '/')
        return path;

    return std::string(get_current_dir_name()) + '/' + path;
}

std::optional<Rule> parse_rule_arg(size_t rulepos, const std::string &arg)
{
    std::string buf = "";
    std::optional<std::string> key = std::nullopt;

    Rule rule;

    size_t errpos = 0, valpos = 0;
    size_t errlen = 0;

    for (size_t i = 0, arglen = arg.length(); i <= arglen; ++i) {
        if (key) {
            if (i == arglen || arg[i] == ',') {
                /* Handle key=value options. */
                if (key.value() == "path") {
                    rule.socket_path = make_absolute(buf);
#ifdef SYSTEMD_SUPPORT
                } else if (key.value() == "systemd") {
                    rule.socket_activation = true;
                    rule.fd_name = buf;
#endif
                } else if (key.value() == "reject") {
                    rule.reject = true;
                    std::optional<int> rej_errno = parse_errno(buf);
                    if (rej_errno) {
                        rule.reject_errno = rej_errno.value();
                    } else {
                        print_arg_error(rulepos, arg, valpos, i - valpos,
                                        "invalid reject error code");
                        return std::nullopt;
                    }
                } else if (key.value() == "addr" || key.value() == "address") {
                    rule.address = buf;
                } else if (key.value() == "port") {
                    /* Handle port ranges, like "1000-2000". */
                    std::size_t rangesep = buf.find('-');
                    std::string portbuf;
                    if (rangesep == std::string::npos || rangesep == 0) {
                        portbuf = buf;
                    } else {
                        portbuf = buf.substr(0, rangesep);
                        std::optional<uint16_t> portend =
                            string2port(buf.substr(rangesep + 1));
                        if (portend) {
                            rule.port_end = portend.value();
                        } else {
                            print_arg_error(rulepos, arg,
                                            valpos + rangesep + 1,
                                            i - valpos - rangesep - 1,
                                            "invalid end port in range");
                            return std::nullopt;
                        }
                    }

                    std::optional<uint16_t> port = string2port(portbuf);
                    if (port) {
                        rule.port = port.value();
                    } else {
                        print_arg_error(rulepos, arg, valpos, i - valpos,
                                        "invalid port");
                        return std::nullopt;
                    }
                } else {
                    print_arg_error(rulepos, arg, errpos, errlen,
                                    "unknown key");
                    return std::nullopt;
                }
                key = std::nullopt;
                errpos = i + 1;
                errlen = 0;
                buf.assign("");
                continue;
            } else if (arg[i] == '\\' && i < arglen && (arg[i + 1] == ',' ||
                                                        arg[i + 1] == '\\')) {
                buf += arg[++i];
                continue;
            }
        } else if (i == arglen || arg[i] == ',') {
            /* Handle bareword toggle flags. */
            if (buf == "tcp") {
                rule.type = SocketType::TCP;
            } else if (buf == "udp") {
                rule.type = SocketType::UDP;
            } else if (buf == "in") {
                rule.direction = RuleDir::INCOMING;
            } else if (buf == "out") {
                rule.direction = RuleDir::OUTGOING;
#ifdef SYSTEMD_SUPPORT
            } else if (buf == "systemd") {
                rule.socket_activation = true;
#endif
            } else if (buf == "reject") {
                rule.reject = true;
            } else if (buf == "blackhole") {
                rule.blackhole = true;
            } else if (buf == "ignore") {
                rule.ignore = true;
            } else {
                print_arg_error(rulepos, arg, errpos, errlen, "unknown flag");
                return std::nullopt;
            }
            errpos = i + 1;
            errlen = 0;
            buf.assign("");
            continue;
        } else if (arg[i] == '=') {
            key = buf;
            valpos = i + 1;
            buf.assign("");
            continue;
        } else {
            errlen += 1;
        }

        buf += arg[i];
    }

    std::optional<std::string> errmsg = validate_rule(rule);
    if (errmsg) {
        print_arg_error(rulepos, arg, 0, 0, errmsg.value());
        return std::nullopt;
    }

    return rule;
}

void print_rules(std::vector<Rule> &rules, std::ostream &out)
{
    int pos = 0;
    for (Rule &rule : rules) {
        std::string dirstr;
        if (rule.direction == RuleDir::INCOMING)
            dirstr = "incoming";
        else if (rule.direction == RuleDir::OUTGOING)
            dirstr = "outgoing";
        else
            dirstr = "both";

        std::string typestr;
        if (rule.type == SocketType::TCP)
            typestr = "TCP";
        else if (rule.type == SocketType::UDP)
            typestr = "UDP";
        else
            typestr = "TCP and UDP";

        std::string portstr;
        if (rule.port)
            portstr = std::to_string(rule.port.value());
        else
            portstr = "<any>";

        out << "Rule #" << ++pos << ':' << std::endl
            << "  Direction: " << dirstr << std::endl
            << "  IP Type: " << typestr << std::endl
            << "  Address: " << rule.address.value_or("<any>") << std::endl;

        if (rule.port_end) {
            out << "  Ports: " << portstr << " - "
                << std::to_string(rule.port_end.value())
                << std::endl;
        } else {
            out << "  Port: " << portstr << std::endl;
        }

#ifdef SYSTEMD_SUPPORT
        if (rule.socket_activation) {
            out << "  Socket activation";
            if (rule.fd_name) {
                out << " with file descriptor name: "
                    << rule.fd_name.value() << std::endl;
            } else {
                out << "." << std::endl;
            }
        } else {
#endif
            if (rule.reject) {
                out << "  Reject connect() and bind() calls";
                if (rule.reject_errno)
                    out << " with errno "
                        << errno2name(rule.reject_errno.value());
                out << "." << std::endl;
            } else if (rule.blackhole) {
                out << "  Blackhole the socket." << std::endl;
            } else if (rule.ignore) {
                out << "  Don't handle this socket." << std::endl;
            } else {
                out << "  Socket path: " << rule.socket_path.value()
                    << std::endl;
            }
#ifdef SYSTEMD_SUPPORT
        }
#endif
    }
}
