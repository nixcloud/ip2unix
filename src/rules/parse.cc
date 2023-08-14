// SPDX-License-Identifier: LGPL-3.0-only
#include "../rules.hh"
#include "errno_list.hh"
#include "types.hh"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

static std::string describe_nodetype(const YAML::Node &node)
{
    switch (node.Type()) {
        case YAML::NodeType::Undefined: return "undefined";
        case YAML::NodeType::Null:      return "null";
        case YAML::NodeType::Scalar:    return "a scalar";
        case YAML::NodeType::Sequence:  return "a sequence";
        case YAML::NodeType::Map:       return "a map";
    }
    return "an unknown type";
}

static std::optional<std::string> validate_rule(Rule &rule)
{
    if (rule.matches.address) {
        char buf[INET6_ADDRSTRLEN];
        const char *addr = rule.matches.address.value().c_str();
        if (
            inet_pton(AF_INET, addr, buf) == 0 &&
            inet_pton(AF_INET6, addr, buf) == 0
        ) {
            return "Address \"" + rule.matches.address.value() + "\""
                   " is not a valid IPv4 or IPv6 address.";
        }
    }

    if (!rule.matches.port && rule.matches.port_end)
        return "Port range has an ending port but no starting port.";

    if (rule.matches.port && rule.matches.port_end) {
        if (rule.matches.port.value() > rule.matches.port_end.value())
            return "Starting port in port range is bigger than end port.";
        if (rule.matches.port.value() == rule.matches.port_end.value())
            return "Ending port in port range has the same value as the"
                   " starting port.";
    }

    if (rule.action.socket_path) {
        if (rule.action.socket_path->type == SocketPath::Type::FILESYSTEM) {
            const std::string path = rule.action.socket_path->value;

            if (path.empty())
                return "Socket path has to be non-empty.";
            if (path[0] != '/')
                return "Socket path has to be absolute.";

#ifdef SYSTEMD_SUPPORT
            if (rule.action.socket_activation)
                return "Can't enable socket activation in conjunction with a"
                       " socket path.";
#endif
            if (rule.action.reject)
                return "Using a reject action in conjuction with a socket"
                       " path is not allowed.";

            if (rule.action.ignore)
                return "Using an ignore action in conjuction with a socket"
                       " path is not allowed.";

            if (rule.action.blackhole)
                return "Using a blackhole action in conjuction with a socket"
                       " path is not allowed.";
#if defined(__linux__)
        } else if (
            rule.action.socket_path->type == SocketPath::Type::ABSTRACT
        ) {
            if (rule.action.socket_path->value.empty())
                return "Abstract socket name has to be non-empty.";

#ifdef SYSTEMD_SUPPORT
            if (rule.action.socket_activation)
                return "Can't enable socket activation in conjunction with an"
                       " abstract socket name.";
#endif

            if (rule.action.reject)
                return "Using a reject action in conjuction with an abstract"
                       " socket name is not allowed.";

            if (rule.action.ignore)
                return "Using an ignore action in conjuction with an abstract"
                       " socket name is not allowed.";

            if (rule.action.blackhole)
                return "Using a blackhole action in conjuction with an"
                       " abstract socket name is not allowed.";
#endif
        }
    } else if (rule.action.reject && rule.action.blackhole) {
        return "Reject and blackhole actions are mutually exclusive.";
    } else if (
        rule.action.ignore && (rule.action.blackhole || rule.action.reject)
    ) {
        return "Ignore action can't be used in conjunction with blackhole"
               " or reject.";
#ifdef SYSTEMD_SUPPORT
    } else if (rule.action.ignore && rule.action.socket_activation) {
        return "Ignore action can't be used in conjunction with socket"
               " activation.";
#endif
    } else if (rule.action.reject || rule.action.ignore) {
        return std::nullopt;
    } else if (rule.action.blackhole) {
        if (rule.matches.direction != RuleDir::INCOMING)
            return "Blackhole rules are only valid for incoming connections.";
        return std::nullopt;
#ifdef SYSTEMD_SUPPORT
    } else if (!rule.action.socket_activation) {
        return "Socket activation is disabled and no socket"
               " path, abstract name, reject, ignore or blackhole action was"
               " specified.";
#else
    } else {
        return "No socket path, abstract name, reject, ignore or blackhole"
               " action specified.";
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

    if (!str.empty() && value.empty())
        return 0;

    if (value.empty())
        return std::nullopt;

    if (std::all_of(value.begin(), value.end(), isdigit)) {
        uint32_t intval = std::stoul(value);

        if (value.length() <= 6 && intval <= 65535)
            return static_cast<uint16_t>(intval);

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

// NOLINTBEGIN(bugprone-macro-parentheses)
#define RULE_ERROR(msg) \
    std::cerr << file << ":rule #" << pos + 1 << ": " << msg << std::endl
// NOLINTEND(bugprone-macro-parentheses)

#define RULE_CONVERT(target, key, type, tname) \
    try { \
        (target) = value.as<type>(); \
    } catch (const YAML::BadConversion&) { \
        RULE_ERROR("The \"" key "\" option needs to be a " tname "."); \
        return std::nullopt; \
    }

static std::optional<Rule> parse_rule(const std::string &file, int pos,
                                      const YAML::Node &doc)
{
    Rule rule;

    for (const auto &foo : doc) {
        std::string key = foo.first.as<std::string>();
        YAML::Node value = foo.second;
        if (key == "direction") {
            std::string val;
            RULE_CONVERT(val, "direction", std::string, "string");
            if (val == "outgoing") {
                rule.matches.direction = RuleDir::OUTGOING;
            } else if (val == "incoming") {
                rule.matches.direction = RuleDir::INCOMING;
            } else {
                RULE_ERROR("Invalid direction \"" << val << "\".");
                return std::nullopt;
            }
        } else if (key == "type") {
            std::string val;
            RULE_CONVERT(val, "type", std::string, "string");
            if (val == "tcp" || val == "stream") {
                rule.matches.type = SocketType::STREAM;
            } else if (val == "udp" || val == "dgram" || val == "datagram") {
                rule.matches.type = SocketType::DATAGRAM;
            } else {
                RULE_ERROR("Invalid type \"" << val << "\".");
                return std::nullopt;
            }
        } else if (key == "address") {
            RULE_CONVERT(rule.matches.address, "address", std::string,
                         "string");
        } else if (key == "port") {
            std::string val;
            RULE_CONVERT(val, "port", std::string, "16 bit unsigned int");
            std::optional<uint16_t> port = string2port(val);
            if (port) {
                rule.matches.port = port.value();
            } else {
                RULE_ERROR("Port number is not a 16 bit unsigned int.");
                return std::nullopt;
            }
        } else if (key == "portEnd") {
            std::string val;
            RULE_CONVERT(val, "portEnd", std::string, "16 bit unsigned int");
            std::optional<uint16_t> portend = string2port(val);
            if (portend) {
                rule.matches.port_end = portend.value();
            } else {
                RULE_ERROR("Port range end number is not a "
                           "16 bit unsigned int.");
                return std::nullopt;
            }
#ifdef SYSTEMD_SUPPORT
        } else if (key == "socketActivation") {
            RULE_CONVERT(rule.action.socket_activation, "socketActivation",
                         bool, "bool");
        } else if (key == "fdName") {
            RULE_CONVERT(rule.action.fd_name, "fdName", std::string, "string");
#endif
        } else if (key == "reject") {
            RULE_CONVERT(rule.action.reject, "reject", bool, "bool");
        } else if (key == "rejectError") {
            std::string val;
            RULE_CONVERT(val, "rejectError", std::string, "string");
            std::optional<int> rej_errno = parse_errno(val);
            if (rej_errno) {
                rule.action.reject_errno = rej_errno;
            } else {
                RULE_ERROR("Invalid reject error code \"" << val << "\".");
                return std::nullopt;
            }
        } else if (key == "blackhole") {
            RULE_CONVERT(rule.action.blackhole, "blackhole", bool, "bool");
        } else if (key == "ignore") {
            RULE_CONVERT(rule.action.ignore, "ignore", bool, "bool");
        } else if (key == "socketPath") {
            if (rule.action.socket_path) {
                RULE_ERROR("Socket path or abstract name already specified.");
                return std::nullopt;
            }
            std::string path;
            RULE_CONVERT(path, "socketPath", std::string, "string");
            rule.action.socket_path =
                SocketPath(SocketPath::Type::FILESYSTEM, path);
#if defined(__linux__)
        } else if (key == "abstract") {
            if (rule.action.socket_path) {
                RULE_ERROR("Socket path or abstract name already specified.");
                return std::nullopt;
            }
            std::string name;
            RULE_CONVERT(name, "abstract", std::string, "string");
            rule.action.socket_path =
                SocketPath(SocketPath::Type::ABSTRACT, name);
#endif
        } else {
            RULE_ERROR("Invalid key \"" << key << "\".");
            return std::nullopt;
        }
    }

    std::optional<std::string> errmsg = validate_rule(rule);
    if (errmsg) {
        RULE_ERROR(errmsg.value());
        return std::nullopt;
    }

    return rule;
}

bool is_yaml_rule_file(const std::string &filename)
{
    YAML::Node doc;

    try {
        doc = YAML::LoadFile(filename);
    } catch (const YAML::ParserException&) {
        return false;
    } catch (const YAML::BadFile&) {
        // If the file can't be opened, let's assume it's YAML for now, since
        // we're going to eventually throw an error anyway.
        return true;
    }

    return doc.IsSequence();
}

std::optional<std::vector<Rule>>
    parse_rules(const std::string &content, bool content_is_filename)
{
    YAML::Node doc;
    std::string file = content_is_filename ? content : "<unknown>";

    try {
        if (content_is_filename)
            doc = YAML::LoadFile(file);
        else
            doc = YAML::Load(content);
    } catch (const YAML::ParserException &e) {
        std::cerr << file << ": " << e.msg << std::endl;
        return std::nullopt;
    } catch (const YAML::BadFile&) {
        std::cerr << "Unable to open file \"" << file << "\"." << std::endl;
        return std::nullopt;
    }

    if (!doc.IsSequence()) {
        std::cerr << file << ": Root node needs to be a sequence but it's "
                  << describe_nodetype(doc) << " instead." << std::endl;
        return std::nullopt;
    }

    std::vector<Rule> result;

    int pos = 0;
    for (const YAML::Node &node : doc) {
        std::optional<Rule> rule = parse_rule(file, pos++, node);
        if (!rule) return std::nullopt;
        result.push_back(rule.value());
    }

    return result;
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

std::optional<Rule> parse_rule_arg(size_t rulepos, const std::string &arg)
{
    std::string buf;
    std::optional<std::string> key = std::nullopt;

    Rule rule;

    size_t errpos = 0, valpos = 0;
    size_t errlen = 0;

    for (size_t i = 0, arglen = arg.length(); i <= arglen; ++i) {
        if (key) {
            if (i == arglen || arg[i] == ',') {
                /* Handle key=value options. */
                if (key.value() == "path") {
                    if (rule.action.socket_path) {
                        print_arg_error(
                            rulepos, arg, errpos, errlen,
                            "socket path or abstract name specified earlier"
                        );
                        return std::nullopt;
                    }
                    rule.action.socket_path = SocketPath(
                        SocketPath::Type::FILESYSTEM,
                        std::filesystem::absolute(buf)
                    );
#if defined(__linux__)
                } else if (key.value() == "abstract") {
                    if (rule.action.socket_path) {
                        print_arg_error(
                            rulepos, arg, errpos, errlen,
                            "socket path or abstract name specified earlier"
                        );
                        return std::nullopt;
                    }
                    rule.action.socket_path = SocketPath(
                        SocketPath::Type::ABSTRACT,
                        buf
                    );
#endif
#ifdef SYSTEMD_SUPPORT
                } else if (key.value() == "systemd") {
                    rule.action.socket_activation = true;
                    rule.action.fd_name = buf;
#endif
                } else if (key.value() == "reject") {
                    rule.action.reject = true;
                    std::optional<int> rej_errno = parse_errno(buf);
                    if (rej_errno) {
                        rule.action.reject_errno = rej_errno.value();
                    } else {
                        print_arg_error(rulepos, arg, valpos, i - valpos,
                                        "invalid reject error code");
                        return std::nullopt;
                    }
                } else if (key.value() == "addr" || key.value() == "address") {
                    rule.matches.address = buf;
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
                            rule.matches.port_end = portend.value();
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
                        rule.matches.port = port.value();
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
            }

            if (arg[i] == '\\' && i < arglen && (arg[i + 1] == ',' ||
                                                 arg[i + 1] == '\\')) {
                buf += arg[++i];
                continue;
            }
        } else if (i == arglen || arg[i] == ',') {
            /* Handle bareword toggle flags. */
            if (buf == "tcp" || buf == "stream") {
                rule.matches.type = SocketType::STREAM;
            } else if (buf == "udp" || buf == "dgram" || buf == "datagram") {
                rule.matches.type = SocketType::DATAGRAM;
            } else if (buf == "in") {
                rule.matches.direction = RuleDir::INCOMING;
            } else if (buf == "out") {
                rule.matches.direction = RuleDir::OUTGOING;
#ifdef SYSTEMD_SUPPORT
            } else if (buf == "systemd") {
                rule.action.socket_activation = true;
#endif
            } else if (buf == "reject") {
                rule.action.reject = true;
            } else if (buf == "blackhole") {
                rule.action.blackhole = true;
            } else if (buf == "ignore") {
                rule.action.ignore = true;
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
        if (rule.matches.direction == RuleDir::INCOMING)
            dirstr = "incoming";
        else if (rule.matches.direction == RuleDir::OUTGOING)
            dirstr = "outgoing";
        else
            dirstr = "both";

        std::string typestr;
        if (rule.matches.type == SocketType::STREAM)
            typestr = "TCP";
        else if (rule.matches.type == SocketType::DATAGRAM)
            typestr = "UDP";
        else
            typestr = "TCP and UDP";

        std::string portstr;
        if (rule.matches.port)
            portstr = std::to_string(rule.matches.port.value());
        else
            portstr = "<any>";

        out << "Rule #" << ++pos << ':' << std::endl
            << "  Direction: " << dirstr << std::endl
            << "  IP Type: " << typestr << std::endl
            << "  Address: " << rule.matches.address.value_or("<any>")
            << std::endl;

        if (rule.matches.port_end) {
            out << "  Ports: " << portstr << " - "
                << std::to_string(rule.matches.port_end.value())
                << std::endl;
        } else {
            out << "  Port: " << portstr << std::endl;
        }

#ifdef SYSTEMD_SUPPORT
        if (rule.action.socket_activation) {
            out << "  Socket activation";
            if (rule.action.fd_name) {
                out << " with file descriptor name: "
                    << rule.action.fd_name.value() << std::endl;
            } else {
                out << "." << std::endl;
            }
        } else {
#endif
            if (rule.action.reject) {
                out << "  Reject connect() and bind() calls";
                if (rule.action.reject_errno)
                    out << " with errno "
                        << errno2name(rule.action.reject_errno.value());
                out << "." << std::endl;
            } else if (rule.action.blackhole) {
                out << "  Blackhole the socket." << std::endl;
            } else if (rule.action.ignore) {
                out << "  Don't handle this socket." << std::endl;
            } else if (rule.action.socket_path) {
#if defined(__linux__)
                if (
                    rule.action.socket_path->type == SocketPath::Type::ABSTRACT
                ) {
                    out << "  Abstract name: "
                        << rule.action.socket_path->value
                        << std::endl;
                } else {
#endif
                    out << "  Socket path: "
                        << rule.action.socket_path->value
                        << std::endl;
#if defined(__linux__)
                }
#endif
            }
#ifdef SYSTEMD_SUPPORT
        }
#endif
    }
}
