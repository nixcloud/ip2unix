// SPDX-License-Identifier: LGPL-3.0-only
#include <algorithm>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <unordered_map>

#include <arpa/inet.h>

#include <yaml-cpp/yaml.h>

#include "../rules.hh"

#include "errno_list.hh"

static const std::string describe_nodetype(const YAML::Node &node)
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

    if (rule.socket_path) {
        if (rule.socket_path.value().empty())
            return "Socket path has to be non-empty.";
        if (rule.socket_path.value()[0] != '/')
            return "Socket path has to be absolute.";

#ifdef SOCKET_ACTIVATION
        if (rule.socket_activation)
            return "Can't enable socket activation in conjunction with a"
                   " socket path.";
#endif
        if (rule.reject)
            return "Using a reject action in conjuction with a socket"
                   " path is not allowed.";
    } else if (rule.reject) {
        return std::nullopt;
#ifdef SOCKET_ACTIVATION
    } else if (!rule.socket_activation) {
         return "Socket activation is disabled and no socket"
                " path or reject action was specified.";
#endif
    }

    return std::nullopt;
}

/* Convert a string into a port number, checking whether it satisfies bounds of
 * an uint16_t. First we convert to string, check whether everything is just
 * digits and whether the length is short enough for a 16 bit unsigned int and
 * then convert to uint32_t and check the upper bound.
 */
static inline std::optional<uint16_t> string2port(const std::string &str)
{
    std::string value(str);
    value.erase(0, str.find_first_not_of('0'));

    if (str.size() > 0 && value.empty())
        return 0;

    if (value.empty())
        return std::nullopt;

    if (std::all_of(value.begin(), value.end(), isdigit)) {
        uint32_t intval = std::stoi(value);
        if (value.length() <= 6 && intval <= 65535)
            return (uint16_t)intval;
        else
            return std::nullopt;
    }

    return std::nullopt;
}

static inline std::optional<int> parse_errno(const std::string &str)
{
    if (str.empty())
        return std::nullopt;

    if (std::all_of(str.begin(), str.end(), isdigit))
        return std::stoi(str);

    return name2errno(str);
}

#define RULE_ERROR(msg) \
    std::cerr << file << ":rule #" << pos + 1 << ": " << msg << std::endl

#define RULE_CONVERT(target, key, type, tname) \
    try { \
        target = value.as<type>(); \
    } catch (const YAML::BadConversion &e) { \
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
                rule.direction = RuleDir::OUTGOING;
            } else if (val == "incoming") {
                rule.direction = RuleDir::INCOMING;
            } else {
                RULE_ERROR("Invalid direction \"" << val << "\".");
                return std::nullopt;
            }
        } else if (key == "type") {
            std::string val;
            RULE_CONVERT(val, "type", std::string, "string");
            if (val == "tcp") {
                rule.type = SocketType::TCP;
            } else if (val == "udp") {
                rule.type = SocketType::UDP;
            } else {
                RULE_ERROR("Invalid type \"" << val << "\".");
                return std::nullopt;
            }
        } else if (key == "address") {
            RULE_CONVERT(rule.address, "address", std::string, "string");
        } else if (key == "port") {
            std::string val;
            RULE_CONVERT(val, "port", std::string, "16 bit unsigned int");
            std::optional<uint16_t> port = string2port(val);
            if (port) {
                rule.port = port.value();
            } else {
                RULE_ERROR("Port number is not a 16 bit unsigned int.");
                return std::nullopt;
            }
#ifdef SOCKET_ACTIVATION
        } else if (key == "socketActivation") {
            RULE_CONVERT(rule.socket_activation, "socketActivation", bool,
                         "bool");
        } else if (key == "fdName") {
            RULE_CONVERT(rule.fd_name, "fdName", std::string, "string");
#endif
        } else if (key == "reject") {
            RULE_CONVERT(rule.reject, "reject", bool, "bool");
        } else if (key == "rejectError") {
            std::string val;
            RULE_CONVERT(val, "rejectError", std::string, "string");
            std::optional<int> rej_errno = parse_errno(val);
            if (rej_errno) {
                rule.reject_errno = rej_errno;
            } else {
                RULE_ERROR("Invalid reject error code \"" << val << "\".");
                return std::nullopt;
            }
        } else if (key == "socketPath") {
            RULE_CONVERT(rule.socket_path, "socketPath", std::string,
                         "string");
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

std::optional<std::vector<Rule>>
    parse_rules(std::string content, bool content_is_filename)
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
    } catch (const YAML::BadFile &e) {
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
                    rule.socket_path = std::string(buf);
#ifdef SOCKET_ACTIVATION
                } else if (key.value() == "systemd") {
                    rule.socket_activation = true;
                    rule.fd_name = std::string(buf);
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
                    rule.address = std::string(buf);
                } else if (key.value() == "port") {
                    std::optional<uint16_t> port = string2port(buf);
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
#ifdef SOCKET_ACTIVATION
            } else if (buf == "systemd") {
                rule.socket_activation = true;
#endif
            } else if (buf == "reject") {
                rule.reject = true;
            } else {
                print_arg_error(rulepos, arg, errpos, errlen, "unknown flag");
                return std::nullopt;
            }
            errpos = i + 1;
            errlen = 0;
            buf.assign("");
            continue;
        } else if (arg[i] == '=') {
            key = std::string(buf);
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

std::string encode_rules(std::vector<Rule> rules)
{
    YAML::Node doc;

    for (const auto &rule : rules) {
        YAML::Node node;

        if (rule.direction) {
            if (rule.direction.value() == RuleDir::OUTGOING)
                node["direction"] = "outgoing";
            else if (rule.direction.value() == RuleDir::INCOMING)
                node["direction"] = "incoming";
        }

        if (rule.type) {
            if (rule.type.value() == SocketType::TCP)
                node["type"] = "tcp";
            else if (rule.type.value() == SocketType::UDP)
                node["type"] = "udp";
        }

        if (rule.address)
            node["address"] = rule.address.value();

        if (rule.port)
            node["port"] = rule.port.value();

        if (rule.socket_path)
            node["socketPath"] = rule.socket_path.value();

#ifdef SOCKET_ACTIVATION
        if (rule.socket_activation)
            node["socketActivation"] = true;

        if (rule.fd_name)
            node["fdName"] = rule.fd_name.value();
#endif

        if (rule.reject)
            node["reject"] = true;

        if (rule.reject_errno)
            node["rejectError"] = rule.reject_errno.value();

        doc.push_back(node);
    }

    return YAML::Dump(doc);
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
            << "  Address: " << rule.address.value_or("<any>") << std::endl
            << "  Port: " << portstr << std::endl;

#ifdef SOCKET_ACTIVATION
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
            } else {
                out << "  Socket path: " << rule.socket_path.value()
                    << std::endl;
            }
#ifdef SOCKET_ACTIVATION
        }
#endif
    }
}
