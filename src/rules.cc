// SPDX-License-Identifier: LGPL-3.0-only
#include <algorithm>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>

#include <arpa/inet.h>

#include <yaml-cpp/yaml.h>

#include "rules.hh"

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

#define RULE_ERROR(msg) \
    std::cerr << file << ":rule #" << pos << ": " << msg << std::endl

static bool validate_rule(const std::string &file, int pos, UdsmapRule &rule)
{
    if (rule.address) {
        char buf[INET6_ADDRSTRLEN];
        const char *addr = rule.address.value().c_str();
        if (
            !inet_pton(AF_INET, addr, buf) &&
            !inet_pton(AF_INET6, addr, buf)
        ) {
            RULE_ERROR("Address \"" << rule.address.value() << "\""
                       " is not a valid IPv4 or IPv6 address.");
            return false;
        }
    }

    if (!rule.socket_path || rule.socket_path.value().empty()) {
#ifdef SOCKET_ACTIVATION
        if (!rule.socket_activation) {
            RULE_ERROR("Socket activation is disabled and no socket"
                       " path was specified.");
            return false;
        }
#else
        RULE_ERROR("No socket path specified.");
        return false;
#endif
    } else if (rule.socket_path.value()[0] != '/') {
        RULE_ERROR("Socket path has to be absolute.");
        return false;
    }

#ifdef SOCKET_ACTIVATION
    if (rule.socket_path && rule.socket_activation) {
        RULE_ERROR("Can't enable socket activation in conjunction with a"
                   " socket path.");
        return false;
    }
#endif

    return true;
}

#define RULE_CONVERT(target, key, type, tname) \
    try { \
        target = value.as<type>(); \
    } catch (const YAML::BadConversion &e) { \
        RULE_ERROR("The \"" key "\" option needs to be a " tname "."); \
        return std::nullopt; \
    }

static std::optional<UdsmapRule> parse_rule(const std::string &file, int pos,
                                            const YAML::Node &doc)
{
    UdsmapRule rule;

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
                rule.type = RuleIpType::TCP;
            } else if (val == "udp") {
                rule.type = RuleIpType::UDP;
            } else {
                RULE_ERROR("Invalid type \"" << val << "\".");
                return std::nullopt;
            }
        } else if (key == "address") {
            RULE_CONVERT(rule.address, "address", std::string, "string");
        } else if (key == "port") {
            // FIXME: Very ugly! We convert first to string, check for digits
            //        and whether the length is short enough and then convert
            //        to uint32_t and check the upper bound. This is because
            //        yaml-cpp only casts to the target type without bounds
            //        checking.
            std::string val;
            RULE_CONVERT(val, "port", std::string, "16 bit unsigned int");
            if (std::all_of(val.begin(), val.end(), isdigit)) {
                uint32_t intval = value.as<uint32_t>();
                if (val.length() <= 6 && intval <= 65535) {
                    rule.port = (uint16_t)intval;
                } else {
                    RULE_ERROR("Port number is not in range 0..65535.");
                    return std::nullopt;
                }
            } else {
                RULE_ERROR("Invalid port value \"" << val << "\".");
                return std::nullopt;
            }
#ifdef SOCKET_ACTIVATION
        } else if (key == "socketActivation") {
            RULE_CONVERT(rule.socket_activation, "socketActivation", bool,
                         "bool");
        } else if (key == "fdName") {
            RULE_CONVERT(rule.fd_name, "fdName", std::string, "string");
#endif
        } else if (key == "socketPath") {
            RULE_CONVERT(rule.socket_path, "socketPath", std::string,
                         "string");
        } else {
            RULE_ERROR("Invalid key \"" << key << "\".");
            return std::nullopt;
        }
    }

    if (!validate_rule(file, pos, rule))
        return std::nullopt;

    return rule;
}

std::optional<std::vector<UdsmapRule>> parse_rules(std::string file)
{
    YAML::Node doc;

    try {
        doc = YAML::LoadFile(file);
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

    std::vector<UdsmapRule> result;

    int pos = 0;
    for (const YAML::Node &node : doc) {
        std::optional<UdsmapRule> rule = parse_rule(file, pos++, node);
        if (!rule) return std::nullopt;
        result.push_back(rule.value());
    }

    return result;
}

void print_rules(std::vector<UdsmapRule> &rules, std::ostream &out)
{
    int pos = 0;
    for (UdsmapRule &rule : rules) {
        std::string dirstr;
        if (rule.direction == RuleDir::INCOMING)
            dirstr = "incoming";
        else if (rule.direction == RuleDir::OUTGOING)
            dirstr = "outgoing";

        std::string typestr;
        if (rule.type == RuleIpType::TCP)
            typestr = "TCP";
        else if (rule.type == RuleIpType::UDP)
            typestr = "UDP";
        else
            typestr = "TCP and UDP";

        std::string portstr;
        if (rule.port)
            portstr = std::to_string(rule.port.value());
        else
            portstr = "<any>";

        out << "Rule #" << pos++ << ':' << std::endl
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
            out << "  Socket path: " << rule.socket_path.value() << std::endl;
#ifdef SOCKET_ACTIVATION
        }
#endif
    }
}
