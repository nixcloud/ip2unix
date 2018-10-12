// SPDX-License-Identifier: LGPL-3.0-only
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>

#include <rapidjson/error/en.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/schema.h>
#include <rapidjson/stringbuffer.h>

#include "rules.hh"

/* FIXME: Revise this schema once RapidJSON supports a newer specification. */
static const char *RulesSchema = R"schema(
{
  // RapidJSON currently only supports draft-04.
  "$schema": "http://json-schema.org/draft-04/schema#",

  "id": "urn:uuid:db179ece-5967-4fab-8573-7f3fe18dafd2",
  "title": "IP2Unix rules",
  "description": "A set of rules for transforming IP to Unix sockets",
  "type": "array",
  "additionalItems": false,
  "items": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "direction": {
        "description": "Whether it's an outgoing or incoming socket.",
        "type": "string",
        "enum": ["incoming", "outgoing"]
      },
      "type": {
        "description": "The IP type for this rule to match.",
        "type": "string",
        "enum": ["tcp", "udp"]
      },
      "address": {
        "description": "The IPv4 or IPv6 address to match.",
        "type": "string",
        "format": "ip-address",
        // Fallback pattern because RapidJSON 1.1.0 doesn't support formats.
        "pattern": "^(([0-9]+\\.){3}[0-9]+)|([a-fA-F0-9]*:[a-fA-F0-9:.]*)$"
      },
      "port": {
        "description": "The TCP or UDP port to match.",
        "type": "integer",
        "minimum": 0,
        "maximum": 65535
      },
)schema"
#ifdef SOCKET_ACTIVATION
R"schema(
      "socketActivation": {
        "description": "Use systemd socket activation.",
        "type": "boolean"
      },
      "fdName": {
        "description": "The file descriptor name for socket activation.",
        "type": "string"
      },
)schema"
#endif
R"schema(
      "socketPath": {
        "description": "The absolute path of the Unix Domain Socket.",
        "type": "string",
        "pattern": "^/"
      }
    }
  }
}
)schema";

using namespace rapidjson;

static void print_parse_error(const std::string &file, Document &doc)
{
    std::cerr << file << ':' << doc.GetErrorOffset() << ": "
              << GetParseError_En(doc.GetParseError()) << std::endl;
}

static std::optional<SchemaDocument> parse_schema(void)
{
    Document doc;

    if (doc.Parse<kParseCommentsFlag>(RulesSchema).HasParseError()) {
        print_parse_error("(schema)", doc);
        return std::nullopt;
    }

    return SchemaDocument(doc);
}

static std::optional<UdsmapRule> parse_rule(const std::string &file, int pos,
                                            const Value &doc)
{
    UdsmapRule rule;

#ifdef SOCKET_ACTIVATION
    rule.socket_activation = false;
#endif

    for (auto &node : doc.GetObject()) {
        std::string key = node.name.GetString();
        if (key == "direction") {
            std::string val = node.value.GetString();
            if (val == "outgoing")
                rule.direction = RuleDir::OUTGOING;
            else
                rule.direction = RuleDir::INCOMING;
        } else if (key == "type") {
            std::string val = node.value.GetString();
            if (val == "tcp")
                rule.type = RuleIpType::TCP;
            else if (val == "udp")
                rule.type = RuleIpType::UDP;
        } else if (key == "address") {
            rule.address = node.value.GetString();
        } else if (key == "port") {
            rule.port = node.value.GetUint();
#ifdef SOCKET_ACTIVATION
        } else if (key == "socketActivation") {
            rule.socket_activation = node.value.GetBool();
        } else if (key == "fdName") {
            rule.fd_name = node.value.GetString();
#endif
        } else if (key == "socketPath") {
            rule.socket_path = node.value.GetString();
        }
    }

    if (!rule.socket_path) {
#ifdef SOCKET_ACTIVATION
        if (!rule.socket_activation) {
            std::cerr << file << ":rule #" << pos << ": "
                      << "Socket activation is disabled and no "
                      << "socket path was specified." << std::endl;
            return std::nullopt;
        }
#else
        std::cerr << file << ":rule #" << pos << ": "
                  << "No socket path specified." << std::endl;
        return std::nullopt;
#endif
    }

#ifdef SOCKET_ACTIVATION
    if (rule.socket_path && rule.socket_activation) {
        std::cerr << file << ":rule #" << pos << ": "
                  << "Can't enable socket activation in conjunction "
                  << "with a socket path." << std::endl;
        return std::nullopt;
    }
#endif

    return rule;
}

std::optional<std::vector<UdsmapRule>> parse_rules(std::string file)
{
    std::optional<SchemaDocument> schema = parse_schema();
    if (!schema)
        return std::nullopt;

    Document doc;
    std::ifstream stream(file);
    IStreamWrapper rulestream(stream);

    if (doc.ParseStream(rulestream).HasParseError()) {
        print_parse_error(file, doc);
        return std::nullopt;
    }

    SchemaValidator validator(schema.value());
    if (!doc.Accept(validator)) {
        // FIXME: Better errors are coming soon with RapidJSON 1.2.0:
        // https://github.com/Tencent/rapidjson/pull/1068
        StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        std::string schema_token = sb.GetString();
        std::string schema_keyword = validator.GetInvalidSchemaKeyword();
        sb.Clear();
        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        std::cerr << file << ": "
                  << "Error \"" << schema_keyword << "\""
                  << " in pointer " << sb.GetString()
                  << " (" << schema_token << ")."
                  << std::endl;
        return std::nullopt;
    }

    std::vector<UdsmapRule> result;

    int pos = 0;
    for (auto &node : doc.GetArray()) {
        std::optional<UdsmapRule> rule = parse_rule(file, pos++, node);
        if (!rule)
            return std::nullopt;
        result.push_back(rule.value());
    }

    return result;
}

void print_rules(std::vector<UdsmapRule> &rules)
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

        std::cerr
            << "Rule #" << pos++ << ':' << std::endl
            << "  Direction: " << dirstr << std::endl
            << "  IP Type: " << typestr << std::endl
            << "  Address: " << rule.address.value_or("<any>") << std::endl
            << "  Port: " << portstr << std::endl;

#ifdef SOCKET_ACTIVATION
        if (rule.socket_activation) {
            std::cerr << "  Socket activation";
            if (rule.fd_name) {
                std::cerr << " with file descriptor name: "
                          << rule.fd_name.value() << std::endl;
            } else {
                std::cerr << "." << std::endl;
            }
        } else {
#endif
            std::cerr << "  Socket path: " << rule.socket_path.value()
                      << std::endl;
#ifdef SOCKET_ACTIVATION
        }
#endif
    }
}
