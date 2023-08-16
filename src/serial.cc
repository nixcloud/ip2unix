// SPDX-License-Identifier: LGPL-3.0-only
#include "serial.hh"

#include "rules.hh"
#include "socketpath.hh"
#include "systemd.hh"
#include "types.hh"

void serialise(const std::string &str, std::ostream &out)
{
    for (const char &c : str) {
        switch (c) {
            case '&':
            case '!':
            case '\\':
                out.put('\\');
                out.put(c);
                break;
            case '\0':
                out << "\\@";
                break;
            default:
                out.put(c);
                break;
        }
    }
    out.put('&');
}

MaybeError deserialise(std::istream &in, std::string *out)
{
    char c;

    for (;;) {
        in.get(c);

        if (in.eof())
            return "End of stream while awaiting end of string.";

        if (c == '&')
            break;

        if (c == '\\') {
            in.get(c);

            if (in.eof()) {
                return "End of stream while waiting for"
                       " backslash-escaped character.";
            }

            *out += c == '@' ? '\0' : c;
            continue;
        }

        *out += c;
    }
    return std::nullopt;
}

void serialise(const bool &val, std::ostream &out)
{
    out.put(val ? 't' : 'f');
}

MaybeError deserialise(std::istream &in, bool *out)
{
    char c;

    in.get(c);

    if (in.eof())
        return "End of stream while reading boolean.";

    switch (c) {
        case 't':
            *out = true;
            break;
        case 'f':
            *out = false;
            break;
        default:
            return std::string("Invalid character '") + c + "' for boolean.";
    }
    return std::nullopt;
}

void serialise(const RuleDir &dir, std::ostream &out)
{
    switch (dir) {
        case RuleDir::OUTGOING:
            out.put('o');
            break;
        case RuleDir::INCOMING:
            out.put('i');
            break;
    }
}

MaybeError deserialise(std::istream &in, RuleDir *out)
{
    char c;

    in.get(c);

    if (in.eof())
        return "End of stream while reading RuleDir.";

    switch (c) {
        case 'o':
            *out = RuleDir::OUTGOING;
            break;
        case 'i':
            *out = RuleDir::INCOMING;
            break;
        default:
            return std::string("Invalid character '") + c + "' in RuleDir.";
    }
    return std::nullopt;
}

void serialise(const SocketType &stype, std::ostream &out)
{
    switch (stype) {
        case SocketType::STREAM:
            out.put('t');
            break;
        case SocketType::DATAGRAM:
            out.put('u');
            break;
        case SocketType::INVALID:
            out.put('i');
            break;
    }
}

MaybeError deserialise(std::istream &in, SocketType *out)
{
    char c;

    in.get(c);

    if (in.eof())
        return "End of stream while reading SocketType.";

    switch (c) {
        case 't':
            *out = SocketType::STREAM;
            break;
        case 'u':
            *out = SocketType::DATAGRAM;
            break;
        case 'i':
            *out = SocketType::INVALID;
            break;
        default:
            return std::string("Invalid character '") + c + "' in SocketType.";
    }
    return std::nullopt;
}

void serialise(const SocketPath &path, std::ostream &out)
{
    switch (path.type) {
        case SocketPath::Type::FILESYSTEM:
            out.put('f');
            break;
#ifdef ABSTRACT_SUPPORT
        case SocketPath::Type::ABSTRACT:
            out.put('a');
            break;
#endif
    }

    serialise(path.value, out);
    serialise(path.unlink, out);
}

MaybeError deserialise(std::istream &in, SocketPath *out)
{
    char c;

    in.get(c);

    if (in.eof())
        return "End of stream while reading socket path type.";

    switch (c) {
        case 'f':
            out->type = SocketPath::Type::FILESYSTEM;
            break;
#ifdef ABSTRACT_SUPPORT
        case 'a':
            out->type = SocketPath::Type::ABSTRACT;
            break;
#endif
        default:
            return std::string("Invalid character '")
                 + c + "' used as socket path type.";
    }

    MaybeError err;
    if ((err = deserialise(in, &out->value))) return err;
    return deserialise(in, &out->unlink);
}

void serialise(const Rule &rule, std::ostream &out)
{
    serialise(rule.matches.direction, out);
    serialise(rule.matches.type, out);
    serialise(rule.matches.address, out);
    serialise(rule.matches.port, out);
    serialise(rule.matches.port_end, out);
    serialise(rule.action.socket_path, out);
#ifdef SYSTEMD_SUPPORT
    serialise(rule.action.socket_activation, out);
    serialise(rule.action.fd_name, out);
#endif
    serialise(rule.action.reject, out);
    serialise(rule.action.reject_errno, out);
    serialise(rule.action.blackhole, out);
    serialise(rule.action.ignore, out);
}

#define DESERIALISE_OR_ERR(what) \
    if ((err = deserialise(in, &out->what))) return err

MaybeError deserialise(std::istream &in, Rule::Matches *out)
{
    MaybeError err;
    DESERIALISE_OR_ERR(direction);
    DESERIALISE_OR_ERR(type);
    DESERIALISE_OR_ERR(address);
    DESERIALISE_OR_ERR(port);
    DESERIALISE_OR_ERR(port_end);
    return std::nullopt;
}

MaybeError deserialise(std::istream &in, Rule::Action *out)
{
    MaybeError err;
    DESERIALISE_OR_ERR(socket_path);
#ifdef SYSTEMD_SUPPORT
    DESERIALISE_OR_ERR(socket_activation);
    DESERIALISE_OR_ERR(fd_name);
#endif
    DESERIALISE_OR_ERR(reject);
    DESERIALISE_OR_ERR(reject_errno);
    DESERIALISE_OR_ERR(blackhole);
    DESERIALISE_OR_ERR(ignore);
    return std::nullopt;
}

MaybeError deserialise(std::istream &in, Rule *out)
{
    MaybeError err;
    DESERIALISE_OR_ERR(matches);
    DESERIALISE_OR_ERR(action);
    return std::nullopt;
}

#ifdef SYSTEMD_SUPPORT
void serialise(const Systemd::FdInfo &fdinfo, std::ostream &out)
{
    serialise(fdinfo.fd, out);
    serialise(fdinfo.is_inet, out);
}

MaybeError deserialise(std::istream &in, Systemd::FdInfo *out)
{
    MaybeError err;
    DESERIALISE_OR_ERR(fd);
    DESERIALISE_OR_ERR(is_inet);
    return std::nullopt;
}
#endif
