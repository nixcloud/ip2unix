// SPDX-License-Identifier: LGPL-3.0-only
#include "serial.hh"
#include "rules.hh"
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
    while ((c = in.get()) != '&') {
        if (c == '\\')
            *out += (c = in.get()) == '@' ? '\0' : c;
        else
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
    switch (c = in.get()) {
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
    switch (c = in.get()) {
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
        case SocketType::TCP:
            out.put('t');
            break;
        case SocketType::UDP:
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
    switch (c = in.get()) {
        case 't':
            *out = SocketType::TCP;
            break;
        case 'u':
            *out = SocketType::UDP;
            break;
        case 'i':
            *out = SocketType::INVALID;
            break;
        default:
            return std::string("Invalid character '") + c + "' in SocketType.";
    }
    return std::nullopt;
}

void serialise(const Rule &rule, std::ostream &out)
{
    serialise(rule.direction, out);
    serialise(rule.type, out);
    serialise(rule.address, out);
    serialise(rule.port, out);
    serialise(rule.port_end, out);
    serialise(rule.socket_path, out);
#ifdef SYSTEMD_SUPPORT
    serialise(rule.socket_activation, out);
    serialise(rule.fd_name, out);
#endif
    serialise(rule.reject, out);
    serialise(rule.reject_errno, out);
    serialise(rule.blackhole, out);
    serialise(rule.ignore, out);
}

#define DESERIALISE_OR_ERR(what) \
    if ((err = deserialise(in, &out->what))) return err

MaybeError deserialise(std::istream &in, Rule *out)
{
    MaybeError err;
    DESERIALISE_OR_ERR(direction);
    DESERIALISE_OR_ERR(type);
    DESERIALISE_OR_ERR(address);
    DESERIALISE_OR_ERR(port);
    DESERIALISE_OR_ERR(port_end);
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
