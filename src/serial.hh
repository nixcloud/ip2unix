// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SERIAL_HH
#define IP2UNIX_SERIAL_HH

#include <stdio.h>
#include <deque>
#include <sstream>
#include <unordered_map>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "rules.hh"

enum class RuleDir;
enum class SocketType;
namespace Systemd {
struct FdInfo;
}  // namespace Systemd
struct Rule;

#ifdef SYSTEMD_SUPPORT
#include "systemd.hh"
#endif

using MaybeError = std::optional<std::string>;

void serialise(const std::string&, std::ostream&);
MaybeError deserialise(std::istream&, std::string*);

void serialise(const bool&, std::ostream&);
MaybeError deserialise(std::istream&, bool*);

void serialise(const RuleDir&, std::ostream&);
MaybeError deserialise(std::istream&, RuleDir*);

void serialise(const SocketType&, std::ostream&);
MaybeError deserialise(std::istream&, SocketType*);

void serialise(const Rule&, std::ostream&);
MaybeError deserialise(std::istream&, Rule*);

#ifdef SYSTEMD_SUPPORT
void serialise(const Systemd::FdInfo&, std::ostream&);
MaybeError deserialise(std::istream&, Systemd::FdInfo*);
#endif

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
inline void serialise(const T &val, std::ostream &out)
{
    out << val;
    out.put('&');
}

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
MaybeError deserialise(std::istream &in, T *out)
{
    char c;
    in >> *out;
    if ((c = in.get()) != '&')
        return std::string("Invalid character '") + c + "' after integer.";
    return std::nullopt;
}

template <typename T>
void serialise(const std::optional<T> &val, std::ostream &out)
{
    if (val)
        serialise(*val, out);
    else
        out.put('!');
}

template <typename T>
MaybeError deserialise(std::istream &in, std::optional<T> *out)
{
    if (in.get() == '!') {
        *out = std::nullopt;
        return std::nullopt;
    }

    in.unget();
    T outval;
    MaybeError err;
    if ((err = deserialise(in, &outval)))
        return err;
    out->emplace(outval);
    return std::nullopt;
}

template <typename A, typename B>
void serialise(const std::pair<A, B> &val, std::ostream &out)
{
    serialise(val.first, out);
    out.put('#');
    serialise(val.second, out);
    out.put('$');
}

template <typename A, typename B>
MaybeError deserialise(std::istream &in, std::pair<A, B> *out)
{
    char c;
    MaybeError err;

    if ((err = deserialise(in, &out->first)))
        return err;

    if ((c = in.get()) != '#')
        return std::string("Invalid character '")
             + c + "' after first pair value.";

    if ((err = deserialise(in, &out->second)))
        return err;

    if ((c = in.get()) != '$')
        return std::string("Invalid character '")
             + c + "' after second pair value.";

    return std::nullopt;
}

template <typename T>
void serialise(const std::deque<T> &val, std::ostream &out)
{
    for (const T &item : val)
        serialise(item, out);
}

template <typename T>
MaybeError deserialise(std::istream &in, std::deque<T> *out)
{
    while (in.peek() != EOF) {
        T outval;
        MaybeError err;
        if ((err = deserialise(in, &outval)))
            return err;
        out->push_back(outval);
    }
    return std::nullopt;
}

template <typename T>
void serialise(const std::vector<T> &val, std::ostream &out)
{
    for (const T &item : val)
        serialise(item, out);
}

template <typename T>
MaybeError deserialise(std::istream &in, std::vector<T> *out)
{
    while (in.peek() != EOF) {
        T outval;
        MaybeError err;
        if ((err = deserialise(in, &outval)))
            return err;
        out->push_back(outval);
    }
    return std::nullopt;
}

template <typename K, typename V>
void serialise(const std::unordered_map<K, V> &val, std::ostream &out)
{
    for (const std::pair<const K, V> &item : val) {
        serialise(item.first, out);
        out.put('=');
        serialise(item.second, out);
        out.put(';');
    }
}

template <typename K, typename V>
MaybeError deserialise(std::istream &in, std::unordered_map<K, V> *out)
{
    char c;
    while (in.peek() != EOF) {
        MaybeError err;

        K outkey;
        if ((err = deserialise(in, &outkey)))
            return err;

        if ((c = in.get()) != '=')
            return std::string("Invalid character '") + c + "' after map key.";

        V outval;
        if ((err = deserialise(in, &outval)))
            return err;

        if ((c = in.get()) != ';') {
            return std::string("Invalid character '") + c
                 + "' after map record.";
        }

        (*out)[outkey] = outval;
    }
    return std::nullopt;
}

/* The following two functions are just std::string convenience wrappers. */

template <typename T>
std::string serialise(const T &val)
{
    std::ostringstream out;
    serialise(val, out);
    return out.str();
}

template <typename T>
MaybeError deserialise(const std::string &val, T *out)
{
    std::istringstream in;
    in.str(val);
    MaybeError err;
    if ((err = deserialise(in, out)))
        return err;
    return std::nullopt;
}

#endif
