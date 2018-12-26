// SPDX-License-Identifier: LGPL-3.0-only
#ifndef IP2UNIX_SERIAL_HH
#define IP2UNIX_SERIAL_HH

#include <sstream>

#include "rules.hh"

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

inline void serialise(const int &val, std::ostream &out)
{
    out << val;
    out.put('&');
}

template <typename T,
          typename std::enable_if_t<std::is_integral<T>::value>* = nullptr>
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
    if (err = deserialise(in, &outval))
        return err;
    out->emplace(outval);
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
        if (err = deserialise(in, &outval))
            return err;
        out->push_back(outval);
    }
    return std::nullopt;
}

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
    if (err = deserialise(in, out))
        return err;
    return std::nullopt;
}

#endif
