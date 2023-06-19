#include <serial.hh>
#include <stdint.h>
#include <stdexcept>

#include "rules.hh"
#include "types.hh"

/* All the combinations of values we want to check */

static std::vector<std::optional<RuleDir>> ruledirs = {
    std::nullopt,
    RuleDir::INCOMING,
    RuleDir::OUTGOING
};

static std::vector<std::optional<SocketType>> sotypes = {
    std::nullopt,
    SocketType::TCP,
    SocketType::UDP,
    SocketType::INVALID
};

static std::vector<std::optional<std::string>> strings = {
    std::nullopt,
    "",
    "\0",
    "aaa@\0bbb",
    "aaa\\@\0bbb",
    "!",
    "\\!",
    "!\\",
    "123",
    "&",
    "\\!&",
    "xxx!yyy",
    "yyy\\xxx",
    "-321"
};

static std::vector<std::optional<uint16_t>> ports = {
    0, 1, 19, 1000, 65535
};

static std::vector<std::optional<int>> ints = {
    0, 12, -19, -1000, 65535
};

static std::vector<bool> bools = { true, false };

/* A small pretty-printer to ensure that we get helpful error messages. */

std::string pprint(const int &x) { return std::to_string(x); }
std::string pprint(const uint16_t &x) { return std::to_string(x); }
std::string pprint(const std::string &x) { return std::string("'") + x + "'"; }
std::string pprint(const bool &x) { return x ? "true" : "false"; }

std::string pprint(const RuleDir &dir) {
    switch (dir) {
        case RuleDir::INCOMING:
            return "RuleDir::INCOMING";
        case RuleDir::OUTGOING:
            return "RuleDir::OUTGOING";
    }

    throw std::runtime_error("Invalid RuleDir value");
}

std::string pprint(const SocketType &type) {
    switch (type) {
        case SocketType::UDP:
            return "SocketType::UDP";
        case SocketType::TCP:
            return "SocketType::TCP";
        case SocketType::INVALID:
            return "SocketType::INVALID";
    }

    throw std::runtime_error("Invalid SocketType value");
}

template <typename T>
std::string pprint(const std::optional<T> &x)
{
    if (x)
        return std::string("(Just ") + pprint(*x) + ')';
    return "Nothing";
}

template <typename A, typename B>
std::string pprint(const std::pair<A, B> &pair)
{
    return std::string("<") + pprint(pair.first) + ", "
         + pprint(pair.second) + ">";
}

#define CHOOSE(values) \
    values[seed % values.size()]; seed /= values.size()

#define ASSERT_RULEVAL(field) \
    if (newrule.field != rule.field) { \
        std::ostringstream msg; \
        msg << "Mismatch in value for " #field " which was "; \
        msg << pprint(rule.field); \
        msg << " before encoding and became "; \
        msg << pprint(newrule.field); \
        msg << " after decoding."; \
        throw std::runtime_error(msg.str()); \
    }

#define ASSERT_EQUAL(expected, result) \
    if (expected != result) { \
        std::ostringstream msg; \
        msg << "Expected value " << pprint(expected); \
        msg << " but got " << pprint(result) << " instead."; \
        throw std::runtime_error(msg.str()); \
    }

/*
 * Iterate through all combinations of the vectors given by CHOOSE(), which
 * uses the seed value as its number base. The seed value is subtracted by
 * the lengths of each individual vector and the result is returned so that
 * when the returned value is > 0 we know that we have iterated through all
 * the combinations.
 */
static unsigned long test_rule(unsigned long seed)
{
    Rule rule;
    rule.direction = CHOOSE(ruledirs);
    rule.type = CHOOSE(sotypes);
    rule.address = CHOOSE(strings);
    rule.port = CHOOSE(ports);
    rule.port_end = CHOOSE(ports);
#ifdef SYSTEMD_SUPPORT
    rule.socket_activation = CHOOSE(bools);
    rule.fd_name = CHOOSE(strings);
#endif
    rule.socket_path = CHOOSE(strings);
    rule.reject = CHOOSE(bools);
    rule.reject_errno = CHOOSE(ints);
    rule.blackhole = CHOOSE(bools);
    rule.ignore = CHOOSE(bools);

    std::string result = serialise(rule);
    Rule newrule;
    MaybeError err;
    if ((err = deserialise(result, &newrule)))
        throw std::runtime_error(*err);

    ASSERT_RULEVAL(direction);
    ASSERT_RULEVAL(type);
    ASSERT_RULEVAL(address);
    ASSERT_RULEVAL(port);
    ASSERT_RULEVAL(port_end);
#ifdef SYSTEMD_SUPPORT
    ASSERT_RULEVAL(socket_activation);
    ASSERT_RULEVAL(fd_name);
#endif
    ASSERT_RULEVAL(socket_path);
    ASSERT_RULEVAL(reject);
    ASSERT_RULEVAL(reject_errno);
    ASSERT_RULEVAL(blackhole);
    ASSERT_RULEVAL(ignore);
    return seed;
}

static void test_pairs(void)
{
    std::vector<std::pair<int, bool>> subjects1 = {
        {123, true}, {456, false}, {789, true}
    };
    std::vector<std::pair<std::string, int>> subjects2 = {
        {"foo", 100}, {"bar", 200}
    };

    for (const std::pair<int, bool> &item : subjects1) {
        std::string result = serialise(item);
        MaybeError err;
        std::pair<int, bool> out;
        if ((err = deserialise(result, &out)))
            throw std::runtime_error(*err);
        ASSERT_EQUAL(item, out);
    }

    for (const std::pair<std::string, int> &item : subjects2) {
        std::string result = serialise(item);
        MaybeError err;
        std::pair<std::string, int> out;
        if ((err = deserialise(result, &out)))
            throw std::runtime_error(*err);
        ASSERT_EQUAL(item, out);
    }
}

int main(void)
{
    /* Note that this begins at 1, because the last iteration picks the first
     * elements of all vectors. If we'd use 0 here we would pick it twice.
     */
    for (unsigned long i = 1; test_rule(i) <= 0; ++i);

    test_pairs();
    return 0;
}
