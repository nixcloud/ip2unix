#include <stdint.h>
#include <string>
#include <stdexcept>
#include <unordered_set>

#include "dynports.hh"

#define ASSERT(check, msg) \
    if (!(check)) throw std::runtime_error(msg)

#define ASSERT_EXCEPTION(code, exception)                                     \
    [&]() {                                                                   \
        auto value = 0;                                                       \
        try {                                                                 \
            value = code;                                                     \
        } catch (exception&) {                                                \
            return;                                                           \
        } catch (...) {                                                       \
            throw std::runtime_error("Unknown exception in \"" #code "\".");  \
        }                                                                     \
        throw std::runtime_error("\"" #code "\" should have thrown "          \
                                 #exception ", but returned \"" +             \
                                 std::to_string(value) + "\" instead.");      \
    } ()

void test_overlap(void)
{
    DynPorts ports;

    for (int pass = 0; pass < 10; ++pass) {
        std::unordered_set<uint16_t> results;

        for (int i = 0; i < 64512; ++i) {
            uint16_t current = ports.acquire();

            ASSERT(results.find(current) == results.end(),
                   "Found non-uniform value " + std::to_string(current) +
                   " in pass " + std::to_string(pass) + " of iteration " +
                   std::to_string(i) + ".");

            ASSERT(current >= 1024, "Port out of bounds: " +
                                    std::to_string(current));

            results.emplace(current);
        }
    }
}

void test_exhaust_random(void)
{
    DynPorts ports;

    // Reserve all ports
    for (int i = 1024; i < 65536; ++i)
        ports.reserve();

    ASSERT_EXCEPTION(ports.acquire(), std::overflow_error);
}

void test_exhaust_specific(void)
{
    DynPorts ports;

    // Reserve all ports except 65535
    for (int i = 1024; i < 65535; ++i)
        ports.reserve(i);

    uint16_t newport = ports.acquire();
    ASSERT(newport == 65535, "Port should be 65535, but it is " +
                             std::to_string(newport));

    ports.reserve(65535);

    ASSERT_EXCEPTION(ports.acquire(), std::overflow_error);
}

void test_exhaust_reservation(void)
{
    DynPorts ports;

    // Make sure that the current port is the last port, so we
    // trigger a wrap-around later.
    while (ports.acquire() != 65535);

    // Reserve all ports except 65535
    for (int i = 1024; i < 65535; ++i)
        ports.reserve(i);

    uint16_t acquired = ports.acquire();
    ASSERT(acquired == 65535, "Acquired port should be 65535 bit it's " +
                              std::to_string(acquired) + " instead.");

    uint16_t reserved = ports.reserve();
    ASSERT(reserved == 65535, "Reserved port should be 65535 bit it's " +
                              std::to_string(reserved) + " instead.");

    ASSERT_EXCEPTION(ports.reserve(), std::overflow_error);
    ASSERT_EXCEPTION(ports.acquire(), std::overflow_error);
}

int main(void)
{
    test_overlap();
    test_exhaust_random();
    test_exhaust_specific();
    test_exhaust_reservation();
    return 0;
}
