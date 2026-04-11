#include <vector>
#include <string>
#include <cstdint>

#ifndef DNSSEC_KEYS_HPP // DNSSEC_KEYS_HPP
#define DNSSEC_KEYS_HPP

namespace dns {
    enum dnssec_key_enum : uint16_t {
        DNSSEC_ZSK = 256,
        DNSSEC_KSK = 257
    };
    typedef dnssec_key_enum dnssec_key_t;
}

#endif // DNSSEC_KEYS_HPP