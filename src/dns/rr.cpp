#include <vector>
#include <string>
#include <cstdint>
#include "rr.hpp"
#include "wire_format.hpp"

namespace dns {
    std::vector<uint8_t> DNSResourceRecord::toWire() const {
            std::vector<uint8_t> wire;
            auto name_wire = encodeName(toLower(name));
            wire.insert(wire.end(), name_wire.begin(), name_wire.end());
            writeUint16(wire, type);
            writeUint16(wire, rclass);
            writeUint32(wire, ttl);
            writeUint16(wire, rdata.size());
            wire.insert(wire.end(), rdata.begin(), rdata.end());
            return wire;
    }
}