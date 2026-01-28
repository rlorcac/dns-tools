#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
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

    std::ostream& operator<<(std::ostream& os, const rr_class_t& rclass) {
        std::string class_str;
        auto it = rr_class_t_to_str.find(rclass);
        if (it != rr_class_t_to_str.end()) {
            class_str = it->second;
        } else {
            class_str = "UNKNOWN(" + std::to_string(static_cast<uint16_t>(rclass)) + ")";
        }
        os << class_str;
        return os;
    }

    std::ostream& operator<<(std::ostream& os, const rr_type_t& rtype) {
        std::string type_str;
        auto it = rr_type_t_to_str.find(rtype);
        if (it != rr_type_t_to_str.end()) {
            type_str = it->second;
        } else {
            type_str = "UNKNOWN(" + std::to_string(static_cast<uint16_t>(rtype)) + ")";
        }
        os << type_str;
        return os;
    }

    std::ostream& operator<<(std::ostream& os, const DNSResourceRecord& rr) {
        os << rr.name << "\t" << std::dec << rr.ttl << "\t" << rr.rclass << "\t" << rr.type << "\t";
        for (uint8_t byte : rr.rdata) {
            os << std::hex << std::setfill('0') << std::setw(2) << (int)byte;
        }
        return os;
    }
}