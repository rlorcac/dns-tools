#include <string>
#include <vector>
#include <fstream>

#include "rr.hpp"
#include "wire_format.hpp"
#include "zone_writer.hpp"
#include "string_commons.hpp"

namespace dns {

    void ZoneWriter::writeZoneFile(const std::string& filename, const std::vector<DNSResourceRecord>& records, const std::string& origin) {
        std::ofstream ofs(filename);
        if (!ofs.is_open()) {
            throw std::runtime_error("Failed to open zone file for writing: " + filename);
        }

        for (const auto& rr : records) {
            this->writeRecord(ofs, rr, origin);
        }

        ofs.close();
    }

} // namespace dns
