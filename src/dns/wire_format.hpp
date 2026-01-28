#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <stdexcept>

#ifndef DNS_WIRE_FORMAT_HPP // DNS_WIRE_FORMAT_HPP
#define DNS_WIRE_FORMAT_HPP

namespace dns {

// Wire format helpers
inline void writeUint8(std::vector<uint8_t>& buf, uint8_t val);

inline void writeUint16(std::vector<uint8_t>& buf, uint16_t val);

inline void writeUint32(std::vector<uint8_t>& buf, uint32_t val);

inline uint16_t readUint16(const uint8_t* buf, size_t& offset);

inline uint32_t readUint32(const uint8_t* buf, size_t& offset);

// DNS name encoding
inline std::vector<uint8_t> encodeName(const std::string& name);

inline std::string toLower(std::string s);

} // namespace dns

#endif // DNS_WIRE_FORMAT_HPP