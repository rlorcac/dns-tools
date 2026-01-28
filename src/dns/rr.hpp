#include <string>
#include <vector>
#include <cstdint>

#ifndef DNS_RR_HPP // DNS_RR_HPP
#define DNS_RR_HPP

// list per IANA DNS Parameters - DNS CLASSes (https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2)
enum rr_class_enum : uint16_t {
    RR_CLASS_IN = 1,
    RR_CLASS_CH = 3,
    RR_CLASS_HS = 4,
    RR_CLASS_NONE = 254,
    RR_CLASS_ANY = 255
};

typedef enum rr_class_enum rr_class_t;

// list per IANA DNS Parameters - RR TYPEs (https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
enum rr_type_enum : uint16_t {
    // 0 is reserved
    RR_TYPE_A = 1,
    RR_TYPE_NS = 2,
    RR_TYPE_MD = 3,
    RR_TYPE_MF = 4,
    RR_TYPE_CNAME = 5,
    RR_TYPE_SOA = 6,
    RR_TYPE_MB = 7,
    RR_TYPE_MG = 8,
    RR_TYPE_MR = 9,
    RR_TYPE_NULL = 10,
    RR_TYPE_WKS = 11,
    RR_TYPE_PTR = 12,
    RR_TYPE_HINFO = 13,
    RR_TYPE_MINFO = 14,
    RR_TYPE_MX = 15,
    RR_TYPE_TXT = 16,
    RR_TYPE_RP = 17,
    RR_TYPE_AFSDB = 18,
    RR_TYPE_X25 = 19,
    RR_TYPE_ISDN = 20,
    RR_TYPE_RT = 21,
    RR_TYPE_NSAP = 22,
    RR_TYPE_NSAP_PTR = 23,
    RR_TYPE_SIG = 24,
    RR_TYPE_KEY = 25,
    RR_TYPE_PX = 26,
    RR_TYPE_GPOS = 27,
    RR_TYPE_AAAA = 28,
    RR_TYPE_LOC = 29,
    RR_TYPE_NXT = 30,
    RR_TYPE_EID = 31,
    RR_TYPE_NIMLOC = 32,
    RR_TYPE_SRV = 33,
    RR_TYPE_ATMA = 34,
    RR_TYPE_NAPTR = 35,
    RR_TYPE_KX = 36,
    RR_TYPE_CERT = 37,
    RR_TYPE_A6 = 38,
    RR_TYPE_DNAME = 39,
    RR_TYPE_SINK = 40,
    RR_TYPE_OPT = 41,
    RR_TYPE_APL = 42,
    RR_TYPE_DS = 43,
    RR_TYPE_SSHFP = 44,
    RR_TYPE_IPSECKEY = 45,
    RR_TYPE_RRSIG = 46,
    RR_TYPE_NSEC = 47,
    RR_TYPE_DNSKEY = 48,
    RR_TYPE_DHCID = 49,
    RR_TYPE_NSEC3 = 50,
    RR_TYPE_NSEC3PARAM = 51,
    RR_TYPE_TLSA = 52,
    RR_TYPE_SMIMEA = 53,
    // 54 is unassigned
    RR_TYPE_HIP = 55,
    RR_TYPE_NINFO = 56,
    RR_TYPE_RKEY = 57,
    RR_TYPE_TALINK = 58,
    RR_TYPE_CDS = 59,
    RR_TYPE_CDNSKEY = 60,
    RR_TYPE_OPENPGPKEY = 61,
    RR_TYPE_CSYNC = 62,
    RR_TYPE_ZONEMD = 63,
    RR_TYPE_SVCB = 64,
    RR_TYPE_HTTPS = 65,
    RR_TYPE_DSYNC = 66,
    RR_TYPE_HHIT = 67,
    RR_TYPE_BRID = 68,
    // 69-98 are unassigned
    RR_TYPE_SPF = 99,
    RR_TYPE_UINFO = 100,
    RR_TYPE_UID = 101,
    RR_TYPE_GID = 102,
    RR_TYPE_UNSPEC = 103,
    RR_TYPE_NID = 104,
    RR_TYPE_L32 = 105,
    RR_TYPE_L64 = 106,
    RR_TYPE_LP = 107,
    RR_TYPE_EUI48 = 108,
    RR_TYPE_EUI64 = 109,
    // 110-127 are unassigned
    RR_TYPE_NXNAME = 128,
    // 129-248 are unassigned
    RR_TYPE_TKEY = 249,
    RR_TYPE_TSIG = 250,
    RR_TYPE_IFXR = 251,
    RR_TYPE_AXFR = 252,
    RR_TYPE_MAILB = 253,
    RR_TYPE_MAILA = 254,
    RR_TYPE_ANY = 255,
    RR_TYPE_URI = 256,
    RR_TYPE_CAA = 257,
    RR_TYPE_AVC = 258,
    RR_TYPE_DOA = 259,
    RR_TYPE_AMTRELAY = 260,
    RR_TYPE_RESINFO = 261,
    RR_TYPE_WALLET = 262,
    RR_TYPE_CLA = 263,
    RR_TYPE_IPN = 264,
    // 265-32767 are unassigned
    RR_TYPE_TA = 32768,
    RR_TYPE_DLV = 32769
};

typedef enum rr_type_enum rr_type_t;
namespace dns {
    class DNSResourceRecord {
    public:
        std::string name;
        rr_type_t type;
        rr_class_t rclass = RR_CLASS_IN; // IN
        uint32_t ttl;
        std::vector<uint8_t> rdata;
        std::vector<uint8_t> toWire() const;
    };
}
#endif // DNS_RR_HPP
