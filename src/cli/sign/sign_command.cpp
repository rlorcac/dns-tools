#include "sign/sign_command.hpp"
#include "sign/sign.hpp"
#include "zone_parser.hpp"
#include "zone_writer.hpp"
#include "context.hpp"
#include <CLI/CLI.hpp>
#include <CLI/Formatter.hpp>


CLI::App *register_sign_file(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("file", "uses keys from a file to sign the zone");
    
    sc->add_option("-K,--ksk-file", OPTION_STRUCT->sign.fileOptions.kskFile, 
        "Full path to KSK key file.")->required();
    sc->add_option("-Z,--zsk-file", OPTION_STRUCT->sign.fileOptions.zskFile, 
        "Full path to ZSK key file.")->required();
    
    sc->callback(
        [&](){
            if (OPTION_STRUCT->sign.createKeys) {
                crypto::DNSSECSigner signer(OPTION_STRUCT->sign.zone);
                signer.generateKeys();
                signer.saveKeys(
                    OPTION_STRUCT->sign.fileOptions.zskFile,
                    OPTION_STRUCT->sign.fileOptions.kskFile
                );
                return;
            }
            dns::SimpleZoneParser parser;
            auto records = parser.parse(OPTION_STRUCT->sign.file, OPTION_STRUCT->sign.zone);
            
            crypto::DNSSECSigner signer(OPTION_STRUCT->sign.zone);
            signer.loadKeys(
                OPTION_STRUCT->sign.fileOptions.zskFile,
                OPTION_STRUCT->sign.fileOptions.kskFile
            );
            
            std::vector<dns::DNSResourceRecord> dnskey_records = signer.getDNSKEYRecords(3600);
            std::vector<dns::DNSResourceRecord> signed_records;
            
            // Group records by name, type, class for signing
            std::map<std::tuple<std::string, dns::rr_type_t, dns::rr_class_t>, dns::DNSResourceRecordSet> rrsets;
            
            // Add DNSKEY records to the RRsets for signing
            for (const auto& rr : dnskey_records) {
                auto key = std::make_tuple(rr.name, rr.type, rr.rclass);
                rrsets[key].name = rr.name;
                rrsets[key].type = rr.type;
                rrsets[key].rclass = rr.rclass;
                rrsets[key].ttl = rr.ttl;
                rrsets[key].records.push_back(rr);
            }
            
            // Add zone records to RRsets
            for (const auto& rr : records) {
                auto key = std::make_tuple(rr.name, rr.type, rr.rclass);
                rrsets[key].name = rr.name;
                rrsets[key].type = rr.type;
                rrsets[key].rclass = rr.rclass;
                rrsets[key].ttl = rr.ttl;
                rrsets[key].records.push_back(rr);
            }
            
            // Sign each RRset
            for (const auto& pair : rrsets) {
                const auto& rrset = pair.second;
                dns::DNSResourceRecord rrsig = signer.signRRSet(rrset, 90); // 90 days validity
                signed_records.push_back(rrsig);
                for (const auto& rr : rrset.records) {
                    signed_records.push_back(rr);
                }
            }
            
            dns::ZoneWriter writer;
            writer.writeZoneFile(
                OPTION_STRUCT->sign.output,
                signed_records,
                OPTION_STRUCT->sign.zone
            );
        }
    );

    return sc;
}

CLI::App *register_sign_pkcs11(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("pkcs11", "uses keys from a PKCS#11 library to sign the zone");
    
    sc->add_option("-l,--key-label", OPTION_STRUCT->sign.pkcs11Options.keyLabel, 
        "Label of HSM Signer PKCS11 Key. (default: HSM-tools)");
    sc->add_option("-p,--p11lib", OPTION_STRUCT->sign.pkcs11Options.p11lib, 
        "Full path to PKCS11 lib file.");
    sc->add_option("-u,--user-key", OPTION_STRUCT->sign.pkcs11Options.userKey, 
        "HSM User Login PKCS11Key. (default: 1234)");
    
    return sc;
}

CLI::App *register_sign(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("sign", "Signs a DNS Zone using a PKCS#11 library or a file");
    
    // boolean options
    sc->add_flag("-c,--create-keys", OPTION_STRUCT->sign.createKeys, 
        "Creates a new pair of keys, deleting all previously valid keys.");
    sc->add_flag("-d,--digest", OPTION_STRUCT->sign.digest, 
        "Add DigestEnabled RR to the zone.");
    sc->add_flag("-i,--info", OPTION_STRUCT->sign.info,
        "If true, an TXT RR is added with information about the signing process (tool and mode).");
    sc->add_flag("-L,--lazy", OPTION_STRUCT->sign.lazy, 
        "Sign zone only if needed (i.e. it is not signed already, it is signed with different key, the signatures are about to expire, or the original zone is newer than the signed zone)"
    );
    CLI::Option *option_nsec3 = sc->add_flag("-3,--nsec3", OPTION_STRUCT->sign.NSEC3, 
        "Use NSEC3 instead of NSEC");
    // NSEC3 options
    CLI::Option *option_nsec3_salt_length = sc->add_option("--nsec3-salt-length", OPTION_STRUCT->sign.NSEC3SaltLength, "Length of the salt to be used for NSEC3 hashing. If --nsec3-salt-value is not provided, a random salt of this length will be generated. (default: 64)")
        ->needs(option_nsec3);
    sc->add_option("--nsec3-salt-value", OPTION_STRUCT->sign.NSEC3SaltValue, 
        "Salt value to be used for NSEC3 hashing, in hexadecimal format.")
        ->needs(option_nsec3)->excludes(option_nsec3_salt_length);
    sc->add_option("--nsec3-iterations", OPTION_STRUCT->sign.NSEC3Iterations, 
        "Number of iterations to be used for NSEC3 hashing.")
        ->needs(option_nsec3);
    sc->add_flag("-x,--opt-out", OPTION_STRUCT->sign.optOut, 
        "Use NSEC3 with opt-out.")
        ->needs(option_nsec3);
    // string options
    sc->add_option("-f,--file", OPTION_STRUCT->sign.file, 
        "Full path to the zone file to be signed.");
    sc->add_option("-z,--zone", OPTION_STRUCT->sign.zone,
        "Origin zone name. If not specified, $ORIGIN inside the file will be used.");
    sc->add_option("-a,--sign-algorithm", OPTION_STRUCT->sign.signAlgorithm, 
        "Signing algorithm to be used. Supported values are: rsa, ecdsa.")
        ->transform(CLI::Transformer(crypto::stringToSignAlgorithm, CLI::ignore_case));
    sc->add_option("-o,--output", OPTION_STRUCT->sign.output, 
        "Output for the signed zone file. By default based on zone file name with '-signed' suffix.");
    sc->add_option("-D,--rrsig-duration", OPTION_STRUCT->sign.rrsigDuration, 
        "Relative RRSIG expiration date, in human readable format (e.g., 3months, 90days).");
    sc->add_option("-E,--rrsig-expiration-date", OPTION_STRUCT->sign.rrsigExpirationDate,
        "RRSIG expiration date in YYYYMMDD format. Default is three months from now.");
    sc->add_option("-T,--verify-threshold-date", OPTION_STRUCT->sign.verifyThresholdDate,
        "Exact date before signature expiration to be considered expired by verifier. Default is tomorrow.");
    sc->add_option("-t,--verify-threshold-duration", OPTION_STRUCT->sign.verifyThresholdDuration,
        "Number of days before signature expiration to be considered valid by verifier.");
    // integer options
    sc->add_option("-Q,--hash-digest", OPTION_STRUCT->sign.hashDigest,
        "Hash algorithm for digest verification. Supported values are: sha384, sha512.")
         ->transform(CLI::Transformer(crypto::stringToDigestAlgorithm, CLI::ignore_case));
    
    register_sign_file(*sc);
    register_sign_pkcs11(*sc);

    return sc;
}

