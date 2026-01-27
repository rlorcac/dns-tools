#include "sign/sign_command.hpp"
#include "sign/sign.hpp"
#include "context.hpp"
#include <CLI/CLI.hpp>


CLI::App *register_sign_file(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("file", "uses keys from a file to sign the zone");
    return sc;
}

CLI::App *register_sign_pkcs11(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("pkcs11", "uses keys from a PKCS#11 library to sign the zone");
    return sc;
}

CLI::App *register_sign(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("sign", "Signs a DNS Zone using a PKCS#11 library or a file");
    sc->fallthrough(true);

    // boolean options
    sc->add_flag("-c,--create-keys", OPTION_STRUCT->sign.createKeys, "Creates a new pair of keys, deleting all previously valid keys.");
    sc->add_flag("-d,--digest", OPTION_STRUCT->sign.digest, "Add DigestEnabled RR to the zone.");
    sc->add_flag("-L,--lazy", OPTION_STRUCT->sign.lazy, 
        "Sign zone only if needed (i.e. it is not signed already, it is signed with different key, the signatures are about to expire, or the original zone is newer than the signed zone)"
    );
    CLI::Option *option_nsec3 = sc->add_flag("-3,--nsec3", OPTION_STRUCT->sign.NSEC3, "Use NSEC3 instead of NSEC");
    sc->add_flag("-x,--opt-out", OPTION_STRUCT->sign.optOut, "Use NSEC3 with opt-out.");
    // string options
    {
        sc->add_option("--file", OPTION_STRUCT->sign.file, "Full path to the zone file to be signed.");
        sc->add_option("--nsec3-salt-value", OPTION_STRUCT->sign.NSEC3SaltValue, "Salt value to be used for NSEC3 records, in hexadecimal format.")
        ->needs(option_nsec3);
    }

    register_sign_file(*sc);
    register_sign_pkcs11(*sc);

    return sc;
}

