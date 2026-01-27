#include "sign/sign_command.hpp"
#include "sign/sign.hpp"
#include "context.hpp"
#include <CLI/CLI.hpp>


CLI::App *register_sign_file(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("file", "uses keys from a file to sign the zone");
    sc->fallthrough(true);
    return sc;
}

CLI::App *register_sign_pkcs11(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("pkcs11", "uses keys from a PKCS#11 library to sign the zone");
    sc->fallthrough(true);
    return sc;
}

CLI::App *register_sign(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("sign", "Signs a DNS Zone using a PKCS#11 library or a file");
    sc->fallthrough(true);
    // boolean options
    sc->add_flag("-c,--create-keys", OPTION_STRUCT->sign.createKeys, 
        "Creates a new pair of keys, deleting all previously valid keys.");
    sc->add_flag("-d,--digest", OPTION_STRUCT->sign.digest, 
        "Add DigestEnabled RR to the zone.");
    sc->add_flag("-L,--lazy", OPTION_STRUCT->sign.lazy, 
        "Sign zone only if needed (i.e. it is not signed already, it is signed with different key, the signatures are about to expire, or the original zone is newer than the signed zone)"
    );
    CLI::Option *option_nsec3 = sc->add_flag("-3,--nsec3", OPTION_STRUCT->sign.NSEC3, 
        "Use NSEC3 instead of NSEC");
    sc->add_flag("-x,--opt-out", OPTION_STRUCT->sign.optOut, 
        "Use NSEC3 with opt-out.");
    // string options
    sc->add_option("--file", OPTION_STRUCT->sign.file, 
        "Full path to the zone file to be signed.");
    sc->add_option("-a,--sign-algorithm", OPTION_STRUCT->sign.signAlgorithm, 
        "Signing algorithm to be used. Supported values are: rsa, ecdsa.")
        ->transform(CLI::CheckedTransformer(stringToSignAlgorithm, CLI::ignore_case));
    CLI::Option *option_nsec3_salt_length = sc->add_option("--nsec3-salt-length", OPTION_STRUCT->sign.NSEC3SaltLength, "Length of the salt to be used for NSEC3 hashing. If --nsec3-salt-value is not provided, a random salt of this length will be generated.")
        ->needs(option_nsec3);
    sc->add_option("--nsec3-salt-value", OPTION_STRUCT->sign.NSEC3SaltValue, 
        "Salt value to be used for NSEC3 hashing, in hexadecimal format.")
        ->needs(option_nsec3)->excludes(option_nsec3_salt_length);
    sc->add_option("--nsec3-iterations", OPTION_STRUCT->sign.NSEC3Iterations, 
        "Number of iterations to be used for NSEC3 hashing.")
        ->needs(option_nsec3);
    sc->add_option("-o,--output", OPTION_STRUCT->sign.output, 
        "Output file for the signed zone.");
    sc->add_option("-D,--rrsig-duration", OPTION_STRUCT->sign.rrsigDuration, 
        "Duration for RRSIG validity period (e.g., 30d for 30 days).");
    register_sign_file(*sc);
    register_sign_pkcs11(*sc);

    return sc;
}

