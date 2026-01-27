#include "digest/digest_command.hpp"
#include "hash/digest.hpp"
#include "context.hpp"
#include <CLI/CLI.hpp>

CLI::App *register_digest(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("digest", "Adds DigestEnabled RR to the zone");
    
    sc->add_option("-f,--file", OPTION_STRUCT->digest.file,
        "Full path to zone file.");
    sc->add_option("-d,--hash-digest", OPTION_STRUCT->digest.hashDigest,
        "Hash algorithm for digest computation. Supported values are: sha384, sha512.")
        ->transform(CLI::CheckedTransformer(stringToDigestAlgorithm, CLI::ignore_case));
    sc->add_flag("-i,--info", OPTION_STRUCT->digest.info,
        "If true, a TXT RR is added with information about the digesting process (tool and mode).");
    sc->add_option("-o,--output", OPTION_STRUCT->digest.output,
        "Output for the digested zone file.");
    sc->add_option("-z,--zone", OPTION_STRUCT->digest.zone,
        "Zone name");
    
    return sc;
}