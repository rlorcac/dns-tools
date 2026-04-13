#include "cli/verify_command.hpp"
#include "context/context.hpp"
#include <CLI/App.hpp>

CLI::App *register_verify(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("verify", "Verification options");

    sc->add_option("-f,--file", OPTION_STRUCT->verify.file,
        "Full path to zone file.");
    sc->add_flag("-D,--skip-digests", OPTION_STRUCT->verify.skipDigests,
        "Skip verification of DigestEnabled RRs.");
    sc->add_flag("-S,--skip-signatures", OPTION_STRUCT->verify.skipSignatures,
        "Skip verification of RRSIG RRs.");
    sc->add_option("-T,--threshold-date", OPTION_STRUCT->verify.thresholdDate,
        "Exact date it needs to be before a signature expiration to be considered as expired by the verifier."
        "It is ignored if --verify-threshold-duration is set. Default is tomorrow");
    sc->add_option("-t,--verify-threshold-duration", OPTION_STRUCT->verify.thresholdDuration,
        "Number of days it needs to be before a signature expiration to be considered as valid by the verifier. Default is empty");
    sc->add_option("-z,--zone", OPTION_STRUCT->verify.zone,
        "Zone name.");

    return sc;
}
