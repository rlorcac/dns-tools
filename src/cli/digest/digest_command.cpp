#include "digest/digest_command.hpp"
#include <CLI/CLI.hpp>

CLI::App *register_digest(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("digest", "Adds DigestEnabled RR to the zone");
    sc->fallthrough(true);

    return sc;
}