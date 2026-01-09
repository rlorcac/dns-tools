#include "verify_command.hpp"
#include <CLI/App.hpp>

CLI::App *register_verify(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("verify", "Verification options");
    return sc;
}
