#include "sign_command.hpp"
#include <CLI/App.hpp>

CLI::App *register_sign(CLI::App &app) {
    CLI::App *sc = app.add_subcommand("sign", "Signs a DNS Zone using a PKCS#11 library or a file");
    return sc;
}
