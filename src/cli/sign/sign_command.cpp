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
    register_sign_file(*sc);
    register_sign_pkcs11(*sc);

    return sc;
}

