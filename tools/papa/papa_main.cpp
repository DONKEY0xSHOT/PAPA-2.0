#include "papa/exceptions.h"
#include "papa/main_driver.h"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        auto parse = papa::cli::parse_args(argc - 1, argv + 1);
        if (!parse.error.empty()) {
            std::cerr << "error: " << parse.error << '\n';
            return parse.exit_code;
        }
        return papa::cli::run(parse.args);
    } catch (const papa::PapaInvariantError& e) {
        // Programmer-visible bug
        // Bubble up loudly with a stable code so scripts can detect it
        std::cerr << "internal error: " << e.what() << '\n';
        return papa::cli::kExitUnexpectedFailure;
    } catch (const std::exception& e) {
        std::cerr << "unexpected error: " << e.what() << '\n';
        return papa::cli::kExitUnexpectedFailure;
    }
}
