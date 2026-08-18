#include "papa/exceptions.h"
#include "papa/main_driver.h"

#include <cstdio>
#include <exception>
#include <iostream>

#if defined(_WIN32) && defined(_MSC_VER)
#  pragma warning(push, 0)
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <windows.h>
#  pragma warning(pop)
#endif

namespace {

#if defined(_WIN32) && defined(_MSC_VER)

// Set up an interactive Windows console to render the report like capa does
class ConsoleGuard {
public:
    ConsoleGuard() noexcept : previous_cp_(::GetConsoleOutputCP()) {
        ::SetConsoleOutputCP(CP_UTF8);
        const HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (out != INVALID_HANDLE_VALUE && ::GetConsoleMode(out, &previous_mode_) != 0) {
            had_mode_ = true;
            ::SetConsoleMode(out, previous_mode_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    ~ConsoleGuard() {
        std::cout.flush();
        std::fflush(nullptr);
        ::SetConsoleOutputCP(previous_cp_);
        if (had_mode_) {
            const HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
            if (out != INVALID_HANDLE_VALUE) { ::SetConsoleMode(out, previous_mode_); }
        }
    }

    ConsoleGuard(const ConsoleGuard&)            = delete;
    ConsoleGuard& operator=(const ConsoleGuard&) = delete;

private:
    UINT  previous_cp_;
    DWORD previous_mode_{0};
    bool  had_mode_{false};
};

#endif

}  // namespace

int main(int argc, char** argv) {
#if defined(_WIN32) && defined(_MSC_VER)
    const ConsoleGuard console_guard;
#endif
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
