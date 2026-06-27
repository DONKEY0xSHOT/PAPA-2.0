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

// Set up an interactive Windows console to render the report like capa does.
// Two things are needed and both default off on a fresh console:
//   * UTF-8 output: the report's box-drawing glyphs are UTF-8, but a console
//     interprets output bytes in its active code page (an OEM page), so without
//     this a `┌` (the bytes `E2 94 8C`) appears as the mojibake `Γöî`.
//   * Virtual-terminal processing: the report's cyan styling is emitted as ANSI
//     escapes, which a console only interprets as color once this mode is on,
//     otherwise the raw escape bytes are shown.
// Redirected output is raw bytes unaffected by either setting (and the renderer
// emits no color when not a terminal), so byte-for-byte parity with capa.exe is
// preserved. Both settings are restored on exit, after every buffered stream is
// flushed so the report is emitted while they are still active.
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
