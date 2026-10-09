#include "papa/version.h"

namespace papa::version {

std::string_view version() noexcept {
    return PAPA_VERSION;
}

}  // namespace papa::version
