#include "papa/exceptions.h"

#include <string>

namespace papa {

PapaError make_error(ErrorKind kind, std::string detail) {
    return PapaError{kind, std::move(detail)};
}

}  // namespace papa
