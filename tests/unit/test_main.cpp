// MSVC: <ostream> must precede doctest so std::string pretty-printing compiles
#include <ostream>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
