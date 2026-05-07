#pragma once

#include <cstddef>
#include <exception>
#include <type_traits>
#include <utility>
#include <variant>

namespace papa::util {

template <typename E>
class Unexpected {
public:
    constexpr explicit Unexpected(E e) noexcept(std::is_nothrow_move_constructible_v<E>)
        : error_(std::move(e)) {}

    [[nodiscard]] constexpr const E& error() const& noexcept { return error_; }
    [[nodiscard]] constexpr E&       error() & noexcept       { return error_; }
    [[nodiscard]] constexpr E&&      error() && noexcept      { return std::move(error_); }

private:
    E error_;
};

template <typename E>
Unexpected(E) -> Unexpected<E>;

class BadExpectedAccess : public std::exception {
public:
    [[nodiscard]] const char* what() const noexcept override { return "bad Expected access"; }
};

template <typename T, typename E>
class Expected {
    static_assert(!std::is_same_v<T, E>, "T and E must differ");

public:
    constexpr Expected() noexcept(std::is_nothrow_default_constructible_v<T>)
        requires(std::is_default_constructible_v<T>)
        : storage_(std::in_place_index<0>, T{}) {}

    template <typename U = T>
        requires(std::is_constructible_v<T, U&&> &&
                 !std::is_same_v<std::remove_cvref_t<U>, Expected> &&
                 !std::is_same_v<std::remove_cvref_t<U>, Unexpected<E>>)
    constexpr Expected(U&& v) noexcept(std::is_nothrow_constructible_v<T, U&&>)
        : storage_(std::in_place_index<0>, std::forward<U>(v)) {}

    template <typename G = E>
    constexpr Expected(Unexpected<G> u) noexcept(std::is_nothrow_constructible_v<E, G&&>)
        : storage_(std::in_place_index<1>, std::move(u).error()) {}

    [[nodiscard]] constexpr bool has_value() const noexcept { return storage_.index() == 0; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] constexpr const T& value() const& {
        if (!has_value()) { throw BadExpectedAccess{}; }
        return std::get<0>(storage_);
    }
    [[nodiscard]] constexpr T& value() & {
        if (!has_value()) { throw BadExpectedAccess{}; }
        return std::get<0>(storage_);
    }
    [[nodiscard]] constexpr T&& value() && {
        if (!has_value()) { throw BadExpectedAccess{}; }
        return std::move(std::get<0>(storage_));
    }

    [[nodiscard]] constexpr const E& error() const& noexcept { return std::get<1>(storage_); }
    [[nodiscard]] constexpr E&       error() & noexcept       { return std::get<1>(storage_); }
    [[nodiscard]] constexpr E&&      error() && noexcept      { return std::move(std::get<1>(storage_)); }

    [[nodiscard]] constexpr const T& operator*() const& noexcept { return std::get<0>(storage_); }
    [[nodiscard]] constexpr T&       operator*() & noexcept       { return std::get<0>(storage_); }

    [[nodiscard]] constexpr const T* operator->() const noexcept { return &std::get<0>(storage_); }
    [[nodiscard]] constexpr T*       operator->() noexcept       { return &std::get<0>(storage_); }

    template <typename U>
    [[nodiscard]] constexpr T value_or(U&& fallback) const& {
        return has_value() ? std::get<0>(storage_) : static_cast<T>(std::forward<U>(fallback));
    }

private:
    std::variant<T, E> storage_;
};

// Specialization for Expected<void, E>: success carries no payload
template <typename E>
class Expected<void, E> {
public:
    constexpr Expected() noexcept : has_value_(true), error_{} {}

    template <typename G = E>
    constexpr Expected(Unexpected<G> u) noexcept(std::is_nothrow_constructible_v<E, G&&>)
        : has_value_(false), error_(std::move(u).error()) {}

    [[nodiscard]] constexpr bool has_value() const noexcept { return has_value_; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return has_value_; }

    constexpr void value() const {
        if (!has_value_) { throw BadExpectedAccess{}; }
    }

    [[nodiscard]] constexpr const E& error() const& noexcept { return error_; }
    [[nodiscard]] constexpr E&       error() & noexcept       { return error_; }
    [[nodiscard]] constexpr E&&      error() && noexcept      { return std::move(error_); }

private:
    bool has_value_;
    E    error_;
};

}  // namespace papa::util
