// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

namespace elements_abi {
template <typename T>
constexpr bool CALLBACK = std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;

template <auto Function, uint32_t Operation, typename Signature> struct Binding;
template <auto Function, uint32_t Operation, typename Result, typename... Args>
struct Binding<Function, Operation, Result(Args...)> {
    Result operator()(Args... args) const
    {
        std::array<uint64_t, (0 + ... + std::is_integral_v<Args>)> scalars{};
        std::array<void*, (0 + ... + (std::is_pointer_v<Args> && !CALLBACK<Args>))> pointers{};
        std::array<void (*)(), (0 + ... + CALLBACK<Args>)> callbacks{};
        size_t scalar_index{}, pointer_index{}, callback_index{};
        const auto append = [&]<typename T>(T value) {
            if constexpr (std::is_integral_v<T>) scalars[scalar_index++] = static_cast<uint64_t>(value);
            else if constexpr (CALLBACK<T>) callbacks[callback_index++] = value;
            else pointers[pointer_index++] = static_cast<void*>(value);
        };
        (append(args), ...);
        uint64_t result{};
        if (Function(Operation, scalars.size(), scalars.data(), pointers.size(), pointers.data(),
                callbacks.size(), callbacks.data(), &result) != 0)
            throw std::runtime_error("Haskell domain ABI transport failure");
        return static_cast<Result>(std::bit_cast<int64_t>(result));
    }
};
}
