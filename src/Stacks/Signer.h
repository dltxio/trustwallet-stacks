// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include "../Data.h"
#include "../PrivateKey.h"
#include "../proto/Stacks.pb.h"

namespace TW::Stacks {

/// Helper class that performs Stacks transaction signing.
class Signer {
public:
    /// Hide default constructor
    Signer() = delete;

    explicit Signer(const Proto::SigningInput& input): input(input) {}

    TW::Data sign() const noexcept;

    /// Signs a Proto::SigningInput transaction
    static Proto::SigningOutput sign(const Proto::SigningInput& input) noexcept;

private:
    Proto::SigningInput input;

};

} // namespace TW::Stacks

/// Wrapper for C interface.
struct TWStacksSigner {
    TW::Stacks::Signer impl;
};
