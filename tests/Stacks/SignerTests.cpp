// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "../interface/TWTestUtilities.h"

#include "Stacks/Address.h"
#include "Stacks/Signer.h"
#include "HexCoding.h"
#include "PrivateKey.h"
#include "BinaryCoding.h"
#include "Base64.h"

#include <gtest/gtest.h>

using namespace TW;
using namespace TW::Stacks;

TEST(StacksSigner, sign) {
    auto input = Proto::SigningInput();
    auto transfer = input.mutable_tokentransfer();
    auto common = transfer->mutable_common();
    transfer->set_senderkey("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc");
    common->set_recipient("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159");
    common->set_amount(12345);
    common->set_fee(0);
    common->set_nonce(0);
    common->set_anchormode(3);
    common->set_memo("test memo");

    const auto signer = Signer(input);

    const auto signature = Base64::encode(signer.sign());
    ASSERT_EQ(signature, "AAAAAAmpZryqzBA+OIlrquP4wvBsIf1H3U+GT/DTP5gZ31yiAAAD6AAAAAAAAAACAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAxYC2MXoOs5v3/NT6PBn9q0uJu6u/YQle5FBa9uzteq4AAAAAAAAAAACYloAAAAAAAAAAARnfXKIAAABAocQZwTnVvGMQlpdGacWvgenxN5ku8YB8yhEGrDfEV48yDqcj6QaePAitDj/N2gxfYD9Q2pJ+ZpkQMsZZG4ACAg==");
}
