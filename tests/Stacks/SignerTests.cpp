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
    auto key = parse_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01");
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159");
    transfer->set_amount(12345);
    transfer->set_fee(100);
    transfer->set_nonce(10);
    transfer->set_anchormode(3);
    transfer->set_memo("");
    transfer->set_memo("test memo");

    const auto signer = Signer(input);

    const auto signature = Base64::encode(signer.sign());
    ASSERT_EQ(signature, "AAAAAAmpZryqzBA+OIlrquP4wvBsIf1H3U+GT/DTP5gZ31yiAAAD6AAAAAAAAAACAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAxYC2MXoOs5v3/NT6PBn9q0uJu6u/YQle5FBa9uzteq4AAAAAAAAAAACYloAAAAAAAAAAARnfXKIAAABAocQZwTnVvGMQlpdGacWvgenxN5ku8YB8yhEGrDfEV48yDqcj6QaePAitDj/N2gxfYD9Q2pJ+ZpkQMsZZG4ACAg==");
}
