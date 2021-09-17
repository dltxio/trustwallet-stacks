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

#include <gtest/gtest.h>

using namespace TW;
using namespace TW::Stacks;

TEST(StacksSigner, signBasic) {
    auto input = Proto::SigningInput();
    auto key = parse_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01");
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159");
    transfer->set_amount(100);
    transfer->set_anchormode(3);

    const auto signer = Signer(input);

    const auto [encoded, error] = signer.sign();
    ASSERT_EQ(encoded, parse_hex("0000000001040015c31b8c1c11c515e244b75806bac48d1399c775000000000000000000000000000000000000147306f1a22e3e2e0ba6b96ee970cf0a077771bde408d25d2eb72f2edc883a193e5c1313d3eef3f01cb7bdb75e57d442b7c143766d20cdb28ceb6784ea4033f5030200000000000516df0ba3e79792be7be5e50a370289accfc8c9e032000000000000006400000000000000000000000000000000000000000000000000000000000000000000"));
    ASSERT_EQ(error, "");
}

TEST(StacksSigner, signWithFee) {
    auto input = Proto::SigningInput();
    auto key = parse_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01");
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159");
    transfer->set_amount(12345);
    transfer->set_fee(100);
    transfer->set_nonce(987654321);
    transfer->set_anchormode(3);

    const auto signer = Signer(input);

    const auto [encoded, error] = signer.sign();
    ASSERT_EQ(encoded, parse_hex("0000000001040015c31b8c1c11c515e244b75806bac48d1399c775000000003ade68b100000000000000640000afa753c693b1dfdd22ce0074676037aea60161daa39f4cdd86b96bafb11f00b166995c9637ea1f9afc6f87e7446bf9bf986ff84eda80b64b9b0f38c425ee4890030200000000000516df0ba3e79792be7be5e50a370289accfc8c9e032000000000000303900000000000000000000000000000000000000000000000000000000000000000000"));
    ASSERT_EQ(error, "");
}

TEST(StacksSigner, signWithMemo) {
    auto input = Proto::SigningInput();
    auto key = parse_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01");
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159");
    transfer->set_amount(12345);
    transfer->set_fee(100);
    transfer->set_nonce(987654321);
    transfer->set_anchormode(3);
    transfer->set_memo("test memo");

    const auto signer = Signer(input);

    const auto [encoded, error] = signer.sign();
    ASSERT_EQ(encoded, parse_hex("0000000001040015c31b8c1c11c515e244b75806bac48d1399c775000000003ade68b10000000000000064000129cd8f04922291c97f9c24a5547bc7a65b54067b91b52f2f4b9b373dea1cf8ef4a97a2a71b78a60f42eb9aee7f6e76287fb24e6ecd32bd581cb9d1b936eb6a0c030200000000000516df0ba3e79792be7be5e50a370289accfc8c9e032000000000000303974657374206d656d6f00000000000000000000000000000000000000000000000000"));
    ASSERT_EQ(error, "");
}

TEST(StacksSigner, anchorModeFail) {
    auto input = Proto::SigningInput();
    auto key = parse_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01");
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159");
    transfer->set_anchormode(0);

    const auto signer = Signer(input);

    const auto [encoded, error] = signer.sign();
    ASSERT_EQ(encoded, Data());
    ASSERT_EQ(error, "Invalid anchor mode");
}

TEST(StacksSigner, memoFail) {
    auto input = Proto::SigningInput();
    auto key = parse_hex("edf9aee84d9b7abc145504dde6726c64f369d37ee34ded868fabd876c26570bc01");
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159");
    transfer->set_amount(12345);
    transfer->set_fee(100);
    transfer->set_nonce(10);
    transfer->set_anchormode(3);
    transfer->set_memo("this is a really long memo which should not be allowed");

    const auto signer = Signer(input);

    const auto [encoded, error] = signer.sign();
    ASSERT_EQ(encoded, Data());
    ASSERT_EQ(error, "Invalid length for memo");
}

