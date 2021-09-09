// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Signer.h"
#include "Address.h"
#include "../PublicKey.h"

#include <algorithm>

using namespace TW;
using namespace TW::Stacks;

static const auto MAINNET_TRANSACTION_VERSION = 0x00;

static const auto MAINNET_CHAIN_ID = 0x01;

static const auto STACKSMSGTYPE_ADDRESS = 0x00;
static const auto STACKSMSGTYPE_PRINCIPAL = 0x01;
static const auto STACKSMSGTYPE_LENGTHPREFIXEDSTRING = 0x02;
static const auto STACKSMSGTYPE_MEMOSTRING = 0x03;
static const auto STACKSMSGTYPE_ASSETINFO = 0x04;
static const auto STACKSMSGTYPE_POSTCONDITION = 0x05;
static const auto STACKSMSGTYPE_PUBLICKEY = 0x06;
static const auto STACKSMSGTYPE_LENGTHPREFIXEDLIST = 0x07;
static const auto STACKSMSGTYPE_PAYLOAD = 0x08;
static const auto STACKSMSGTYPE_MESSAGESIGNATURE = 0x09;
static const auto STACKSMSGTYPE_TRANSACTIONAUTHFIELD = 0x0A;

static const auto ANCHORMODE_ONCHAINONLY = 0x01;
static const auto ANCHORMODE_OFFCHAINONLY = 0x02;
static const auto ANCHORMODE_ANY = 0x03;
static const auto ANCHORMODE = { ANCHORMODE_ONCHAINONLY, ANCHORMODE_OFFCHAINONLY, ANCHORMODE_ANY };

static const auto ADDRESSHASHMODE_SERIALIZEP2PKH = 0x00;

Proto::SigningOutput Signer::sign(const Proto::SigningInput &input) noexcept {
    if (input.has_tokentransfer()) {
	Proto::StacksTransaction tx;
        tx.set_version(MAINNET_TRANSACTION_VERSION);
        tx.set_chainid(MAINNET_CHAIN_ID);
	auto transferCommon = input.tokentransfer().common();
        if (std::find(ANCHORMODE.begin(), ANCHORMODE.end(), transferCommon.anchormode()) != ANCHORMODE.end()) {
	}
        tx.set_anchormode(transferCommon.anchormode());
	auto auth = tx.mutable_auth();
	auth->set_authtype(STACKSMSGTYPE_ADDRESS);
	auto spending = auth->mutable_spendingcondition()->mutable_single();
	spending->set_hashmode(ADDRESSHASHMODE_SERIALIZEP2PKH);
	spending->set_signer("");
	spending->set_nonce(transferCommon.nonce());
	spending->set_fee(transferCommon.fee());
	spending->set_keyencoding(0);
	auto payload = tx.mutable_payload();
    }
    
    auto protoOutput = Proto::SigningOutput();
    Data encoded;
    // auto privateKey = PrivateKey(Data(input.private_key().begin(), input.private_key().end()));
    // auto signature = privateKey.sign(payload, TWCurveED25519);
    // encoded = encodeSignature(signature);

    protoOutput.set_encoded(encoded.data(), encoded.size());
    return protoOutput;
}
