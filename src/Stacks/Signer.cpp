// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Signer.h"
#include "Address.h"
#include "../Hash.h"
#include "../PublicKey.h"
#include "../PrivateKey.h"
#include "../BinaryCoding.h"
#include "../HexCoding.h"

#include <algorithm>

using namespace TW;
using namespace TW::Stacks;

static const auto PRIVATE_KEY_LENGTH = 32;

static const auto RECOVERABLE_ECSDA_SIG_LENGTH_BYTES = 65;

static const auto MEMO_MAX_LENGTH_BYTES = 34;

static const auto MAINNET_TRANSACTION_VERSION = 0x00;

static const auto MAINNET_CHAIN_ID = 0x01;

static const auto ADDRESSHASHMODE_SERIALIZEP2PKH = 0x00;

static const auto AUTHTYPE_STANDARD = 0x04;

static const auto CLARITYTYPE_PRINCIPALSTANDARD = 0x05;

static const auto PAYLOADTYPE_TOKENTRANSFER = 0x00;

static const auto POSTCONDITIONMODE_DENY = 0x02;

static const auto PUBKEYENCODING_COMPRESSED = 0x00;
static const auto PUBKEYENCODING_UNCOMPRESSED = 0x01;

static const auto ANCHORMODE = { Signer::AnchorModeOnChainOnly, Signer::AnchorModeOffChainOnly, Signer::AnchorModeAny };

static void serialize(Data& data, const Proto::MessageSignature& signature) {
    auto sig = signature.data();
    data.insert(data.end(), sig.begin(), sig.end());
}

static void serialize(Data& data, const Proto::SingleSigSpendingCondition& spending) {
    data.push_back(spending.hashmode());
    auto signer = spending.signer();
    data.insert(data.end(), signer.begin(), signer.end());
    encode64BE(spending.nonce(), data);
    encode64BE(spending.fee(), data);
    data.push_back(spending.keyencoding());
    serialize(data, spending.signature());
}

static void serialize(Data& data, const Proto::SpendingCondition& spending) {
    if (!spending.has_single()) {
        throw std::invalid_argument("Invalid spending condition"); 
    }
    serialize(data, spending.single());
}

static void serialize(Data& data, const Proto::Authorization& auth) {
    if (auth.authtype() != AUTHTYPE_STANDARD) {
        throw std::invalid_argument("Invalid authorization type");
    }
    data.push_back(auth.authtype());
    serialize(data, auth.spendingcondition());
}

static void serialize(Data& data, const Proto::Address& addr) {
    data.push_back(addr.version());
    auto hash = addr.hash160();
    data.insert(data.end(), hash.begin(), hash.end());
}

static void serialize(Data& data, const Proto::StandardPrincipalCV& cv) {
    data.push_back(CLARITYTYPE_PRINCIPALSTANDARD);
    serialize(data, cv.address());
}

static void serialize(Data& data, const Proto::PrincipalCV& cv) {
    if (!cv.has_standard()) {
        throw std::invalid_argument("Invalid principal");
    }
    serialize(data, cv.standard());
}

static void serialize(Data& data, const Proto::MemoString& memo) {
    auto content = memo.content();
    if (content.size() > MEMO_MAX_LENGTH_BYTES) {
        throw std::invalid_argument("Invalid length for memo");
    }
    data.insert(data.end(), content.begin(), content.end());
    auto pad = std::string(MEMO_MAX_LENGTH_BYTES - content.size(), '\0');
    data.insert(data.end(), pad.begin(), pad.end());
}

static void serialize(Data& data, const Proto::TokenTransferPayload& transfer) {
    data.push_back(PAYLOADTYPE_TOKENTRANSFER);
    serialize(data, transfer.recipient());
    encode64BE(transfer.amount(), data);
    serialize(data, transfer.memo());
}

static void serialize(Data& data, const Proto::Payload& payload) {
    if (!payload.has_transfer()) {
        throw std::invalid_argument("Invalid payload");
    }
    serialize(data, payload.transfer());
}

static void serialize(Data& data, const Proto::StacksTransaction& transaction) {
    data.push_back(transaction.version());
    encode32BE(transaction.chainid(), data);
    serialize(data, transaction.auth());
    data.push_back(transaction.anchormode());
    data.push_back(POSTCONDITIONMODE_DENY);
    encode32BE(0, data); // no items in post-condition list
    serialize(data, transaction.payload());
}

std::tuple<Data, std::string> Signer::sign() const noexcept {
    try {
        Data encoded;
        auto tx = generate();
        serialize(encoded, sign(tx));
        return std::make_tuple(encoded, "");    
    }
    catch (std::exception& ex) {
        return std::make_tuple(Data(), std::string(ex.what()));
    }
}

Proto::SigningOutput Signer::sign(const Proto::SigningInput& input) noexcept {
    auto signer = Signer(input);
    auto output = Proto::SigningOutput();
    auto [encoded, error] = signer.sign();
    output.set_encoded(&encoded[0], encoded.size());
    output.set_error(error);
    return output;
}

std::tuple<PrivateKey, TWPublicKeyType> Signer::senderKey() const {
    auto senderKey = input.senderkey();
    auto keyType = TWPublicKeyTypeSECP256k1Extended;
    if ((senderKey.size() == (PRIVATE_KEY_LENGTH + 1)) && (senderKey.back() == 0x01)) {
        keyType = TWPublicKeyTypeSECP256k1;
        senderKey.pop_back();
    }
    else if (senderKey.size() != PRIVATE_KEY_LENGTH) {
        throw std::invalid_argument("Invalid private key format"); 
    }
    return std::make_tuple(PrivateKey(senderKey), keyType);
}

Proto::StacksTransaction Signer::generate() const {
    Proto::StacksTransaction tx;
    if (input.has_tokentransfer()) {
        auto tokenTransfer = input.tokentransfer();
        auto[key, keyType] = senderKey();
        auto senderAddress = Address(key.getPublicKey(keyType));
        auto recipientAddress = Address(tokenTransfer.recipient());
        tx.set_version(MAINNET_TRANSACTION_VERSION);
        tx.set_chainid(MAINNET_CHAIN_ID);
        if (std::find(ANCHORMODE.begin(), ANCHORMODE.end(), tokenTransfer.anchormode()) == ANCHORMODE.end()) {
            throw std::invalid_argument("Invalid anchor mode");
        }
        tx.set_anchormode(tokenTransfer.anchormode());
        auto auth = tx.mutable_auth();
        auth->set_authtype(AUTHTYPE_STANDARD);
        auto spending = auth->mutable_spendingcondition()->mutable_single();
        spending->set_hashmode(ADDRESSHASHMODE_SERIALIZEP2PKH);
        spending->set_signer(&senderAddress.bytes[1], senderAddress.bytes.size() - 1);
        spending->set_nonce(tokenTransfer.nonce());
        spending->set_fee(tokenTransfer.fee());
        spending->set_keyencoding(keyType == TWPublicKeyTypeSECP256k1 ? PUBKEYENCODING_COMPRESSED : PUBKEYENCODING_UNCOMPRESSED);
        auto transfer = tx.mutable_payload()->mutable_transfer();
        transfer->set_payloadtype(PAYLOADTYPE_TOKENTRANSFER);
        transfer->set_amount(tokenTransfer.amount());
        auto address = transfer->mutable_recipient()->mutable_standard()->mutable_address();
        address->set_version(recipientAddress.bytes[0]);
        address->set_hash160(&recipientAddress.bytes[1], recipientAddress.bytes.size() - 1);
        auto memo = transfer->mutable_memo();
        memo->set_content(tokenTransfer.memo());
    }
    else {
        throw std::invalid_argument("Invalid input type");
    }
    return tx;
}

Proto::StacksTransaction& Signer::sign(Proto::StacksTransaction& tx) const {
    auto copyTx(tx);
    auto auth = copyTx.mutable_auth();
    if ((auth->authtype() == AUTHTYPE_STANDARD) && auth->spendingcondition().has_single()) {
        auto spending = auth->mutable_spendingcondition()->mutable_single();
        spending->set_nonce(0);
        spending->set_fee(0);
        spending->mutable_signature()->set_data(std::string(RECOVERABLE_ECSDA_SIG_LENGTH_BYTES, 0x00));
        Data encoded;
        serialize(encoded, copyTx);
        auto sigHash = Hash::sha512_256(encoded);
        sigHash.push_back(AUTHTYPE_STANDARD);
        encode64BE(tx.auth().spendingcondition().single().fee(), sigHash);
        encode64BE(tx.auth().spendingcondition().single().nonce(), sigHash);
        sigHash = Hash::sha512_256(sigHash);
        auto [key, _] = senderKey();
        auto signature = key.sign(sigHash, TWCurveSECP256k1);
        signature.insert(signature.begin(), signature.back());
        signature.pop_back();
        spending = tx.mutable_auth()->mutable_spendingcondition()->mutable_single();    
        spending->mutable_signature()->set_data(&signature[0], signature.size());
    }
    else {
        throw std::invalid_argument("Invalid signing type");
    }
    return tx;
}

