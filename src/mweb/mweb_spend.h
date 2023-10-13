#pragma once

#include <consensus/amount.h>
#include <mw/consensus/Weight.h>
#include <mw/models/tx/PegInCoin.h>
#include <policy/feerate.h>
#include <wallet/recipient.h>
#include <wallet/utxo.h>
#include <util/result.h>
#include <optional>

namespace MWEB {

struct MutableMWEBTx {
    std::vector<wallet::MWWalletUTXO> inputs{};
    std::vector<wallet::CRecipient> outputs{};
    std::vector<wallet::CRecipient> pegouts{};
    std::optional<CAmount> pegin_amount{std::nullopt};

    util::Result<std::pair<mw::Transaction::CPtr, std::vector<mw::Coin>>> Finalize(const CFeeRate& feeRate) const noexcept;

    std::vector<PegOutCoin> GetPegOutCoins() const noexcept;

    // The fee to be paid on the MWEB side.
    // This includes all MWEB inputs, outputs, and kernels, as well as any HogEx outputs for pegouts.
    CAmount CalcMWEBFee(const CFeeRate& feeRate) const noexcept;

    uint32_t CalcMWEBWeight() const noexcept;
};

}
