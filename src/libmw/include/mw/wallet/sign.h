#pragma once

#include <mw/common/Macros.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/wallet/Coin.h>

#include <coins.h>
#include <primitives/transaction.h>
#include <util/result.h>

MW_NAMESPACE

struct SignTxResult
{
    //! Contains a mw::Coin for each output that was signed for the MutableTx, mapped to the output's ID.
    std::map<mw::Hash, mw::Coin> coins_by_output_id;
};

/// <summary>
/// Finalizes a MutableTx by generating all excesses, pubkeys, signatures, etc.
/// </summary>
/// <param name="tx">A MutableTx containing all inputs, kernels, and outputs. Components can be stubs (unsigned) or already finalized/signed.</param>
/// <param name="input_coins"></param>
/// <returns></returns>
// MW: TODO - Probably needs wallet ptr or some kind of signing provider to generate secrets.
extern util::Result<mw::SignTxResult> SignTx(mw::MutableTx& tx, const std::map<mw::Hash, mw::Coin>& input_coins) noexcept;

END_NAMESPACE
