#include <mweb/mweb_spend.h>
#include <mw/wallet/TxBuilder.h>

using namespace MWEB;

util::Result<std::pair<mw::Transaction::CPtr, std::vector<mw::Coin>>> MutableMWEBTx::Finalize(const CFeeRate& feeRate) const noexcept
{
    // Add recipients (Includes any MWEB change outputs)
    std::vector<mw::Recipient> receivers;
    std::transform(
        outputs.cbegin(), outputs.cend(), std::back_inserter(receivers),
        [](const wallet::CRecipient& recipient) { return mw::Recipient{recipient.nAmount, recipient.GetMWEBAddress()}; });

    std::vector<mw::Coin> input_coins;
    for (const wallet::MWWalletUTXO& input : inputs) {
        input_coins.push_back(input.coin);
    }

    mw::Transaction::CPtr tx;
    std::vector<mw::Coin> output_coins;

    try {
        // Create the MWEB transaction
        tx = mw::TxBuilder::BuildTx(
            input_coins,
            receivers,
            GetPegOutCoins(),
            pegin_amount,
            CalcMWEBFee(feeRate),
            output_coins);
    } catch (std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }

    return std::make_pair(tx, std::move(output_coins));
}

std::vector<PegOutCoin> MutableMWEBTx::GetPegOutCoins() const noexcept
{
    std::vector<PegOutCoin> pegout_coins;
    std::transform(
        pegouts.cbegin(), pegouts.cend(), std::back_inserter(pegout_coins),
        [](const wallet::CRecipient& pegout) { return PegOutCoin{pegout.nAmount, pegout.GetScript()}; });
    return pegout_coins;
}

// The fee to be paid on the MWEB side.
// This includes all MWEB inputs, outputs, and kernels, as well as any HogEx outputs for pegouts.
CAmount MutableMWEBTx::CalcMWEBFee(const CFeeRate& feeRate) const noexcept
{
    size_t nBytes = 0;
    for (const PegOutCoin& pegout : GetPegOutCoins()) {
        nBytes += ::GetSerializeSize(CTxOut(pegout.GetAmount(), pegout.GetScriptPubKey()), PROTOCOL_VERSION);
    }

    return feeRate.GetFee(nBytes, CalcMWEBWeight());
}

uint32_t MutableMWEBTx::CalcMWEBWeight() const noexcept
{
    if (inputs.empty() && outputs.empty() && pegouts.empty() && !pegin_amount.has_value()) {
        return 0;
    }

    return (mw::STANDARD_OUTPUT_WEIGHT * outputs.size()) + Weight::CalcKernelWeight(true, GetPegOutCoins());
}
