#include <wallet/txbuilder.h>

#include <consensus/validation.h>
#include <mw/wallet/TxBuilder.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <util/check.h>
#include <util/fees.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/trace.h>
#include <wallet/change.h>
#include <wallet/fees.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

namespace wallet {

TxBuilder::Ptr TxBuilder::New(const CWallet& wallet, const CCoinControl& coin_control, const std::vector<CRecipient>& recipients, const std::optional<int>& change_position)
{
    ChangeBuilder change = ChangeBuilder::New(wallet, coin_control, recipients, change_position);

    return TxBuilder::Ptr(new TxBuilder{wallet, coin_control, recipients, std::move(change)});
}

util::Result<CreatedTransactionResult> TxBuilder::Build(bool sign)
{
    m_wallet.WalletLogPrintf("TxBuilder::Build() - START\n");
    m_selection_params.m_avoid_partial_spends = m_coin_control.m_avoid_partial_spends;
    m_selection_params.m_long_term_feerate = m_wallet.m_consolidate_feerate;
    m_selection_params.m_subtract_fee_outputs = m_recipients.NumOutputsToSubtractFeeFrom() > 0;

    FeeCalculation feeCalc;
    m_selection_params.m_effective_feerate = GetMinimumFeeRate(m_wallet, m_coin_control, &feeCalc);
    m_selection_params.m_discard_feerate = GetDiscardRate(m_wallet);

    // Do not, ever, assume that it's fine to change the fee rate if the user has explicitly
    // provided one
    if (m_coin_control.m_feerate && m_selection_params.m_effective_feerate > *m_coin_control.m_feerate) {
        return util::Error{strprintf(_("Fee rate (%s) is lower than the minimum fee rate setting (%s)"), m_coin_control.m_feerate->ToString(FeeEstimateMode::SAT_VB), m_selection_params.m_effective_feerate.ToString(FeeEstimateMode::SAT_VB))};
    }

    if (feeCalc.reason == FeeReason::FALLBACK && !m_wallet.m_allow_fallback_fee) {
        // eventually allow a fallback fee
        return util::Error{_("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.")};
    }
    
    // Get available coins
    m_wallet.WalletLogPrintf("TxBuilder::Build() - Getting available coins\n");
    auto available_coins = AvailableCoins(
        m_wallet,
        &m_coin_control,
        m_selection_params.m_effective_feerate,
        1,          /*nMinimumAmount*/
        MAX_MONEY,  /*nMaximumAmount*/
        MAX_MONEY,  /*nMinimumSumAmount*/
        0           /*nMaximumCount*/
    );
    
    // Select coins to spend
    m_wallet.WalletLogPrintf("TxBuilder::Build() - Selecting coins\n");
    auto result = SelectInputCoins(available_coins);
    if (!result) {
        return util::Error{ErrorString(result)};
    }
    
    std::vector<GenericWalletUTXO> selected_coins = result->GetShuffledInputVector();
    TRACE5(coin_selection, selected_coins, m_wallet.GetName().c_str(), GetAlgorithmName(result->GetAlgo()).c_str(), result->GetTarget(), result->GetWaste(), result->GetSelectedValue());

    // Add selected inputs
    m_wallet.WalletLogPrintf("TxBuilder::Build() - Adding inputs\n");
    auto add_inputs_error = AddInputs(selected_coins);
    if (add_inputs_error.has_value()) {
        return add_inputs_error.value();
    }
    
    DiscourageFeeSniping(m_tx, m_selection_params.rng_fast, m_wallet.chain(), m_wallet.GetLastBlockHash(), m_wallet.GetLastBlockHeight());
    
    // Add outputs (recipients, change, pegin)
    m_wallet.WalletLogPrintf("TxBuilder::Build() - Adding outputs\n");
    auto add_outputs_error = AddOutputs(m_selection_params, *result);
    if (add_outputs_error.has_value()) {
        return add_outputs_error.value();
    }

    m_wallet.WalletLogPrintf("TxBuilder::Build() - Calling CalcMaxSignedTxBytes\n");
    auto tx_bytes = CalcMaxSignedTxBytes(m_tx);
    if (!tx_bytes) {
        return util::Error{ErrorString(tx_bytes)};
    }
    
    // Subtract fee from outputs
    m_wallet.WalletLogPrintf("TxBuilder::Build() - Subtracting fee from outputs\n");
    auto subtract_fee_error = SubtractFeeFromOutputs(m_selection_params);
    if (subtract_fee_error.has_value()) {
        return subtract_fee_error.value();
    }
    
    if (m_selection_params.m_tx_type != TxType::LTC_TO_LTC) {
        // Build and add the MWEB tx
        m_wallet.WalletLogPrintf("TxBuilder::Build() - Adding MWEB tx\n");
        auto add_mweb_tx_error = AddMWEBTx();
        if (add_mweb_tx_error.has_value()) {
            return add_mweb_tx_error.value();
        }
    }

    // Give up if change keypool ran out and change is required
    if (m_change.script_or_address.IsEmpty() && !m_change.change_position.IsNull()) {
        return util::Error{m_change.error};
    }

    m_wallet.WalletLogPrintf("TxBuilder::Build() - Signing tx\n");
    if (sign && !m_wallet.SignTransaction(m_tx)) {
        return util::Error{_("Signing transaction failed")};
    }

    // Return the constructed transaction data.
    CTransactionRef tx = MakeTransactionRef(CTransaction(m_tx));

    // Limit size
    if ((sign && GetTransactionWeight(*tx) > MAX_STANDARD_TX_WEIGHT) || (!sign && *tx_bytes > MAX_STANDARD_TX_WEIGHT))
    {
        return util::Error{_("Transaction too large")};
    }

    const CAmount fee_paid = GetFeePaid();
    if (fee_paid > m_wallet.m_default_max_tx_fee) {
        return util::Error{TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED)};
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        if (!m_wallet.chain().checkChainLimits(tx)) {
            return util::Error{_("Transaction has too long of a mempool chain")};
        }
    }

    // Before we return success, we assume any change key will be used to prevent
    // accidental re-use.
    if (m_change.reserve_dest) {
        m_change.reserve_dest->KeepDestination();
    }
    
    m_wallet.WalletLogPrintf("Fee Calculation: Fee:%d Bytes:%u Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              fee_paid, *tx_bytes, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool) > 0.0 ? 100 * feeCalc.est.pass.withinTarget / (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool) : 0.0,
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool) > 0.0 ? 100 * feeCalc.est.fail.withinTarget / (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool) : 0.0,
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return CreatedTransactionResult(tx, fee_paid, m_change.GetPosition(), feeCalc);
}

util::Result<SelectionResult> TxBuilder::SelectInputCoins(const CoinsResult& available_coins)
{
    auto select_by_type = [&](const TxType& tx_type) -> std::optional<SelectionResult> {
        m_selection_params.m_tx_type = tx_type;
        m_selection_params.m_change_params = m_change.BuildParams(m_wallet, m_coin_control, m_selection_params, m_recipients);
        const CAmount nTarget = CalcSelectionTarget(m_selection_params, tx_type);
        CoinsResult available_coins_mut = available_coins;

        m_wallet.WalletLogPrintf("TxBuilder::SelectInputCoins() - Selection target: %s, Change on MWEB: %i\n", FormatMoney(nTarget), ChangeBuilder::ChangeBelongsOnMWEB(m_selection_params.m_tx_type, m_coin_control.destChange));
        return SelectCoins(m_wallet, available_coins_mut, nTarget, m_coin_control, m_selection_params);
    };
    
    // MW: TODO - Handle manually selected inputs that conflict with TxType
    if (!m_recipients.MWEB().empty()) {
        // First try to construct an MWEB-to-MWEB transaction
        std::optional<SelectionResult> mweb_to_mweb_result = select_by_type(TxType::MWEB_TO_MWEB);
        if (mweb_to_mweb_result.has_value()) {
            m_wallet.WalletLogPrintf("TxBuilder::SelectInputCoins() - MWEB_TO_MWEB\n");
            return *mweb_to_mweb_result;
        }

        // If MWEB-to-MWEB fails, create a peg-in transaction
        std::optional<SelectionResult> pegin_result = select_by_type(TxType::PEGIN);
        if (pegin_result.has_value()) {
            m_wallet.WalletLogPrintf("TxBuilder::SelectInputCoins() - PEGIN\n");
            return *pegin_result;
        }
    } else {
        // First try to construct a LTC-to-LTC transaction
        std::optional<SelectionResult> ltc_to_ltc_result = select_by_type(TxType::LTC_TO_LTC);
        if (ltc_to_ltc_result.has_value()) {
            m_wallet.WalletLogPrintf("TxBuilder::SelectInputCoins() - LTC_TO_LTC\n");
            return *ltc_to_ltc_result;
        }

        // Only supports pegging-out to one address
        if (m_recipients.size() > 1) {
            return util::Error{_("Only one pegout per transaction is currently supported")};
        }

        // If LTC-to-LTC fails, try a simple peg-out transaction (MWEB->LTC)
        std::optional<SelectionResult> mweb_to_ltc_result = select_by_type(TxType::PEGOUT);
        if (mweb_to_ltc_result.has_value()) {
            m_wallet.WalletLogPrintf("TxBuilder::SelectInputCoins() - PEGOUT\n");
            return *mweb_to_ltc_result;
        }

        // If simple peg-out fails, try a complex peg-out transaction (LTC->MWEB->LTC)
        std::optional<SelectionResult> pegin_pegout_result =  select_by_type(TxType::PEGIN_PEGOUT);
        if (pegin_pegout_result.has_value()) {
            m_wallet.WalletLogPrintf("TxBuilder::SelectInputCoins() - PEGIN_PEGOUT\n");
            return *pegin_pegout_result;
        }
    }

    return util::Error{_("Insufficient funds")};
}

std::optional<util::Error> TxBuilder::AddInputs(const std::vector<GenericWalletUTXO>& shuffled_inputs)
{
    m_selected_coins = shuffled_inputs;

    // The sequence number is set to non-maxint so that DiscourageFeeSniping
    // works.
    //
    // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
    // we use the highest possible value in that range (maxint-2)
    // to avoid conflicting with other possible uses of nSequence,
    // and in the spirit of "smallest possible change from prior
    // behavior."
    const uint32_t nSequence{m_coin_control.m_signal_bip125_rbf.value_or(m_wallet.m_signal_rbf) ? MAX_BIP125_RBF_SEQUENCE : CTxIn::MAX_SEQUENCE_NONFINAL};
    for (const GenericWalletUTXO& utxo : shuffled_inputs) {
        if (utxo.IsMWEB()) {
            const MWWalletUTXO& mweb_utxo = utxo.GetMWEB();

            mw::MutableInput mweb_input = mw::MutableInput::FromOutput(mweb_utxo.output);
            mweb_input.amount = mweb_utxo.coin.amount;
            mweb_input.spend_key = mweb_utxo.coin.spend_key;
            mweb_input.raw_blind = mweb_utxo.coin.blind;
            m_tx.mweb_tx.inputs.push_back(std::move(mweb_input));
        } else {
            m_tx.vin.push_back(CTxIn(utxo.GetID().ToOutPoint(), CScript(), nSequence));
        }
    }

    return std::nullopt;
}

std::optional<util::Error> TxBuilder::AddOutputs(const CoinSelectionParams& coin_selection_params, const SelectionResult& selection_result)
{
    const TxType tx_type = coin_selection_params.m_tx_type;

    // Outputs for the payees
    m_wallet.WalletLogPrintf("TxBuilder::AddOutputs() - Building recipients\n");
    for (const CRecipient& recipient : m_recipients.All()) {
        if (recipient.IsMWEB()) {
            mw::MutableOutput mweb_output;
            mweb_output.recipient = recipient;
            m_tx.mweb_tx.outputs.push_back(std::move(mweb_output));
        } else {
            if (tx_type == TxType::PEGOUT || tx_type == TxType::PEGIN_PEGOUT) {
                m_tx.mweb_tx.AddPegout(recipient);
            } else {
                m_tx.vout.push_back(CTxOut(recipient.nAmount, recipient.GetScript()));
            }
        }
    }

    // Add the change output
    m_wallet.WalletLogPrintf(
        "TxBuilder::AddOutputs() - Getting change - Selected value: %s, effective value: %s, diff(i.e. input fee): %lld, change_fee: %lld\n",
        FormatMoney(selection_result.GetSelectedValue()),
        FormatMoney(selection_result.GetSelectedEffectiveValue()),
        selection_result.GetSelectedValue() - selection_result.GetSelectedEffectiveValue(),
        coin_selection_params.m_change_params.m_change_fee
    );
    const CAmount change_amount = selection_result.GetChange(coin_selection_params.m_change_params.min_viable_change, coin_selection_params.m_change_params.m_change_fee);
    m_wallet.WalletLogPrintf("TxBuilder::AddOutputs() - change_amount: %s\n", FormatMoney(change_amount));
    if (change_amount > 0) {
        m_change.amount = change_amount;
        if (ChangeBuilder::ChangeBelongsOnMWEB(tx_type, m_coin_control.destChange)) {
            m_wallet.WalletLogPrintf("TxBuilder::AddOutputs() - Change on MWEB\n");
            if (!m_change.script_or_address.IsMWEB()) {
                StealthAddress change_address;
                if (!m_wallet.GetMWWallet()->GetStealthAddress(mw::CHANGE_INDEX, change_address)) {
                    return util::Error{_("Failed to retrieve change stealth address")};
                }
                m_change.script_or_address = change_address;
            }

            mw::MutableOutput mweb_output;
            mweb_output.recipient = CRecipient{m_change.script_or_address.GetMWEBAddress(), change_amount, false};
            m_tx.mweb_tx.outputs.push_back(std::move(mweb_output));

            m_change.change_position = mw::Hash();
        } else {
            m_wallet.WalletLogPrintf("TxBuilder::AddOutputs() - Change on LTC\n");
            CTxOut newTxOut(change_amount, m_change.script_or_address.GetScript()); // MW: TODO - What if script_or_address is MWEB address?
            if (m_change.change_position.IsNull()) {
                // Insert change txn at random position:
                m_change.change_position = coin_selection_params.rng_fast.randrange(m_tx.vout.size() + 1);
            } else if (m_change.change_position.IsLTC() && m_change.change_position.ToLTC() > m_tx.vout.size()) {
                return util::Error{_("Transaction change output index out of range")};
            }

            if (m_change.change_position.IsLTC()) {
                m_tx.vout.insert(m_tx.vout.begin() + m_change.change_position.ToLTC(), newTxOut);
            }
        }
    } else {
        m_change.amount = 0;
        m_change.change_position.SetNull();
    }

    // Add peg-in output for PEGIN and PEGIN_PEGOUT transactions
    if (tx_type == TxType::PEGIN || tx_type == TxType::PEGIN_PEGOUT) {
        m_wallet.WalletLogPrintf("TxBuilder::AddOutputs() - Adding pegin\n");
        CAmount pegin_amount{0};
        for (const GenericWalletUTXO& input : selection_result.GetInputSet()) {
            if (!input.IsMWEB()) {
                pegin_amount += input.GetValue();
            }
        }

        if (m_change.change_position.IsLTC()) {
            pegin_amount -= m_change.amount;
        }

        m_tx.mweb_tx.SetPeginAmount(pegin_amount);
        m_tx.vout.push_back(CTxOut{pegin_amount, GetScriptForPegin(mw::Hash())});
        CTxOut& pegin_output = m_tx.vout.back();

        const util::Result<CAmount> ltc_fee_result = CalcLTCFee(coin_selection_params.m_effective_feerate);
        if (!ltc_fee_result) {
            return util::Error{ErrorString(ltc_fee_result)};
        }

        // Reduce the pegin amount by ltc_fee
        pegin_output.nValue -= ltc_fee_result.value();
        m_tx.mweb_tx.SetPeginAmount(pegin_output.nValue);
        m_wallet.WalletLogPrintf("TxBuilder::AddOutputs() - pegin_amount: %s, ltc_fee: %lld, change_amount: %s\n", FormatMoney(pegin_output.nValue), *ltc_fee_result, FormatMoney(m_change.amount));

        // Error if the pegin output is reduced to be below dust
        if (pegin_output.nValue < 0) {
            return util::Error{_("The transaction amount is too small to pay the fee")};
        } else if (IsDust(pegin_output, m_wallet.chain().relayDustFee())) {
            return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
        }
    }

    m_wallet.WalletLogPrintf("TxBuilder::AddOutputs() - Finished\n");
    return std::nullopt;
}

std::optional<util::Error> TxBuilder::SubtractFeeFromOutputs(const CoinSelectionParams& coin_selection_params)
{
    util::Result<CAmount> ltc_fee_result = CalcLTCFee(coin_selection_params.m_effective_feerate);
    if (!ltc_fee_result) {
        return util::Error{ErrorString(ltc_fee_result)};
    }

    CAmount mweb_fee = m_mweb.CalcMWEBFee(coin_selection_params.m_effective_feerate);
    CAmount fee_needed = *ltc_fee_result + mweb_fee;
    CAmount current_fee = GetFeePaid();
    m_wallet.WalletLogPrintf("TxBuilder::SubtractFeeFromOutputs() - fee_needed: %lld (%lld LTC, %lld MWEB), current_fee: %lld\n", fee_needed, *ltc_fee_result, mweb_fee, current_fee);

    // If there is a change output and we overpay the fees then increase the change to match the fee needed
    if (!m_change.GetPosition().IsNull() && fee_needed < current_fee) {
        if (m_change.GetPosition().IsLTC()) {
            auto& change = m_tx.vout.at(m_change.GetPosition().ToLTC());
            change.nValue += current_fee - fee_needed;
        } else {
            m_change.amount += current_fee - fee_needed;
            m_mweb.outputs.back().nAmount += current_fee - fee_needed;
            m_wallet.WalletLogPrintf("TxBuilder::SubtractFeeFromOutputs() - change amount: %s = %s, updated fee_paid: %lld\n", FormatMoney(m_change.amount), FormatMoney(m_mweb.outputs.back().nAmount), GetFeePaid());
        }
        current_fee = fee_needed;
    }

    // The only time that fee_needed should be less than the amount available for fees is when
    // we are subtracting the fee from the outputs. If this occurs at any other time, it is a bug.
    assert(coin_selection_params.m_subtract_fee_outputs || fee_needed <= current_fee);

    const CAmount to_reduce = fee_needed - current_fee;
    const size_t outputs_to_subtract_fee_from = m_recipients.NumOutputsToSubtractFeeFrom();

    bool fFirst = true;

    if (m_mweb.pegouts.empty()) {
        size_t i = 0;
        for (const auto& recipient : m_recipients.LTC()) {
            ChangePosition change_pos = m_change.GetPosition();
            if (change_pos == i) {
                i++;
            }

            CTxOut& txout = m_tx.vout[i];
            if (recipient.fSubtractFeeFromAmount) {
                txout.nValue -= to_reduce / outputs_to_subtract_fee_from; // Subtract fee equally from each selected recipient

                // first receiver pays the remainder not divisible by output count
                if (fFirst) {
                    fFirst = false;
                    txout.nValue -= to_reduce % outputs_to_subtract_fee_from;
                }
            }

            // Error if this output is reduced to be below dust
            if (txout.nValue < 0) {
                return util::Error{_("The transaction amount is too small to pay the fee")};
            } else if (IsDust(txout, m_wallet.chain().relayDustFee())) {
                return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
            }

            i++;
        }
    }

    m_wallet.WalletLogPrintf("TxBuilder::SubtractFeeFromOutputs() - Subtracting from MWEB outputs\n");
    for (CRecipient& recipient : m_mweb.outputs) {
        if (recipient.fSubtractFeeFromAmount) {
            recipient.nAmount -= to_reduce / outputs_to_subtract_fee_from;

            if (fFirst) {
                fFirst = false;
                recipient.nAmount -= to_reduce % outputs_to_subtract_fee_from;
            }
        }

        if (recipient.nAmount < 0) {
            return util::Error{_("The transaction amount is too small to pay the fee")};
        }
    }

    m_wallet.WalletLogPrintf("TxBuilder::SubtractFeeFromOutputs() - Subtracting from pegouts\n");
    for (CRecipient& recipient : m_mweb.pegouts) {
        if (recipient.fSubtractFeeFromAmount) {
            recipient.nAmount -= to_reduce / outputs_to_subtract_fee_from;

            if (fFirst) {
                fFirst = false;
                recipient.nAmount -= to_reduce % outputs_to_subtract_fee_from;
            }
        }

        if (recipient.nAmount < 0) {
            return util::Error{_("The transaction amount is too small to pay the fee")};
        } else if (IsDust(CTxOut(recipient.nAmount, recipient.GetScript()), m_wallet.chain().relayDustFee())) {
            return util::Error{_("The transaction amount is too small to send after the fee has been deducted")};
        }
    }

    m_wallet.WalletLogPrintf("TxBuilder::SubtractFeeFromOutputs() - Finished\n");
    return std::nullopt;
}

std::optional<util::Error> TxBuilder::AddMWEBTx()
{
    auto mweb_tx_result = m_mweb.Finalize(m_selection_params.m_effective_feerate);
    if (!mweb_tx_result) {
        return util::Error{util::ErrorString(mweb_tx_result)};
    }

    m_wallet.WalletLogPrintf("TxBuilder::AddMWEBTx() - MWEB transaction built\n");
    std::pair<mw::Transaction::CPtr, std::vector<mw::Coin>> mweb_tx = mweb_tx_result.value();

    // Update change position
    if (m_change.change_position.IsMWEB()) {
        for (const mw::Coin& output_coin : mweb_tx.second) {
            if (output_coin.address.has_value() && *output_coin.address == m_change.script_or_address.GetMWEBAddress()) {
                m_change.change_position = output_coin.output_id;
                break;
            }
        }
    }

    if (!mweb_tx.second.empty()) {
        m_wallet.GetMWWallet()->SaveToWallet(mweb_tx.second); // MW: TODO - This should only be done in CommitTransaction, since this could be called with add_to_wallet=false
    }

    // TxBuilder::BuildTx only builds partial coins.
    // We still need to rewind them to populate any remaining fields, like address index.
    m_wallet.GetMWWallet()->RewindOutputs(CTransaction(m_tx));

    // Update pegin output
    auto pegins = m_tx.mweb_tx.GetPegIns();
    if (!pegins.empty()) {
        for (size_t i = 0; i < m_tx.vout.size(); i++) {
            if (IsPegInOutput(CTransaction(m_tx).GetOutput(i))) {
                m_tx.vout[i].nValue = pegins.front().GetAmount();
                m_tx.vout[i].scriptPubKey = GetScriptForPegin(pegins.front().GetKernelID());
                break;
            }
        }
    }

    return std::nullopt;
}

CAmount TxBuilder::CalcSelectionTarget(const CoinSelectionParams& coin_selection_params, const TxType& tx_type) const
{
    m_wallet.WalletLogPrintf("TxBuilder::CalcSelectionTarget() - Calculating target for type: %d\n", (int)tx_type);

    const CAmount recipients_sum = m_recipients.Sum();
    if (coin_selection_params.m_subtract_fee_outputs) {
        return recipients_sum;
    }

    std::vector<CRecipient> ltc_recipients = m_recipients.LTC();
    std::vector<CRecipient> mweb_recipients = m_recipients.MWEB();
    
    // Static vsize overhead + outputs vsize. 4 nVersion, 4 nLocktime, 1 input count, 1 witness overhead (dummy, flag, stack size), and bytes for output count
    size_t num_ltc_recipients = ltc_recipients.size();
    if (tx_type == TxType::PEGIN || tx_type == TxType::PEGIN_PEGOUT) {
        ++num_ltc_recipients;
    }
    const size_t base_ltc_bytes = 10 + GetSizeOfCompactSize(num_ltc_recipients);

    size_t ltc_recipient_bytes{0};
    for (const auto& recipient : ltc_recipients) {
        ltc_recipient_bytes += ::GetSerializeSize(CTxOut(recipient.nAmount, recipient.GetScript()), PROTOCOL_VERSION);
    }

    // Maximum size of a pegin output (in bytes)
    const size_t pegin_output_bytes = ::GetSerializeSize(CTxOut{MAX_MONEY, GetScriptForPegin(mw::Hash())}, PROTOCOL_VERSION);

    // Size (in bytes) of a hogex input - Equivalent to ::GetSerializeSize(CTxIn(), PROTOCOL_VERSION)
    const size_t hogex_input_bytes = 41;

    switch (tx_type) {
    case TxType::MWEB_TO_MWEB: {
        const size_t mweb_weight = mw::KERNEL_WITH_STEALTH_WEIGHT + (mw::STANDARD_OUTPUT_WEIGHT * mweb_recipients.size());
        const CAmount non_change_mweb_fee = coin_selection_params.m_effective_feerate.GetFee(0, mweb_weight);
        return recipients_sum + non_change_mweb_fee;
    }
    case TxType::PEGIN: {
        const size_t pegin_bytes = base_ltc_bytes + pegin_output_bytes + hogex_input_bytes;
        const size_t pegin_mweb_weight = mw::KERNEL_WITH_STEALTH_WEIGHT + (mw::STANDARD_OUTPUT_WEIGHT * mweb_recipients.size());
        const CAmount pegin_fee = coin_selection_params.m_effective_feerate.GetFee(pegin_bytes, pegin_mweb_weight);
        m_wallet.WalletLogPrintf("TxBuilder::CalcSelectionTarget() - Max LTC bytes: %u, MWEB weight: %u, pegin_fee: %lld\n", pegin_bytes, pegin_mweb_weight, pegin_fee);
        return recipients_sum + pegin_fee;
    }
    case TxType::PEGOUT: {
        // Include enough fee to pay for the kernel (with pegout script(s)) and the hogex pegout output(s).
        std::vector<PegOutCoin> pegouts;
        std::transform(
            ltc_recipients.cbegin(), ltc_recipients.cend(), std::back_inserter(pegouts),
            [](const CRecipient& recipient) { return PegOutCoin(recipient.nAmount, recipient.GetScript()); }
        );
        const size_t pegout_kernel_weight = Weight::CalcKernelWeight(true, pegouts);

        const CAmount basic_pegout_fee = coin_selection_params.m_effective_feerate.GetFee(ltc_recipient_bytes, pegout_kernel_weight);
        return recipients_sum + basic_pegout_fee;
    }
    case TxType::PEGIN_PEGOUT: {
        // Include enough fee to pay for:
        // * LTC tx with a pegin output
        // * Hogex pegin input
        // * Hogex pegout output(s)
        // * Kernel (with pegin amount and pegout script(s))
        std::vector<PegOutCoin> pegouts;
        std::transform(
            ltc_recipients.cbegin(), ltc_recipients.cend(), std::back_inserter(pegouts),
            [](const CRecipient& recipient) { return PegOutCoin(recipient.nAmount, recipient.GetScript()); }
        );
        const size_t pegout_kernel_weight = Weight::CalcKernelWeight(true, pegouts);

        const size_t pegin_bytes = base_ltc_bytes + pegin_output_bytes + hogex_input_bytes + ltc_recipient_bytes;
        const CAmount complex_pegout_fee = coin_selection_params.m_effective_feerate.GetFee(pegin_bytes, pegout_kernel_weight);
        return recipients_sum + complex_pegout_fee;
    }
    case TxType::LTC_TO_LTC: {
        const CAmount ltc_to_ltc_fee = coin_selection_params.m_effective_feerate.GetFee(base_ltc_bytes + ltc_recipient_bytes, 0);
        return recipients_sum + ltc_to_ltc_fee;
    }
    }

    assert(false);
}

CAmount TxBuilder::GetFeePaid() const
{
    const CAmount ltc_input_sum = std::accumulate(
        m_selected_coins.cbegin(), m_selected_coins.cend(), CAmount{0},
        [](CAmount sum, const GenericWalletUTXO& coin) { return coin.IsMWEB() ? sum : (sum + coin.GetValue()); }
    );
    const CAmount ltc_output_sum = std::accumulate(
        m_tx.vout.cbegin(), m_tx.vout.cend(), CAmount{0},
        [](CAmount sum, const CTxOut& txout) { return sum += txout.nValue; }
    );
    assert(ltc_input_sum >= ltc_output_sum);
    const CAmount ltc_fee = ltc_input_sum - ltc_output_sum;
    m_wallet.WalletLogPrintf("TxBuilder::GetFeePaid() - ltc_input_sum: %s, ltc_output_sum: %s, ltc_fee: %lld\n", FormatMoney(ltc_input_sum), FormatMoney(ltc_output_sum), ltc_fee);
    
    const CAmount mweb_input_sum = std::accumulate(
        m_selected_coins.cbegin(), m_selected_coins.cend(), CAmount{0},
        [](CAmount sum, const GenericWalletUTXO& coin) { return coin.IsMWEB() ? (sum + coin.GetValue()) : sum; }
    );
    const CAmount mweb_pegin = m_tx.mweb_tx.GetPeginAmount().value_or(0);
    const CAmount mweb_output_sum = std::accumulate(
        m_tx.mweb_tx.outputs.cbegin(), m_tx.mweb_tx.outputs.cend(), CAmount{0},
        [](CAmount sum, const mw::MutableOutput& output) { return sum += (output.recipient.has_value() ? output.recipient->nAmount : 0); }
    );
    std::vector<CRecipient> pegouts = m_tx.mweb_tx.GetPegouts();
    const CAmount mweb_pegout_sum = std::accumulate(
        pegouts.cbegin(), pegouts.cend(), CAmount{0},
        [](CAmount sum, const CRecipient& recipient) { return sum += recipient.nAmount; }
    );
    m_wallet.WalletLogPrintf("TxBuilder::GetFeePaid() - mweb_input_sum: %s, mweb_pegin: %s, mweb_output_sum: %s, mweb_pegout_sum: %s\n", FormatMoney(mweb_input_sum), FormatMoney(mweb_pegin), FormatMoney(mweb_output_sum), FormatMoney(mweb_pegout_sum));
    assert((mweb_input_sum + mweb_pegin) >= (mweb_output_sum + mweb_pegout_sum));
    const CAmount mweb_fee = (mweb_input_sum + mweb_pegin) - (mweb_output_sum + mweb_pegout_sum);

    return ltc_fee + mweb_fee;
}

// Calculate the portion of the fee that should be paid on the LTC side.
util::Result<CAmount> TxBuilder::CalcLTCFee(const CFeeRate& fee_rate) const
{
    CMutableTransaction tx_without_mweb = m_tx;
    tx_without_mweb.mweb_tx.SetNull();
    
    util::Result<size_t> tx_size_result = CalcMaxSignedTxBytes(tx_without_mweb);
    if (!tx_size_result) {
        return util::Error{ErrorString(tx_size_result)};
    }

    size_t tx_bytes = *tx_size_result;
    if (m_tx.mweb_tx.GetPeginAmount().has_value()) {
        // Add hogex input bytes
        tx_bytes += ::GetSerializeSize(CTxIn(), PROTOCOL_VERSION);
    }

    m_wallet.WalletLogPrintf(
        "TxBuilder::CalcLTCFee() - tx_size: %llu, with_hogex: %llu, inputs: %llu, outputs: %llu\n",
        *tx_size_result,
        tx_bytes,
        tx_without_mweb.vin.size(),
        tx_without_mweb.vout.size()
    );
    return fee_rate.GetFee(tx_bytes, 0);
}

util::Result<size_t> TxBuilder::CalcMaxSignedTxBytes(const CMutableTransaction& tx) const
{
    TxSize tx_sizes = CalculateMaximumSignedTxSize(CTransaction(tx), &m_wallet, &m_coin_control);
    int nBytes = tx_sizes.vsize;
    if (nBytes == -1) {
        return util::Error{_("Missing solving data for estimating transaction size")};
    }

    return (size_t)nBytes;
}

} // namespace wallet
