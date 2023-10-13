// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_COINCONTROL_H
#define BITCOIN_WALLET_COINCONTROL_H

#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <script/keyorigin.h>
#include <script/signingprovider.h>
#include <script/standard.h>

#include <optional>
#include <algorithm>
#include <map>
#include <set>

namespace wallet {
const int DEFAULT_MIN_DEPTH = 0;
const int DEFAULT_MAX_DEPTH = 9999999;

//! Default for -avoidpartialspends
static constexpr bool DEFAULT_AVOIDPARTIALSPENDS = false;

/** Coin Control Features. */
class CCoinControl
{
public:
    //! Custom change destination, if not set an address is generated
    CTxDestination destChange = CNoDestination();
    //! Override the default change type if set, ignored if destChange is set
    std::optional<OutputType> m_change_type;
    //! If false, only safe inputs will be used
    bool m_include_unsafe_inputs = false;
    //! If true, the selection process can add extra unselected inputs from the wallet
    //! while requires all selected inputs be used
    bool m_allow_other_inputs = false;
    //! Includes watch only addresses which are solvable
    bool fAllowWatchOnly = false;
    //! Override automatic min/max checks on fee, m_feerate must be set if true
    bool fOverrideFeeRate = false;
    //! Override the wallet's m_pay_tx_fee if set
    std::optional<CFeeRate> m_feerate;
    //! Override the default confirmation target if set
    std::optional<unsigned int> m_confirm_target;
    //! Override the wallet's m_signal_rbf if set
    std::optional<bool> m_signal_bip125_rbf;
    //! Avoid partial use of funds sent to a given address
    bool m_avoid_partial_spends = DEFAULT_AVOIDPARTIALSPENDS;
    //! Forbids inclusion of dirty (previously used) addresses
    bool m_avoid_address_reuse = false;
    //! Fee estimation mode to control arguments to estimateSmartFee
    FeeEstimateMode m_fee_mode = FeeEstimateMode::UNSET;
    //! Minimum chain depth value for coin availability
    int m_min_depth = DEFAULT_MIN_DEPTH;
    //! Maximum chain depth value for coin availability
    int m_max_depth = DEFAULT_MAX_DEPTH;
    //! SigningProvider that has pubkeys and scripts to do spend size estimation for external inputs
    FlatSigningProvider m_external_provider;
	//! Peg-in from LTC address to own MWEB address
	bool fPegIn = false;
	//! Peg-out from MWEB address to own LTC address
	bool fPegOut = false;

    CCoinControl();

    bool HasSelected() const
    {
        return (setSelected.size() > 0);
    }

    bool IsSelected(const GenericOutputID& output_idx) const
    {
        return (setSelected.count(output_idx) > 0);
    }

    bool IsExternalSelected(const GenericOutputID& output_idx) const
    {
        return (m_external_outputs.count(output_idx) > 0);
    }

    bool GetExternalOutput(const GenericOutputID& output_idx, GenericOutput& output) const
    {
        const auto ext_it = m_external_outputs.find(output_idx);
        if (ext_it == m_external_outputs.end()) {
            return false;
        }
        output = ext_it->second;
        return true;
    }

    void Select(const GenericOutputID& output_idx)
    {
        setSelected.insert(output_idx);
    }

    void SelectExternal(const GenericOutputID& output_idx, const GenericOutput& output)
    {
        setSelected.insert(output_idx);
        m_external_outputs.emplace(output_idx, output);
    }

    void UnSelect(const GenericOutputID& output_idx)
    {
        setSelected.erase(output_idx);
    }

    void UnSelectAll()
    {
        setSelected.clear();
    }

    void ListSelected(std::vector<GenericOutputID>& vOutpoints) const
    {
        vOutpoints.assign(setSelected.begin(), setSelected.end());
    }

    void SetInputWeight(const GenericOutputID& output_idx, int64_t weight)
    {
        m_input_weights[output_idx] = weight;
    }

    bool HasInputWeight(const GenericOutputID& output_idx) const
    {
        return m_input_weights.count(output_idx) > 0;
    }

    int64_t GetInputWeight(const GenericOutputID& output_idx) const
    {
        auto it = m_input_weights.find(output_idx);
        assert(it != m_input_weights.end());
        return it->second;
    }

private:
    std::set<GenericOutputID> setSelected;
    std::map<GenericOutputID, GenericOutput> m_external_outputs;
    //! Map of GenericOutputID's to the maximum weight for that input
    std::map<GenericOutputID, int64_t> m_input_weights;
};
} // namespace wallet

#endif // BITCOIN_WALLET_COINCONTROL_H
