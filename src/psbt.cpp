// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <mw/wallet/sign.h>
#include <policy/policy.h>
#include <util/check.h>
#include <util/strencodings.h>


PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx, uint32_t version) : m_version(version)
{
    if (version == 0) {
        this->tx = tx;
    }
    //inputs.resize(tx.vin.size() + tx.mweb_tx.inputs.size(), PSBTInput(GetVersion()));
    //outputs.resize(tx.vout.size() + tx.mweb_tx.outputs.size(), PSBTOutput(GetVersion()));
    //kernels.resize(tx.mweb_tx.kernels.size(), PSBTKernel());
    //SetupFromTx(tx);
}

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    // Prohibited to merge two PSBTs over different transactions
    if (GetUniqueID() != psbt.GetUniqueID()) {
        return false;
    }

    assert(*tx_version == psbt.tx_version);
    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psbt.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psbt.outputs[i]);
    }
    for (auto& xpub_pair : psbt.m_xpubs) {
        if (m_xpubs.count(xpub_pair.first) == 0) {
            m_xpubs[xpub_pair.first] = xpub_pair.second;
        } else {
            m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
        }
    }
    if (fallback_locktime == std::nullopt && psbt.fallback_locktime != std::nullopt) fallback_locktime = psbt.fallback_locktime;
    if (m_tx_modifiable != std::nullopt && psbt.m_tx_modifiable != std::nullopt) *m_tx_modifiable |= *psbt.m_tx_modifiable;
    if (m_tx_modifiable == std::nullopt && psbt.m_tx_modifiable != std::nullopt) m_tx_modifiable = psbt.m_tx_modifiable;
    unknown.insert(psbt.unknown.begin(), psbt.unknown.end());

    return true;
}

bool PartiallySignedTransaction::ComputeTimeLock(uint32_t& locktime) const
{
    std::optional<uint32_t> time_lock{0};
    std::optional<uint32_t> height_lock{0};
    for (const PSBTInput& input : inputs) {
        if (input.time_locktime != std::nullopt && input.height_locktime == std::nullopt) {
            height_lock.reset(); // Transaction can no longer have a height locktime
            if (time_lock == std::nullopt) {
                return false;
            }
        } else if (input.time_locktime == std::nullopt && input.height_locktime != std::nullopt) {
            time_lock.reset(); // Transaction can no longer have a time locktime
            if (height_lock == std::nullopt) {
                return false;
            }
        }
        if (input.time_locktime && time_lock != std::nullopt) {
            time_lock = std::max(time_lock, input.time_locktime);
        }
        if (input.height_locktime && height_lock != std::nullopt) {
            height_lock = std::max(height_lock, input.height_locktime);
        }
    }
    if (height_lock != std::nullopt && *height_lock > 0) {
        locktime = *height_lock;
        return true;
    }
    if (time_lock != std::nullopt && *time_lock > 0) {
        locktime = *time_lock;
        return true;
    }
    locktime = fallback_locktime.value_or(0);
    return true;
}

CMutableTransaction PartiallySignedTransaction::GetUnsignedTx() const
{
    if (tx != std::nullopt) {
        return *tx;
    }

    CMutableTransaction mtx;
    mtx.nVersion = *tx_version;
    bool locktime_success = ComputeTimeLock(mtx.nLockTime);
    assert(locktime_success);
    uint32_t max_sequence = CTxIn::SEQUENCE_FINAL;
    for (const PSBTInput& input : inputs) {
        if (input.mweb_output_id.has_value()) {
            mw::MutableInput mweb_input(*input.mweb_output_id);
            mweb_input.commitment = input.mweb_output_commit;
            mweb_input.output_pubkey = input.mweb_output_pubkey;
            mweb_input.amount = input.mweb_amount;
            // MW: TODO - mweb_input.spend_key =
            mweb_input.raw_blind = input.mweb_blind;
            if (input.mweb_features.has_value()) {
                mweb_input.features = input.mweb_features->first;
                mweb_input.extradata = input.mweb_features->second;
            }

            mweb_input.input_pubkey = input.mweb_input_pubkey;
            mweb_input.signature = input.mweb_sig;
            mtx.mweb_tx.inputs.push_back(std::move(mweb_input));
        } else {
            CTxIn txin;
            txin.prevout.hash = input.prev_txid;
            txin.prevout.n = *input.prev_out;
            txin.nSequence = input.sequence.value_or(max_sequence);
            mtx.vin.push_back(txin);
        }
    }

    for (const PSBTOutput& output : outputs) {
        // MW: TODO - Which fields should be populated at each stage of the PSBT?
        if (output.mweb_stealth_address.has_value() || output.mweb_commit.has_value()) {
            mw::MutableOutput mweb_output;
            mweb_output.commitment = output.mweb_commit;
            mweb_output.sender_pubkey = output.mweb_sender_pubkey;
            mweb_output.receiver_pubkey = output.mweb_output_pubkey;
            // MW: TODO - mweb_output.message =
            mweb_output.proof = output.mweb_rangeproof;
            mweb_output.signature = output.mweb_sig;
            mweb_output.amount = output.amount;
            mweb_output.address = output.mweb_stealth_address;
            mtx.mweb_tx.outputs.push_back(std::move(mweb_output));
        } else {
            CTxOut txout;
            txout.nValue = *output.amount;
            txout.scriptPubKey = *output.script;
            mtx.vout.push_back(txout);
        }
    }

    for (const PSBTKernel& kernel : kernels) {
        mw::MutableKernel mut_kernel;
        // MW: TODO - mut_kernel.features = Determine this from PSBTKernel fields
        mut_kernel.fee = kernel.fee;
        mut_kernel.pegin = kernel.pegin_amount;
        mut_kernel.SetPegOuts(kernel.pegouts);
        mut_kernel.lock_height = kernel.lock_height;
        mut_kernel.excess = kernel.commit;
        mut_kernel.stealth_excess = kernel.stealth_commit;
        mut_kernel.extradata = kernel.extra_data;
        mut_kernel.signature = kernel.sig;
        mtx.mweb_tx.kernels.push_back(std::move(mut_kernel));
    }

    mtx.mweb_tx.kernel_offset = mweb_tx_offset.value_or(BlindingFactor{});
    mtx.mweb_tx.stealth_offset = mweb_stealth_offset.value_or(BlindingFactor{});

    return mtx;
}

uint256 PartiallySignedTransaction::GetUniqueID() const
{
    if (tx != std::nullopt) {
        return tx->GetHash();
    }

    // Get the unsigned transaction
    CMutableTransaction mtx = GetUnsignedTx();
    // Compute the locktime
    bool locktime_success = ComputeTimeLock(mtx.nLockTime);
    assert(locktime_success);
    // Set the sequence numbers to 0
    for (CTxIn& txin : mtx.vin) {
        txin.nSequence = 0;
    }
    return mtx.GetHash();
}

bool PartiallySignedTransaction::AddInput(PSBTInput& psbtin)
{
    // Check required fields are present and this input is not a duplicate
    if (psbtin.prev_txid.IsNull() ||
        psbtin.prev_out == std::nullopt ||
        std::find_if(inputs.begin(), inputs.end(),
        [psbtin](const PSBTInput& psbt) {
            return psbt.prev_txid == psbtin.prev_txid && psbt.prev_out == psbtin.prev_out;
        }
    ) != inputs.end()) {
        return false;
    }

    if (tx != std::nullopt) {
        // This is a v0 psbt, so do the v0 AddInput
        CTxIn txin(COutPoint(psbtin.prev_txid, *psbtin.prev_out));
        if (std::find(tx->vin.begin(), tx->vin.end(), txin) != tx->vin.end()) {
            return false;
        }
        tx->vin.push_back(txin);
        psbtin.partial_sigs.clear();
        psbtin.final_script_sig.clear();
        psbtin.final_script_witness.SetNull();
        inputs.push_back(psbtin);
        return true;
    }

    // No global tx, must be PSBTv2.
    // Check inputs modifiable flag
    if (m_tx_modifiable == std::nullopt || !m_tx_modifiable->test(0)) {
        return false;
    }

    // Determine if we need to iterate the inputs.
    // For now, we only do this if the new input has a required time lock.
    // The BIP states that we should also do this if m_tx_modifiable's bit 2 is set
    // (Has SIGHASH_SINGLE flag) but since we are only adding inputs at the end of the vector,
    // we don't care about that.
    bool iterate_inputs = psbtin.time_locktime != std::nullopt || psbtin.height_locktime != std::nullopt;
    if (iterate_inputs) {
        uint32_t old_timelock;
        if (!ComputeTimeLock(old_timelock)) {
            return false;
        }

        std::optional<uint32_t> time_lock = psbtin.time_locktime;
        std::optional<uint32_t> height_lock = psbtin.height_locktime;
        bool has_sigs = false;
        for (const PSBTInput& input : inputs) {
            if (input.time_locktime != std::nullopt && input.height_locktime == std::nullopt) {
                height_lock.reset(); // Transaction can no longer have a height locktime
                if (time_lock == std::nullopt) {
                    return false;
                }
            } else if (input.time_locktime == std::nullopt && input.height_locktime != std::nullopt) {
                time_lock.reset(); // Transaction can no longer have a time locktime
                if (height_lock == std::nullopt) {
                    return false;
                }
            }
            if (input.time_locktime && time_lock != std::nullopt) {
                time_lock = std::max(time_lock, input.time_locktime);
            }
            if (input.height_locktime && height_lock != std::nullopt) {
                height_lock = std::max(height_lock, input.height_locktime);
            }
            if (!input.partial_sigs.empty()) {
                has_sigs = true;
            }
        }
        uint32_t new_timelock = fallback_locktime.value_or(0);
        if (height_lock != std::nullopt && *height_lock > 0) {
            new_timelock = *height_lock;
        } else if (time_lock != std::nullopt && *time_lock > 0) {
            new_timelock = *time_lock;
        }
        if (has_sigs && old_timelock != new_timelock) {
            return false;
        }
    }

    // Add the input to the end
    inputs.push_back(psbtin);
    return true;
}

bool PartiallySignedTransaction::AddOutput(const PSBTOutput& psbtout)
{
    if (psbtout.amount == std::nullopt || !psbtout.script.has_value()) {
        return false;
    }

    if (tx != std::nullopt) {
        // This is a v0 psbt, do the v0 AddOutput
        CTxOut txout(*psbtout.amount, *psbtout.script);
        tx->vout.push_back(txout);
        outputs.push_back(psbtout);
        return true;
    }

    // No global tx, must be PSBTv2
    // Check outputs are modifiable
    if (m_tx_modifiable == std::nullopt || !m_tx_modifiable->test(1)) {
        return false;
    }
    outputs.push_back(psbtout);

    return true;
}

bool PSBTInput::GetUTXO(CTxOut& utxo) const
{
    if (non_witness_utxo) {
        if (prev_out >= non_witness_utxo->vout.size()) {
            return false;
        }
        if (non_witness_utxo->GetHash() != prev_txid) {
            return false;
        }
        utxo = non_witness_utxo->vout[*prev_out];
    } else if (!witness_utxo.IsNull()) {
        utxo = witness_utxo;
    } else {
        return false;
    }
    return true;
}


COutPoint PSBTInput::GetOutPoint() const
{
    return COutPoint(prev_txid, *prev_out);
}

bool PartiallySignedTransaction::IsComplete() const noexcept
{
    bool complete = true;
    for (const PSBTInput& input : inputs) {
        complete &= PSBTInputSigned(input);
    }

    for (const PSBTKernel& kernel : kernels) {
        complete &= kernel.sig.has_value();
    }

    for (const PSBTOutput& output : outputs) {
        // MW: TODO - Check if MWEB, and if so, check if signed
    }

    return complete;
}

bool PSBTInput::IsNull() const
{
    return !non_witness_utxo && witness_utxo.IsNull() && partial_sigs.empty() && unknown.empty() && hd_keypaths.empty() && redeem_script.empty() && witness_script.empty() && !mweb_output_id.has_value();
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_key_sig.empty()) {
        sigdata.taproot_key_path_sig = m_tap_key_sig;
    }
    for (const auto& [pubkey_leaf, sig] : m_tap_script_sigs) {
        sigdata.taproot_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!m_tap_internal_key.IsNull()) {
        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
    }
    if (!m_tap_merkle_root.IsNull()) {
        sigdata.tr_spenddata.merkle_root = m_tap_merkle_root;
    }
    for (const auto& [leaf_script, control_block] : m_tap_scripts) {
        sigdata.tr_spenddata.scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.taproot_key_path_sig.empty()) {
        m_tap_key_sig = sigdata.taproot_key_path_sig;
    }
    for (const auto& [pubkey_leaf, sig] : sigdata.taproot_script_sigs) {
        m_tap_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (!sigdata.tr_spenddata.merkle_root.IsNull()) {
        m_tap_merkle_root = sigdata.tr_spenddata.merkle_root;
    }
    for (const auto& [leaf_script, control_block] : sigdata.tr_spenddata.scripts) {
        m_tap_scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
}

void PSBTInput::Merge(const PSBTInput& input)
{
    assert(prev_txid == input.prev_txid);
    assert(*prev_out == *input.prev_out);

    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    ripemd160_preimages.insert(input.ripemd160_preimages.begin(), input.ripemd160_preimages.end());
    sha256_preimages.insert(input.sha256_preimages.begin(), input.sha256_preimages.end());
    hash160_preimages.insert(input.hash160_preimages.begin(), input.hash160_preimages.end());
    hash256_preimages.insert(input.hash256_preimages.begin(), input.hash256_preimages.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());
    m_tap_script_sigs.insert(input.m_tap_script_sigs.begin(), input.m_tap_script_sigs.end());
    m_tap_scripts.insert(input.m_tap_scripts.begin(), input.m_tap_scripts.end());
    m_tap_bip32_paths.insert(input.m_tap_bip32_paths.begin(), input.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;
    if (m_tap_key_sig.empty() && !input.m_tap_key_sig.empty()) m_tap_key_sig = input.m_tap_key_sig;
    if (m_tap_internal_key.IsNull() && !input.m_tap_internal_key.IsNull()) m_tap_internal_key = input.m_tap_internal_key;
    if (m_tap_merkle_root.IsNull() && !input.m_tap_merkle_root.IsNull()) m_tap_merkle_root = input.m_tap_merkle_root;
    if (sequence == std::nullopt && input.sequence != std::nullopt) sequence = input.sequence;
    if (time_locktime == std::nullopt && input.time_locktime != std::nullopt) time_locktime = input.time_locktime;
    if (height_locktime == std::nullopt && input.height_locktime != std::nullopt) height_locktime = input.height_locktime;

    // MW: TODO - Merge MWEB fields
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_tree.empty() && m_tap_internal_key.IsFullyValid()) {
        TaprootBuilder builder;
        for (const auto& [depth, leaf_ver, script] : m_tap_tree) {
            builder.Add((int)depth, script, (int)leaf_ver, /*track=*/true);
        }
        assert(builder.IsComplete());
        builder.Finalize(m_tap_internal_key);
        TaprootSpendData spenddata = builder.GetSpendData();

        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
        sigdata.tr_spenddata.Merge(spenddata);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
    }
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (sigdata.tr_builder.has_value() && sigdata.tr_builder->HasScripts()) {
        m_tap_tree = sigdata.tr_builder->GetTreeTuples();
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
}

bool PSBTOutput::IsNull() const
{
    return redeem_script.empty() && witness_script.empty() && hd_keypaths.empty() && unknown.empty(); // MW: TODO - Check MWEB fields
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    assert(*amount == *output.amount);
    assert(*script == *output.script);

    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());
    m_tap_bip32_paths.insert(output.m_tap_bip32_paths.begin(), output.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;
    if (m_tap_internal_key.IsNull() && !output.m_tap_internal_key.IsNull()) m_tap_internal_key = output.m_tap_internal_key;
    if (m_tap_tree.empty() && !output.m_tap_tree.empty()) m_tap_tree = output.m_tap_tree;

    // MW: TODO - Merge MWEB fields
}

bool PSBTInputSigned(const PSBTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull() || input.mweb_sig.has_value();
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    CTxOut utxo;
    assert(psbt.inputs.size() >= input_index);
    const PSBTInput& input = psbt.inputs[input_index];

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = input.GetOutPoint();
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else {
        return false;
    }

    const CMutableTransaction tx = psbt.GetUnsignedTx();
    if (txdata) {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL});
    } else {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, MissingDataBehavior::FAIL});
    }
}

size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}

void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index)
{
    CMutableTransaction tx = psbt.GetUnsignedTx();
    PSBTOutput& psbt_out = psbt.outputs.at(index);
    if (psbt_out.mweb_stealth_address.has_value() || psbt_out.mweb_sig.has_value()) {
        return; // MW: TODO - Sign MWEB outputs?
    }

    const CTxOut& out = tx.vout.at(index);

    // Fill a SignatureData with output info
    SignatureData sigdata;
    psbt_out.FillSignatureData(sigdata);

    // Construct a would-be spend of this output, to update sigdata with.
    // Note that ProduceSignature is used to fill in metadata (not actual signatures),
    // so provider does not need to provide any private keys (it can be a HidingSigningProvider).
    MutableTransactionSignatureCreator creator(tx, /*input_idx=*/0, out.nValue, SIGHASH_ALL);
    ProduceSignature(provider, creator, out.scriptPubKey, sigdata);

    // Put redeem_script, witness_script, key paths, into PSBTOutput.
    psbt_out.FromSignatureData(sigdata);
}

PrecomputedTransactionData PrecomputePSBTData(const PartiallySignedTransaction& psbt)
{
    const CMutableTransaction& tx = psbt.GetUnsignedTx();
    bool have_all_spent_outputs = true;
    std::vector<CTxOut> utxos;
    for (const PSBTInput& input : psbt.inputs) {
        if (!input.GetUTXO(utxos.emplace_back())) have_all_spent_outputs = false;
    }
    // MW: TODO - Check MWEB inputs
    PrecomputedTransactionData txdata;
    if (have_all_spent_outputs) {
        txdata.Init(tx, std::move(utxos), true);
    } else {
        txdata.Init(tx, {}, true);
    }
    return txdata;
}

bool SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, int sighash,  SignatureData* out_sigdata, bool finalize)
{
    PSBTInput& input = psbt.inputs.at(index);
    const CMutableTransaction& tx = psbt.GetUnsignedTx();

    if (PSBTInputSignedAndVerified(psbt, index, txdata)) {
        return true;
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO
    bool require_witness_sig = false;
    CTxOut utxo;

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = input.GetOutPoint();
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return false;
    }

    sigdata.witness = false;
    bool sig_complete;
    if (txdata == nullptr) {
        sig_complete = ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, utxo.scriptPubKey, sigdata);
    } else {
        MutableTransactionSignatureCreator creator(tx, index, utxo.nValue, txdata, sighash);
        sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata);
    }
    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return false;

    // If we are not finalizing, set sigdata.complete to false to not set the scriptWitness
    if (!finalize && sigdata.complete) sigdata.complete = false;

    input.FromSignatureData(sigdata);

    // If we have a witness signature, put a witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        // We can remove the non_witness_utxo if and only if there are no non-segwit or segwit v0
        // inputs in this transaction. Since this requires inspecting the entire transaction, this
        // is something for the caller to deal with (i.e. FillPSBT).
    }

    // Fill in the missing info
    if (out_sigdata) {
        out_sigdata->missing_pubkeys = sigdata.missing_pubkeys;
        out_sigdata->missing_sigs = sigdata.missing_sigs;
        out_sigdata->missing_redeem_script = sigdata.missing_redeem_script;
        out_sigdata->missing_witness_script = sigdata.missing_witness_script;
    }

    return sig_complete;
}

void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbtx, const int& sighash_type)
{
    // Only drop non_witness_utxos if sighash_type != SIGHASH_ANYONECANPAY
    if ((sighash_type & 0x80) != SIGHASH_ANYONECANPAY) {
        // Figure out if any non_witness_utxos should be dropped
        std::vector<unsigned int> to_drop;
        for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
            const auto& input = psbtx.inputs.at(i);
            int wit_ver;
            std::vector<unsigned char> wit_prog;
            if (input.witness_utxo.IsNull() || !input.witness_utxo.scriptPubKey.IsWitnessProgram(wit_ver, wit_prog)) {
                // There's a non-segwit input or Segwit v0, so we cannot drop any witness_utxos
                to_drop.clear();
                break;
            }
            if (wit_ver == 0) {
                // Segwit v0, so we cannot drop any non_witness_utxos
                to_drop.clear();
                break;
            }
            if (input.non_witness_utxo) {
                to_drop.push_back(i);
            }
        }

        // Drop the non_witness_utxos that we can drop
        for (unsigned int i : to_drop) {
            psbtx.inputs.at(i).non_witness_utxo = nullptr;
        }
    }
}

util::Result<CMutableTransaction> FinalizePSBT(PartiallySignedTransaction& psbtx)
{
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
	bool complete = true;
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        complete &= SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, SIGHASH_ALL, nullptr, true);
    }

    // Finalize MWEB outputs and kernels
    CMutableTransaction mtx = psbtx.GetUnsignedTx();
    util::Result<mw::SignTxResult> mweb_result = mw::SignTx(mtx.mweb_tx, {});
    if (mweb_result) {
        size_t idx = 0;
        for (PSBTInput& psbt_input : psbtx.inputs) {
            if (!psbt_input.IsMWEB()) {
                continue;
            }

            const mw::MutableInput& input = mtx.mweb_tx.inputs[idx++];
            psbt_input.mweb_output_commit = input.commitment;
            psbt_input.mweb_output_pubkey = input.output_pubkey;
            psbt_input.mweb_input_pubkey = input.input_pubkey;
            // MW: TODO - psbt_input.mweb_features
            psbt_input.mweb_sig = input.signature;
            // MW: TODO - psbt_input.mweb_address_index
            psbt_input.mweb_amount = input.amount;
            // MW: TODO - psbt_input.mweb_shared_secret
            psbt_input.mweb_blind = input.raw_blind;
            // MW: TODO - psbt_input.mweb_utxo
        }

        idx = 0;
        for (PSBTOutput& psbt_output : psbtx.outputs) {
            if (!psbt_output.IsMWEB()) {
                continue;
            }

            const mw::MutableOutput& output = mtx.mweb_tx.outputs[idx++];
            psbt_output.mweb_commit = output.commitment;
            // MW: TODO - psbt_output.mweb_features
            psbt_output.mweb_sender_pubkey = output.sender_pubkey;
            psbt_output.mweb_output_pubkey = output.receiver_pubkey;
            psbt_output.mweb_key_exchange_pubkey = output.message->key_exchange_pubkey;
            psbt_output.mweb_view_tag = output.message->view_tag;
            psbt_output.mweb_enc_value = output.message->masked_value;
            psbt_output.mweb_enc_nonce = output.message->masked_nonce;
            psbt_output.mweb_rangeproof = output.proof;
            psbt_output.mweb_sig = output.signature;
        }

        if (psbtx.kernels.size() < mtx.mweb_tx.kernels.size()) {
            psbtx.kernels.resize(mtx.mweb_tx.kernels.size());
        }

        idx = 0;
        for (const mw::MutableKernel& kernel : mtx.mweb_tx.kernels) {
            PSBTKernel& psbt_kernel = psbtx.kernels[idx++];
            psbt_kernel.commit = kernel.excess;
            psbt_kernel.stealth_commit = kernel.stealth_excess;
            psbt_kernel.fee = kernel.fee;
            psbt_kernel.pegin_amount = kernel.pegin;
            psbt_kernel.pegouts = kernel.GetPegOuts();
            psbt_kernel.lock_height = kernel.lock_height;
            psbt_kernel.extra_data = kernel.extradata;
            psbt_kernel.sig = kernel.signature;
        }

        for (const PegInCoin& pegin : mtx.mweb_tx.GetPegIns()) {
            for (size_t i = 0; i < mtx.vout.size(); i++) {
                CTxOut& out = mtx.vout[i];
                mw::Hash pegin_hash;
                if (out.scriptPubKey.IsMWEBPegin(&pegin_hash)) { // MW: TODO - && pegin_hash.IsZero()) {
                    out.scriptPubKey = GetScriptForPegin(pegin.GetKernelID());
                    out.nValue = pegin.GetAmount();

                    PSBTOutput& psbt_output = psbtx.outputs[i];
                    psbt_output.amount = out.nValue;
                    psbt_output.script = out.scriptPubKey;
                    break;
                }
            }
        }

        psbtx.mweb_tx_offset = mtx.mweb_tx.kernel_offset;
        psbtx.mweb_stealth_offset = mtx.mweb_tx.stealth_offset;
    }

    if (!psbtx.IsComplete()) {
        return util::Error{};
    }

    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        mtx.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        mtx.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
    }

    return mtx;
}

TransactionError CombinePSBTs(PartiallySignedTransaction& out, const std::vector<PartiallySignedTransaction>& psbtxs)
{
    out = psbtxs[0]; // Copy the first one

    // Merge
    for (auto it = std::next(psbtxs.begin()); it != psbtxs.end(); ++it) {
        if (!out.Merge(*it)) {
            return TransactionError::PSBT_MISMATCH;
        }
    }
    return TransactionError::OK;
}

std::string PSBTRoleName(PSBTRole role) {
    switch (role) {
    case PSBTRole::CREATOR: return "creator";
    case PSBTRole::UPDATER: return "updater";
    case PSBTRole::SIGNER: return "signer";
    case PSBTRole::FINALIZER: return "finalizer";
    case PSBTRole::EXTRACTOR: return "extractor";
        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

bool DecodeBase64PSBT(PartiallySignedTransaction& psbt, const std::string& base64_tx, std::string& error)
{
    auto tx_data = DecodeBase64(base64_tx);
    if (!tx_data) {
        error = "invalid base64";
        return false;
    }
    return DecodeRawPSBT(psbt, MakeByteSpan(*tx_data), error);
}

bool DecodeRawPSBT(PartiallySignedTransaction& psbt, Span<const std::byte> tx_data, std::string& error)
{
    CDataStream ss_data(tx_data, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ss_data >> psbt;
        if (!ss_data.empty()) {
            error = "extra data after PSBT";
            return false;
        }
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return true;
}

uint32_t PartiallySignedTransaction::GetVersion() const
{
    if (m_version != std::nullopt) {
        return *m_version;
    }
    return 0;
}

#include <logging.h>
void PartiallySignedTransaction::SetupFromTx(const CMutableTransaction& tx)
{
    LogPrintf("SetupFromTx() - BEGIN\n");
    tx_version = tx.nVersion;
    fallback_locktime = tx.nLockTime;

    size_t num_inputs = tx.vin.size() + tx.mweb_tx.inputs.size();
    size_t num_outputs = tx.vout.size() + tx.mweb_tx.outputs.size();
    size_t num_kernels = tx.mweb_tx.kernels.size();
    uint32_t version = GetVersion();
    LogPrintf("Inputs(%llu, %llu, %llu)\n", tx.vin.size(), tx.mweb_tx.inputs.size(), num_inputs);
    LogPrintf("Outputs(%llu, %llu, %llu)\n", tx.vout.size(), tx.mweb_tx.outputs.size(), num_outputs);
    LogPrintf("Kernels(%llu)\n", num_kernels);

    LogPrintf("SetupFromTx() - INPUTS\n");
    uint32_t i = 0;
    for (i = 0; i < tx.vin.size(); ++i) {
        PSBTInput input(GetVersion());
        const CTxIn& txin = tx.vin.at(i);

        input.prev_txid = txin.prevout.hash;
        input.prev_out = txin.prevout.n;
        input.sequence = txin.nSequence;
        inputs.push_back(std::move(input));
    }

    for (uint32_t j = 0; j < tx.mweb_tx.inputs.size(); j++) {
        PSBTInput input(GetVersion());
        const mw::MutableInput& mweb_input = tx.mweb_tx.inputs[j];

        input.mweb_output_id = mweb_input.output_id;
        // MW: TODO - input.mweb_features = mweb_input.features;
        input.mweb_output_commit = mweb_input.commitment;
        input.mweb_input_pubkey = mweb_input.input_pubkey;
        input.mweb_output_pubkey = mweb_input.output_pubkey;
        input.mweb_sig = mweb_input.signature;
        input.mweb_amount = mweb_input.amount;
        // MW: TODO - Finish populating this
        inputs.push_back(std::move(input));
    }

    LogPrintf("SetupFromTx() - Outputs\n");
    for (i = 0; i < tx.vout.size(); ++i) {
        PSBTOutput output(GetVersion());
        const CTxOut& txout = tx.vout.at(i);

        output.amount = txout.nValue;
        output.script = txout.scriptPubKey;
        outputs.push_back(std::move(output));
    }

    for (uint32_t j = 0; j < tx.mweb_tx.outputs.size(); j++) {
        PSBTOutput output(GetVersion());
        const mw::MutableOutput& mweb_output = tx.mweb_tx.outputs[j];

        // MW: TODO - Finish populating this
        output.amount = mweb_output.amount;
        output.mweb_stealth_address = mweb_output.address;
        output.mweb_commit = mweb_output.commitment;
        outputs.push_back(std::move(output));
    }

    
    for (const mw::MutableKernel& mweb_kernel : tx.mweb_tx.kernels) {
        PSBTKernel kernel;
        kernel.fee = mweb_kernel.fee;
        kernel.pegin_amount = mweb_kernel.pegin;
        kernel.pegouts = mweb_kernel.GetPegOuts();
        // MW: TODO - Finish populating this
        kernels.push_back(std::move(kernel));
    }
    LogPrintf("SetupFromTx() - END\n");

    // MW: TODO - Kernels
}

void PartiallySignedTransaction::CacheUnsignedTxPieces()
{
    // To make things easier, we split up the global unsigned transaction
    // and use the PSBTv2 fields for PSBTv0.
    if (tx != std::nullopt) {
        SetupFromTx(*tx);
    }
}
