#pragma once

#include <mw/models/tx/Transaction.h>
#include <mw/models/wallet/StealthAddress.h>
#include <optional>

MW_NAMESPACE

struct MutableInput {
    // UTXO: public info
    mw::Hash output_id;
    std::optional<Commitment> commitment;
    std::optional<PublicKey> output_pubkey;

    // UTXO: secrets
    std::optional<CAmount> amount; //! The amount being spent.
    std::optional<SecretKey> spend_key; //! Secret key needed to spend the UTXO.
    std::optional<BlindingFactor> raw_blind; //! Pre-switch blinding factor.

    // Input: public info
    std::optional<uint8_t> features;
    std::optional<PublicKey> input_pubkey;
    std::vector<uint8_t> extradata;
    std::optional<Signature> signature;

    // Input: secrets
    std::optional<SecretKey> ephemeral_key; //! Secret key of the input_pubkey. Generated when signing.

    MutableInput(mw::Hash output_id_)
        : output_id(std::move(output_id_)) { }

    // Builds a MutableInput with the public UTXO fields populated for spending the provided output.
    static MutableInput FromOutput(const mw::Output& output)
    {
        MutableInput input(output.GetOutputID());
        input.commitment = output.GetCommitment();
        input.output_pubkey = output.GetReceiverPubKey();
        return input;
    }

    bool operator==(const MutableInput& other) const noexcept
    {
        return output_id == other.output_id &&
               features == other.features &&
               commitment == other.commitment &&
               input_pubkey == other.input_pubkey &&
               output_pubkey == other.output_pubkey &&
               extradata == other.extradata &&
               signature == other.signature &&
               amount == other.amount &&
               spend_key == other.spend_key &&
               raw_blind == other.raw_blind &&
               ephemeral_key == other.ephemeral_key;
    }

    // A finalized MutableInput is one that has all public fields populated
    bool IsFinal() const noexcept
    {
        return commitment.has_value() &&
            output_pubkey.has_value() &&
            features.has_value() &&
            input_pubkey.has_value() &&
            signature.has_value();
    }

    // Returns the finalized (signed) mw::Input. Will be nullopt if input is not final.
    std::optional<Input> Finalized() const noexcept
    {
        if (IsFinal()) {
            return Input(*features, output_id, *commitment, *input_pubkey, *output_pubkey, *signature); // MW: TODO - Include extradata
        }

        return std::nullopt;
    }

    // Updates the public fields of the MutableInput to their finalized values.
    void Update(const Input& finalized) noexcept
    {
        features = finalized.GetFeatures();
        output_id = finalized.GetOutputID();
        commitment = finalized.GetCommitment();
        input_pubkey = finalized.GetInputPubKey();
        output_pubkey = finalized.GetOutputPubKey();
        extradata = finalized.GetExtraData();
        signature = finalized.GetSignature();
    }
};

struct MutableOutput {
    // MW: TODO: Could probably just be an optional Output and optional Recipient
    std::optional<mw::Hash> output_id{};
    std::optional<Commitment> commitment{};
    std::optional<PublicKey> sender_pubkey{};
    std::optional<PublicKey> receiver_pubkey{};
    std::optional<mw::OutputMessage> message{};
    std::optional<RangeProof::CPtr> proof{};
    std::optional<Signature> signature{};

    std::optional<CAmount> amount{};
    std::optional<StealthAddress> address{};
    std::optional<bool> subtract_fee_from_amount{};
    // MW: TODO - Include generated secrets

    bool operator==(const MutableOutput& other) const noexcept
    {
        return output_id == other.output_id &&
               commitment == other.commitment &&
               sender_pubkey == other.sender_pubkey &&
               receiver_pubkey == other.receiver_pubkey &&
               message == other.message &&
               proof == other.proof &&
               signature == other.signature &&
               amount == other.amount &&
               address == other.address &&
               subtract_fee_from_amount == other.subtract_fee_from_amount;
    }

    // A finalized MutableOutput is one that has all public fields populated
    bool IsFinal() const noexcept
    {
        return output_id.has_value() &&
               commitment.has_value() &&
               sender_pubkey.has_value() &&
               receiver_pubkey.has_value() &&
               message.has_value() &&
               proof.has_value() &&
               signature.has_value();
    }

    // Returns the finalized (signed) mw::Output. Will be nullopt if output is not final.
    std::optional<mw::Output> Finalized() const noexcept
    {
        if (IsFinal()) {
            return mw::Output(*commitment, *sender_pubkey, *receiver_pubkey, *message, *proof, *signature);
        }

        return std::nullopt;
    }

    // Updates the public fields of the MutableOutput to their finalized values.
    void Update(const mw::Output& finalized) noexcept
    {
        output_id = finalized.GetOutputID();
        commitment = finalized.GetCommitment();
        sender_pubkey = finalized.GetSenderPubKey();
        receiver_pubkey = finalized.GetReceiverPubKey();
        message = finalized.GetOutputMessage();
        proof = finalized.GetRangeProof();
        signature = finalized.GetSignature();
    }
};

struct PegOutRecipient
{
    CScript script;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;

    bool operator==(const PegOutRecipient& rhs) const noexcept
    {
        return script == rhs.script && nAmount == rhs.nAmount && fSubtractFeeFromAmount == rhs.fSubtractFeeFromAmount;
    }
};

struct MutableKernel {
    std::optional<uint8_t> features;
    std::optional<CAmount> fee;
    std::optional<CAmount> pegin;
    std::vector<PegOutRecipient> pegouts;
    std::optional<int32_t> lock_height;
    std::optional<PublicKey> stealth_excess;
    std::vector<uint8_t> extradata;
    std::optional<Commitment> excess;
    std::optional<Signature> signature;

    // MW: TODO - Should include secret keys

    bool operator==(const MutableKernel& other) const noexcept
    {
        return features == other.features &&
               fee == other.fee &&
               pegin == other.pegin &&
               pegouts == other.pegouts &&
               lock_height == other.lock_height &&
               stealth_excess == other.stealth_excess &&
               extradata == other.extradata &&
               excess == other.excess &&
               signature == other.signature;
    }

    // A finalized MutableKernel is one that has all public fields populated
    bool IsFinal() const noexcept
    {
        // MW: FUTURE - Based on features, could check if pegin, pegouts, lock_height, stealth_excess, and extradata should be populated
        return features.has_value() &&
               excess.has_value() &&
               signature.has_value();
    }

    // Returns the finalized (signed) mw::Kernel. Will be nullopt if kernel is not final.
    std::optional<mw::Kernel> Finalized() const noexcept
    {
        if (IsFinal()) {
            return mw::Kernel(*features, fee, pegin, GetPegOuts(), lock_height, stealth_excess, extradata, *excess, *signature);
        }

        return std::nullopt;
    }

    void SetPegOuts(const std::vector<PegOutCoin>& pegout_coins) {
        pegouts.clear();
        for (const PegOutCoin& pegout_coin : pegout_coins) {
            pegouts.push_back(PegOutRecipient{pegout_coin.GetScriptPubKey(), pegout_coin.GetAmount(), false});
        }
    }

    // Updates the public fields of the MutableKernel to their finalized values.
    void Update(const mw::Kernel& finalized) noexcept
    {
        features = finalized.m_features;
        fee = finalized.m_fee;
        pegin = finalized.m_pegin;
        SetPegOuts(finalized.m_pegouts);
        lock_height = finalized.m_lockHeight;
        stealth_excess = finalized.m_stealthExcess;
        extradata = finalized.m_extraData;
        excess = finalized.m_excess;
        signature = finalized.m_signature;
    }

    // Calculates the kernel ID. Will be nullopt if kernel is not final
    std::optional<mw::Hash> GetKernelID() const noexcept
    {
        std::optional<mw::Kernel> kernel = Finalized();
        if (kernel.has_value()) {
            return kernel->GetKernelID();
        }

        return std::nullopt;
    }

    std::vector<PegOutCoin> GetPegOuts() const noexcept
    {
        std::vector<PegOutCoin> pegouts_;
        for (const PegOutRecipient& pegout : pegouts) {
            pegouts_.push_back(PegOutCoin{pegout.nAmount, pegout.script});
        }
        return pegouts_;
    }
};

struct MutableTx : public Traits::ISerializable
{
    BlindingFactor kernel_offset;
    BlindingFactor stealth_offset;
    std::vector<MutableInput> inputs;
    std::vector<MutableOutput> outputs;
    std::vector<MutableKernel> kernels; // MW: TODO - Just store fee, pegins, and pegouts here, rather than having mutable kernels?

    void SetFee(const CAmount fee) noexcept
    {
        if (kernels.empty()) {
            kernels.push_back(mw::MutableKernel{});
        }

        kernels.front().fee = fee;
    }

    std::optional<CAmount> GetPeginAmount() const noexcept
    {
        if (kernels.empty()) {
            return std::nullopt;
        }

        return kernels.front().pegin;
    }

    void SetPeginAmount(const CAmount pegin_amount)
    {
        if (kernels.empty()) {
            kernels.push_back(mw::MutableKernel{});
        }

        kernels.front().pegin = pegin_amount;
    }

    void AddPegout(const PegOutRecipient& pegout_recipient)
    {
        if (kernels.empty()) {
            kernels.push_back(mw::MutableKernel{});
        }

        kernels.front().pegouts.push_back(pegout_recipient);
    }

    void AddPegout(CScript script, const CAmount amount, bool subtract_fee_from_amount)
    {
        AddPegout(PegOutRecipient{std::move(script), amount, subtract_fee_from_amount});
    }

    std::vector<PegOutRecipient> GetPegouts() const noexcept
    {
        std::vector<PegOutRecipient> pegouts;
        for (const MutableKernel& kernel : kernels) {
            pegouts.insert(pegouts.end(), kernel.pegouts.begin(), kernel.pegouts.end());
        }

        return pegouts;
    }

    void Apply(const mw::Transaction& tx)
    {
        kernel_offset = tx.GetKernelOffset();
        stealth_offset = tx.GetStealthOffset();
        // MW: TODO - Finish this - Need maps for input, output, and kernel ordering
    }

    bool operator==(const MutableTx& tx) const noexcept
    {
        return kernel_offset == tx.kernel_offset && stealth_offset == tx.stealth_offset && inputs == tx.inputs && outputs == tx.outputs && kernels == tx.kernels;
    }

    bool IsNull() const noexcept
    {
        return kernel_offset.IsZero() && stealth_offset.IsZero() && inputs.empty() && outputs.empty() && kernels.empty();
    }

    void SetNull() noexcept
    {
        kernel_offset = BlindingFactor{};
        stealth_offset = BlindingFactor{};
        inputs.clear();
        outputs.clear();
        kernels.clear();
    }

    bool IsFinal() const noexcept
    {
        if (kernels.empty()) {
            LOG_INFO("Not final - kernels empty");
            return false;
        }

        for (const mw::MutableInput& input : inputs) {
            if (!input.IsFinal()) {
                LOG_INFO("Not final - Non-final input");
                return false;
            }
        }

        for (const mw::MutableOutput& output : outputs) {
            if (!output.IsFinal()) {
                LOG_INFO("Not final - Non-final output");
                return false;
            }
        }

        for (const mw::MutableKernel& kernel : kernels) {
            if (!kernel.IsFinal()) {
                LOG_INFO("Not final - Non-final kernel");
                return false;
            }
        }

        return true;
    }

    std::optional<mw::Transaction::CPtr> Finalized() const noexcept
    {
        if (IsNull() || !IsFinal()) {
            return std::nullopt;
        }

        std::vector<Input> final_inputs;
        for (const mw::MutableInput& input : inputs) {
            final_inputs.push_back(*input.Finalized());
        }

        std::vector<Output> final_outputs;
        for (const mw::MutableOutput& output : outputs) {
            final_outputs.push_back(*output.Finalized());
        }

        std::vector<Kernel> final_kernels;
        for (const mw::MutableKernel& kernel : kernels) {
            final_kernels.push_back(*kernel.Finalized());
        }

        return mw::Transaction::Create(
            kernel_offset,
            stealth_offset,
            std::move(final_inputs),
            std::move(final_outputs),
            std::move(final_kernels)
        );
    }

    std::vector<PegInCoin> GetPegIns() const noexcept
    {
        std::vector<PegInCoin> pegins;
        for (const MutableKernel& kernel : kernels) {
            if (kernel.pegin.has_value()) {
                mw::Hash kernel_id = kernel.GetKernelID().value_or(mw::Hash{});
                pegins.push_back(PegInCoin{kernel.pegin.value(), kernel_id});
            }
        }

        return pegins;
    }

    std::vector<PegOutCoin> GetPegOutCoins() const noexcept
    {
        std::vector<PegOutCoin> pegout_coins;
        for (const MutableKernel& kernel : kernels) {
            for (const PegOutRecipient& pegout : kernel.pegouts) {
                pegout_coins.push_back(PegOutCoin{pegout.nAmount, pegout.script});
            }
        }

        return pegout_coins;
    }

    uint32_t GetMWEBWeight() const noexcept
    {
        if (inputs.empty() && outputs.empty() && kernels.empty()) {
            return 0;
        }

        return (mw::STANDARD_OUTPUT_WEIGHT * outputs.size()) + Weight::CalcKernelWeight(true, GetPegOutCoins());
    }

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(MutableTx, obj)
    {
        READWRITE(obj.kernel_offset, obj.stealth_offset);// MW: TODO - Finish serialization for : obj.inputs, obj.outputs, obj.kernels);
    }
};

END_NAMESPACE
