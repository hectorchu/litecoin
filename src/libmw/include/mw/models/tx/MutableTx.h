#pragma once

#include <mw/models/tx/Transaction.h>
#include <mw/models/wallet/StealthAddress.h>
#include <wallet/recipient.h>
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

    std::optional<wallet::CRecipient> recipient{};
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
               recipient == other.recipient;
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

struct MutableKernel {
    std::optional<uint8_t> features;
    std::optional<CAmount> fee;
    std::optional<CAmount> pegin;
    std::vector<wallet::CRecipient> pegouts;
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

    // Updates the public fields of the MutableKernel to their finalized values.
    void Update(const mw::Kernel& finalized) noexcept
    {
        features = finalized.m_features;
        fee = finalized.m_fee;
        pegin = finalized.m_pegin;

        pegouts.clear();
        for (const PegOutCoin& pegout : finalized.m_pegouts) {
            pegouts.push_back(wallet::CRecipient{pegout.GetScriptPubKey(), pegout.GetAmount(), false});
        }

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
        for (const wallet::CRecipient& pegout : pegouts) {
            pegouts_.push_back(PegOutCoin{pegout.nAmount, pegout.GetScript()});
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

    void AddPegout(const wallet::CRecipient& pegout_recipient)
    {
        if (kernels.empty()) {
            kernels.push_back(mw::MutableKernel{});
        }

        kernels.front().pegouts.push_back(pegout_recipient);
    }

    std::vector<wallet::CRecipient> GetPegouts() const noexcept
    {
        std::vector<wallet::CRecipient> pegouts;
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
            for (const PegOutCoin& pegout_coin : kernel.pegouts) {
                pegout_coins.push_back(pegout_coin);
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
