#include <mw/wallet/sign.h>
#include <mw/common/Logger.h>
#include <mw/crypto/Blinds.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/OutputMask.h>

MW_NAMESPACE

static util::Result<Signature> InputSignature(const mw::Hash& output_id, const uint8_t features, const SecretKey& input_key, const SecretKey& output_key) noexcept
{
    try {
        PublicKey input_pubkey = PublicKey::From(input_key);
        PublicKey output_pubkey = PublicKey::From(output_key);

        // Hash keys (K_i||K_o)
        Hasher key_hasher;
        key_hasher << input_pubkey << output_pubkey;
        SecretKey key_hash = key_hasher.hash();

        // Calculate aggregated key k_agg = k_i + HASH(K_i||K_o) * k_o
        SecretKey sig_key = SecretKeys::From(output_key)
                                .Mul(key_hash)
                                .Add(input_key)
                                .Total();

        // Hash message
        Hasher msg_hasher;
        msg_hasher << features << output_id;
        mw::Hash msg_hash = msg_hasher.hash();

        return Schnorr::Sign(sig_key.data(), msg_hash);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

struct SignInputResult
{
    BlindingFactor input_blind{};
    SecretKey ephemeral_key{};
    SecretKey spend_key{};
};

static util::Result<SignInputResult> SignInput(MutableInput& input, const std::optional<mw::Coin>& coin) noexcept
{
    if (input.signature.has_value()) {
        return util::Error{Untranslated("Input is already signed")};
    }

    if (!input.raw_blind) {
        if (!coin.has_value() || !coin->blind.has_value()) {
            return util::Error{Untranslated("Input blinding factor missing")};
        }

        input.raw_blind = coin->blind.value();
    }

    if (!input.spend_key) {
        if (!coin.has_value() || !coin->spend_key.has_value()) {
            return util::Error{Untranslated("Input spend key missing")};
        }

        input.spend_key = coin->spend_key.value();
    }

    if (!input.amount) {
        if (!coin.has_value()) {
            return util::Error{Untranslated("Input amount missing")};
        }

        input.amount = coin->amount;
    }

    if (!input.ephemeral_key) {
        input.ephemeral_key = SecretKey::Random();
    }

    if (!input.features) {
        input.features = (uint8_t)Input::FeatureBit::STEALTH_KEY_FEATURE_BIT;
    }

    BlindingFactor input_blind = Pedersen::BlindSwitch(*input.raw_blind, *input.amount);
    input.commitment = Commitment::Blinded(input_blind, *input.amount);

    util::Result<Signature> input_signature_result = InputSignature(
        input.output_id,
        *input.features,
        *input.ephemeral_key,
        *input.spend_key
    );
    if (!input_signature_result) {
        return input_signature_result.error();
    }

    input.signature = input_signature_result.value();

    return SignInputResult{input_blind, *input.ephemeral_key, *input.spend_key};
}

struct SignOutputResult {
    BlindingFactor output_blind{};
    SecretKey ephemeral_key{};
    mw::Coin coin{};
};

static util::Result<SignOutputResult> SignOutput(MutableOutput& output) noexcept
{
    if (output.signature.has_value()) {
        return util::Error{Untranslated("Output is already signed")};
    }

    if (!output.amount || !output.address) {
        return util::Error{Untranslated("Output amount or address missing")};
    }

    BlindingFactor raw_blind;
    SecretKey ephemeral_key = SecretKey::Random();
    mw::Output finalized = mw::Output::Create(
        &raw_blind,
        ephemeral_key,
        *output.address,
        *output.amount);

    output.Update(finalized);

    // Populate Coin
    mw::Coin coin;
    coin.blind = raw_blind;
    coin.amount = *output.amount;
    coin.output_id = finalized.GetOutputID();
    coin.sender_key = ephemeral_key;
    coin.address = *output.address;

    BlindingFactor output_blind = Pedersen::BlindSwitch(raw_blind, *output.amount);
    return SignOutputResult{std::move(output_blind), std::move(ephemeral_key), std::move(coin)};
}

util::Result<mw::SignTxResult> SignTx(mw::MutableTx& tx, const std::map<mw::Hash, mw::Coin>& input_coins) noexcept
{
    SignTxResult result{};
    if (tx.IsNull()) {
        LOG_INFO("mw::MutableTx IsNull");
        return result;
    }

    Blinds kernel_offset{};
    Blinds stealth_offset{};

    // Sign outputs
    for (MutableOutput& output : tx.outputs) {
        if (output.signature.has_value()) {
            continue;
        }

        util::Result<SignOutputResult> sign_output_result = SignOutput(output);
        if (!sign_output_result) {
            return sign_output_result.error();
        }

        const SignOutputResult& signed_output = sign_output_result.value();
        kernel_offset.Add(signed_output.output_blind);
        stealth_offset.Add(signed_output.ephemeral_key);
        result.coins_by_output_id[*output.output_id] = signed_output.coin;
    }

    // Sign inputs
    for (MutableInput& input : tx.inputs) {
        if (input.signature.has_value()) {
            continue;
        }

        auto coin_iter = input_coins.find(input.output_id);

        std::optional<mw::Coin> input_coin = std::nullopt;
        if (coin_iter != input_coins.end()) {
            input_coin = coin_iter->second;
        }

        util::Result<SignInputResult> input_sign_result = SignInput(input, input_coin);
        if (!input_sign_result) {
            return input_sign_result.error();
        }

        const SignInputResult& signed_input = input_sign_result.value();
        kernel_offset.Sub(signed_input.input_blind);
        stealth_offset.Add(signed_input.ephemeral_key);
        stealth_offset.Sub(signed_input.spend_key);
    }

    if (tx.kernels.empty()) {
        tx.kernels.push_back(mw::MutableKernel{});
    }

    // Sign kernels
    for (MutableKernel& kernel : tx.kernels) {
        if (kernel.signature.has_value()) {
            continue;
        }

        SecretKey kernel_blind = SecretKey::Random();
        SecretKey stealth_blind = SecretKey::Random();

        mw::Kernel finalized = mw::Kernel::Create(
            kernel_blind,
            stealth_blind,
            kernel.fee,
            kernel.pegin,
            kernel.GetPegOuts(),
            kernel.lock_height
        );

        kernel.features = finalized.GetFeatures();
        kernel.stealth_excess = finalized.GetStealthExcess();
        kernel.excess = finalized.GetExcess();
        kernel.signature = finalized.GetSignature();

        kernel_offset.Sub(kernel_blind);
        stealth_offset.Sub(stealth_blind);
    }

    // MW: TODO - Update pegin scripts

    // MW: TODO - Offset calculations are wrong
    if (!tx.kernel_offset.IsZero()) {
        kernel_offset.Add(tx.kernel_offset);
    }
    tx.kernel_offset = kernel_offset.Total();

    if (!tx.stealth_offset.IsZero()) {
        stealth_offset.Add(tx.stealth_offset);
    }
    tx.stealth_offset = kernel_offset.Total();

    return result;
}

END_NAMESPACE
