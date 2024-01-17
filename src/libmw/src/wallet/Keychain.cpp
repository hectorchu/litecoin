#include <mw/wallet/Keychain.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/OutputMask.h>
#include <wallet/scriptpubkeyman.h>
#include <key_io.h>

MW_NAMESPACE

bool Keychain::RewindOutput(const mw::Output& output, mw::Coin& coin) const
{
    if (!m_spk_man) {
        return false;
    }
    if (!output.HasStandardFields()) {
        return false;
    }

    assert(!GetScanSecret().IsNull());
    PublicKey shared_secret = output.Ke().Mul(GetScanSecret());
    uint8_t view_tag = Hashed(EHashTag::TAG, shared_secret)[0];
    if (view_tag != output.GetViewTag()) {
        return false;
    }

    SecretKey t = Hashed(EHashTag::DERIVE, shared_secret);
    PublicKey B_i = output.Ko().Div(Hashed(EHashTag::OUT_KEY, t));

    // Check if B_i belongs to wallet
    StealthAddress address(B_i.Mul(m_scanSecret), B_i);
    auto pMetadata = m_spk_man->GetMetadata(address);
    if (!pMetadata) {
        return false;
    }

    // Calc blinding factor and unmask nonce and amount.
    OutputMask mask = OutputMask::FromShared(t);
    uint64_t value = mask.MaskValue(output.GetMaskedValue());
    BigInt<16> n = mask.MaskNonce(output.GetMaskedNonce());

    if (mask.SwitchCommit(value) != output.GetCommitment()) {
        return false;
    }

    // Calculate Carol's sending key 's' and check that s*B ?= Ke
    SecretKey s = Hasher(EHashTag::SEND_KEY)
        .Append(address.A())
        .Append(address.B())
        .Append(value)
        .Append(n)
        .hash();
    if (output.Ke() != address.B().Mul(s)) {
        return false;
    }

    // v0.21.2 incorrectly generated MWEB keys from the pre-split keypool for upgraded wallets.
    // These keys will not have an mweb_index, so we set the address_index as CUSTOM_KEY.
    coin.address_index = pMetadata->key_origin.hdkeypath.mweb_index.value_or(CUSTOM_KEY);
    coin.blind = std::make_optional(mask.GetRawBlind());
    coin.amount = value;
    coin.output_id = output.GetOutputID();
    coin.address = address;
    coin.shared_secret = std::make_optional(std::move(t));
    coin.spend_key = CalculateOutputKey(coin);

    return true;
}

std::optional<SecretKey> Keychain::CalculateOutputKey(const mw::Coin& coin) const
{
    if (!m_spk_man) {
        return std::nullopt;
    }

    // If we already calculated the spend key, there's no need to calculate it again.
    if (coin.HasSpendKey()) {
        return coin.spend_key;
    }

    // Watch-only or locked wallets will not have the spend secret.
    if (!HasSpendSecret() || !coin.HasSharedSecret() || !coin.IsMine()) {
        return std::nullopt;
    }

    auto derive_output_key = [](const SecretKey& spend_key, const SecretKey& shared_secret) -> SecretKey {
        return SecretKeys::From(spend_key)
            .Mul(Hashed(EHashTag::OUT_KEY, shared_secret))
            .Total();
    };

    // An address_index of CUSTOM_KEY means the spend key was not generated from the MWEB keychain.
    // We should lookup the secret key in the wallet DB, instead of calculating by index.
    if (coin.address_index == CUSTOM_KEY) {
        if (!coin.HasAddress()) {
            return std::nullopt;
        }

        CKey key;
        if (!m_spk_man->GetKey(coin.address->B().GetID(), key)) {
            return std::nullopt;
        }

        return derive_output_key(SecretKey(key.begin()), *coin.shared_secret);
    }

    return derive_output_key(GetSpendKey(coin.address_index), *coin.shared_secret);
}

StealthAddress Keychain::GetStealthAddress(const uint32_t index) const
{
    assert(HasSpendPubKey());

    SecretKey mi = Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(m_scanSecret)
        .hash();
    PublicKey Bi = m_spendPubkey->Add(mi);
    PublicKey Ai = Bi.Mul(m_scanSecret);

    return StealthAddress(Ai, Bi);
}

SecretKey Keychain::GetSpendKey(const uint32_t index) const
{
    assert(HasSpendSecret());

    SecretKey mi = Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(m_scanSecret)
        .hash();

    return SecretKeys::From(*m_spendSecret).Add(mi).Total();
}

END_NAMESPACE
