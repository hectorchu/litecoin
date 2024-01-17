// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <logging.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>

#include <optional>

namespace wallet {
//! Value for the first BIP 32 hardened derivation. Can be used as a bit mask and as a value. See BIP 32 for more details.
const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

KeyPurpose GetPurpose(const OutputType type, const bool internal)
{
    if (type == OutputType::MWEB) {
        return KeyPurpose::MWEB;
    }

    return internal ? KeyPurpose::INTERNAL : KeyPurpose::EXTERNAL;
}

static uint32_t* GetMutChainCounter(CHDChain& chain, const KeyPurpose purpose)
{
    switch (purpose) {
    case KeyPurpose::EXTERNAL: return &chain.nExternalChainCounter;
    case KeyPurpose::INTERNAL: return &chain.nInternalChainCounter;
    case KeyPurpose::MWEB: return &chain.nMWEBIndexCounter;
    }
    assert(false);
};

//static uint32_t GetChainCounter(const CHDChain& chain, const KeyPurpose purpose)
//{
//    switch (purpose) {
//    case KeyPurpose::EXTERNAL: return chain.nExternalChainCounter;
//    case KeyPurpose::INTERNAL: return chain.nInternalChainCounter;
//    case KeyPurpose::MWEB: return chain.nMWEBIndexCounter;
//    }
//    assert(false);
//}

util::Result<CTxDestination> LegacyScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    if (LEGACY_OUTPUT_TYPES.count(type) == 0) {
        return util::Error{_("Error: Legacy wallets only support the \"legacy\", \"p2sh-segwit\", and \"bech32\" address types")};
    }
    assert(type != OutputType::BECH32M);

    LOCK(cs_KeyStore);

    // Generate a new key that is added to wallet
    CPubKey new_key;
    if (!GetKeyFromPool(new_key, type)) {
        return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
    }
    LearnRelatedScripts(new_key, type);

    SecretKey scan_secret = GetScanSecret();
    if (type == OutputType::MWEB && scan_secret.IsNull()) {
        return util::Error{Untranslated("Error: Scan secret needed for MWEB outputs")};
    }
    return GetDestinationForKey(new_key, type, scan_secret);
}

typedef std::vector<unsigned char> valtype;

namespace {

/**
 * This is an enum that tracks the execution context of a script, similar to
 * SigVersion in script/interpreter. It is separate however because we want to
 * distinguish between top-level scriptPubKey execution and P2SH redeemScript
 * execution (a distinction that has no impact on consensus rules).
 */
enum class IsMineSigVersion
{
    TOP = 0,        //!< scriptPubKey execution
    P2SH = 1,       //!< P2SH redeemScript
    WITNESS_V0 = 2, //!< P2WSH witness script execution
};

/**
 * This is an internal representation of isminetype + invalidity.
 * Its order is significant, as we return the max of all explored
 * possibilities.
 */
enum class IsMineResult
{
    NO = 0,         //!< Not ours
    WATCH_ONLY = 1, //!< Included in watch-only balance
    SPENDABLE = 2,  //!< Included in all balances
    INVALID = 3,    //!< Not spendable by anyone (uncompressed pubkey in segwit, P2SH inside P2SH or witness, witness inside witness)
};

bool PermitsUncompressed(IsMineSigVersion sigversion)
{
    return sigversion == IsMineSigVersion::TOP || sigversion == IsMineSigVersion::P2SH;
}

bool HaveKeys(const std::vector<valtype>& pubkeys, const LegacyScriptPubKeyMan& keystore)
{
    for (const valtype& pubkey : pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (!keystore.HaveKey(keyID)) return false;
    }
    return true;
}

//! Recursively solve script and return spendable/watchonly/invalid status.
//!
//! @param keystore            legacy key and script store
//! @param scriptPubKey        script to solve
//! @param sigversion          script type (top-level / redeemscript / witnessscript)
//! @param recurse_scripthash  whether to recurse into nested p2sh and p2wsh
//!                            scripts or simply treat any script that has been
//!                            stored in the keystore as spendable
IsMineResult IsMineInner(const LegacyScriptPubKeyMan& keystore, const CScript& scriptPubKey, IsMineSigVersion sigversion, bool recurse_scripthash=true)
{
    IsMineResult ret = IsMineResult::NO;

    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    CKeyID keyID;
    switch (whichType) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
    case TxoutType::WITNESS_UNKNOWN:
    case TxoutType::WITNESS_V1_TAPROOT:
    case TxoutType::WITNESS_MWEB_PEGIN:
    case TxoutType::WITNESS_MWEB_HOGADDR:
        break;
    case TxoutType::PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (!PermitsUncompressed(sigversion) && vSolutions[0].size() != 33) {
            return IsMineResult::INVALID;
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::WITNESS_V0_KEYHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WPKH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            // We do not support bare witness outputs unless the P2SH version of it would be
            // acceptable as well. This protects against matching before segwit activates.
            // This also applies to the P2WSH case.
            break;
        }
        ret = std::max(ret, IsMineInner(keystore, GetScriptForDestination(PKHash(uint160(vSolutions[0]))), IsMineSigVersion::WITNESS_V0));
        break;
    }
    case TxoutType::PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!PermitsUncompressed(sigversion)) {
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                return IsMineResult::INVALID;
            }
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::SCRIPTHASH:
    {
        if (sigversion != IsMineSigVersion::TOP) {
            // P2SH inside P2WSH or P2SH is invalid.
            return IsMineResult::INVALID;
        }
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? IsMineInner(keystore, subscript, IsMineSigVersion::P2SH) : IsMineResult::SPENDABLE);
        }
        break;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WSH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            break;
        }
        uint160 hash;
        CRIPEMD160().Write(vSolutions[0].data(), vSolutions[0].size()).Finalize(hash.begin());
        CScriptID scriptID = CScriptID(hash);
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? IsMineInner(keystore, subscript, IsMineSigVersion::WITNESS_V0) : IsMineResult::SPENDABLE);
        }
        break;
    }

    case TxoutType::MULTISIG:
    {
        // Never treat bare multisig outputs as ours (they can still be made watchonly-though)
        if (sigversion == IsMineSigVersion::TOP) {
            break;
        }

        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (!PermitsUncompressed(sigversion)) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    return IsMineResult::INVALID;
                }
            }
        }
        if (HaveKeys(keys, keystore)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    }
    } // no default case, so the compiler can warn about missing cases

    if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
    }
    return ret;
}

} // namespace

isminetype LegacyScriptPubKeyMan::IsMine(const GenericAddress& script) const
{
    if (script.IsMWEB()) {
        if (GetScanSecret().IsNull()) {
            return ISMINE_NO;
        }

        const StealthAddress& mweb_address = script.GetMWEBAddress();
        if (mweb_address.GetSpendPubKey().Mul(GetScanSecret()) != mweb_address.GetScanPubKey()) {
            return ISMINE_NO;
        }

        return HaveKey(mweb_address.GetSpendPubKey().GetID()) ? ISMINE_SPENDABLE : ISMINE_NO;
    }

    switch (IsMineInner(*this, script.GetScript(), IsMineSigVersion::TOP)) {
    case IsMineResult::INVALID:
    case IsMineResult::NO:
        return ISMINE_NO;
    case IsMineResult::WATCH_ONLY:
        return ISMINE_WATCH_ONLY;
    case IsMineResult::SPENDABLE:
        return ISMINE_SPENDABLE;
    }
    assert(false);
}

bool LegacyScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key, bool accept_no_keys)
{
    {
        LOCK(cs_KeyStore);
        assert(mapKeys.empty());

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        WalletBatch batch(m_storage.GetDatabase());
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(master_key, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
            else {
                // Rewrite these encrypted keys with checksums
                batch.WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
            }
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || (!keyPass && !accept_no_keys))
            return false;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

bool LegacyScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_KeyStore);
    encrypted_batch = batch;
    if (!mapCryptedKeys.empty()) {
        encrypted_batch = nullptr;
        return false;
    }

    KeyMap keys_to_encrypt;
    keys_to_encrypt.swap(mapKeys); // Clear mapKeys so AddCryptedKeyInner will succeed.
    for (const KeyMap::value_type& mKey : keys_to_encrypt)
    {
        const CKey &key = mKey.second;
        CPubKey vchPubKey = key.GetPubKey();
        CKeyingMaterial vchSecret(key.begin(), key.end());
        std::vector<unsigned char> vchCryptedSecret;
        if (!EncryptSecret(master_key, vchSecret, vchPubKey.GetHash(), vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
        if (!AddCryptedKey(vchPubKey, vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
    }
    encrypted_batch = nullptr;
    return true;
}

util::Result<CTxDestination> LegacyScriptPubKeyMan::GetReservedDestination(const OutputType type, const bool internal, int64_t& index, CKeyPool& keypool)
{
    if (LEGACY_OUTPUT_TYPES.count(type) == 0) {
        return util::Error{_("Error: Legacy wallets only support the \"legacy\", \"p2sh-segwit\", and \"bech32\" address types")};
    }
    assert(type != OutputType::BECH32M);
    const KeyPurpose purpose = GetPurpose(type, internal);

    LOCK(cs_KeyStore);
    if (!CanGetAddresses(purpose)) {
        return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
    }

    if (!ReserveKeyFromKeyPool(index, keypool, purpose)) {
        return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
    }

    SecretKey scan_secret = GetScanSecret();
    if (type == OutputType::MWEB && scan_secret.IsNull()) {
        return util::Error{Untranslated("Error: Scan secret needed for MWEB outputs")};
    }
    return GetDestinationForKey(keypool.vchPubKey, type, scan_secret);
}

bool LegacyScriptPubKeyMan::TopUpInactiveHDChain(const CKeyID seed_id, int64_t index, const KeyPurpose purpose)
{
    LOCK(cs_KeyStore);

    auto it = m_inactive_hd_chains.find(seed_id);
    if (it == m_inactive_hd_chains.end()) {
        return false;
    }

    CHDChain& chain = it->second;

    if (purpose == KeyPurpose::MWEB) {
	    chain.m_next_mweb_index = std::max(chain.m_next_mweb_index, index + 1);
    } else if (purpose == KeyPurpose::INTERNAL) {
        chain.m_next_internal_index = std::max(chain.m_next_internal_index, index + 1);
    } else {
        chain.m_next_external_index = std::max(chain.m_next_external_index, index + 1);
    }

    TopUpChain(chain, 0);

    return true;
}

std::vector<WalletDestination> LegacyScriptPubKeyMan::MarkUnusedAddresses(const GenericAddress& script)
{
    LOCK(cs_KeyStore);
    std::vector<WalletDestination> result;
    // extract addresses and check if they match with an unused keypool key
    for (const auto& keyid : GetAffectedKeys(script, *this)) {
        std::map<CKeyID, int64_t>::const_iterator mi = m_pool_key_to_index.find(keyid);
        if (mi != m_pool_key_to_index.end()) {
            WalletLogPrintf("%s: Detected a used keypool key, mark all keypool keys up to this key as used\n", __func__);
            for (const auto& keypool : MarkReserveKeysAsUsed(mi->second)) {
                // derive all possible destinations as any of them could have been used
                for (const auto& type : LEGACY_OUTPUT_TYPES) {
                    SecretKey scan_secret = GetScanSecret();
                    if (type == OutputType::MWEB && scan_secret.IsNull()) {
                        continue; // MW: TODO - We need to make sure we load MWEB scan secret before this
                    }

                    const auto dest = GetDestinationForKey(keypool.vchPubKey, type, scan_secret);
                    result.push_back({dest, keypool.fInternal});
                }
            }

            WalletLogPrintf("Calling TopUp from MarkUnusedAddresses\n");
            if (!TopUp()) {
                WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
            }
        }

        // Find the key's metadata and check if it's seed id (if it has one) is inactive, i.e. it is not the current m_hd_chain seed id.
        // If so, TopUp the inactive hd chain
        auto it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()){
            CKeyMetadata meta = it->second;
            if (!meta.hd_seed_id.IsNull() && meta.hd_seed_id != m_hd_chain.seed_id) {
                HDKeyPath hdkeypath;
                if (meta.has_key_origin) {
                    hdkeypath = meta.key_origin.hdkeypath;
                } else if (!ParseHDKeypath(meta.hdKeypath, hdkeypath)) {
                    WalletLogPrintf("%s: Adding inactive seed keys failed, invalid hdKeypath: %s\n",
                                    __func__,
                                    meta.hdKeypath);
                }
                if (hdkeypath.path.size() != 3) {
                    WalletLogPrintf("%s: Adding inactive seed keys failed, invalid path size: %d, has_key_origin: %s\n",
                                    __func__,
                                    hdkeypath.path.size(),
                                    meta.has_key_origin);
                } else {
                    KeyPurpose purpose = KeyPurpose::EXTERNAL;
                    if (meta.key_origin.hdkeypath.mweb_index.has_value()) {
                        purpose = KeyPurpose::MWEB;
                    } else if ((meta.key_origin.hdkeypath.path[1] & ~BIP32_HARDENED_KEY_LIMIT) != 0) {
                        purpose = KeyPurpose::INTERNAL;
                    }
					
                    int64_t index = meta.key_origin.hdkeypath.mweb_index.has_value() ? *meta.key_origin.hdkeypath.mweb_index : (meta.key_origin.hdkeypath.path[2] & ~BIP32_HARDENED_KEY_LIMIT);

                    if (!TopUpInactiveHDChain(meta.hd_seed_id, index, purpose)) {
                        WalletLogPrintf("%s: Adding inactive seed keys failed\n", __func__);
                    }
                }
            }
        }
    }

    return result;
}

void LegacyScriptPubKeyMan::UpgradeKeyMetadata()
{
    LOCK(cs_KeyStore);
    if (m_storage.IsLocked() || m_storage.IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
        return;
    }

    std::unique_ptr<WalletBatch> batch = std::make_unique<WalletBatch>(m_storage.GetDatabase());
    for (auto& meta_pair : mapKeyMetadata) {
        CKeyMetadata& meta = meta_pair.second;
        if (!meta.hd_seed_id.IsNull() && !meta.has_key_origin && meta.hdKeypath != "s") { // If the hdKeypath is "s", that's the seed and it doesn't have a key origin
            CKey key;
            GetKey(meta.hd_seed_id, key);
            CExtKey masterKey;
            masterKey.SetSeed(key);
            // Add to map
            CKeyID master_id = masterKey.key.GetPubKey().GetID();
            std::copy(master_id.begin(), master_id.begin() + 4, meta.key_origin.fingerprint);
            if (!ParseHDKeypath(meta.hdKeypath, meta.key_origin.hdkeypath)) {
                throw std::runtime_error("Invalid stored hdKeypath");
            }
            meta.has_key_origin = true;
            if (meta.nVersion < CKeyMetadata::VERSION_WITH_KEY_ORIGIN) {
                meta.nVersion = CKeyMetadata::VERSION_WITH_MWEB_INDEX;
            }

            // Write meta to wallet
            CPubKey pubkey;
            if (GetPubKey(meta_pair.first, pubkey)) {
                batch->WriteKeyMetadata(meta, pubkey, true);
            }
        }
    }
}

bool LegacyScriptPubKeyMan::SetupGeneration(bool force)
{
    if ((CanGenerateKeys() && !force) || m_storage.IsLocked()) {
        return false;
    }

    SetHDSeed(GenerateNewSeed());
    if (!NewKeyPool()) {
        return false;
    }
    return true;
}

bool LegacyScriptPubKeyMan::IsHDEnabled() const
{
    return !m_hd_chain.seed_id.IsNull();
}

bool LegacyScriptPubKeyMan::CanGetAddresses(const KeyPurpose purpose) const
{
    LOCK(cs_KeyStore);
    // Check if the keypool has keys
    bool keypool_has_keys;
    if (purpose == KeyPurpose::INTERNAL && m_storage.CanSupportFeature(FEATURE_HD_SPLIT)) {
        keypool_has_keys = setInternalKeyPool.size() > 0;
    } else if (purpose == KeyPurpose::MWEB) {
        if (!m_mwebKeychain) {
            return false;
        }

        LogPrintf("DEBUG: set_mweb_keypool.size=%u\n", set_mweb_keypool.size());
        keypool_has_keys = set_mweb_keypool.size() > 0;
    } else {
        keypool_has_keys = KeypoolCountExternalKeys() > 0;
    }
    // If the keypool doesn't have keys, check if we can generate them
    if (!keypool_has_keys) {
        return CanGenerateKeys();
    }
    return keypool_has_keys;
}

bool LegacyScriptPubKeyMan::Upgrade(int prev_version, int new_version, bilingual_str& error)
{
    LOCK(cs_KeyStore);

    if (m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        // Nothing to do here if private keys are not enabled
        return true;
    }

    bool hd_upgrade = false;
    bool split_upgrade = false;
    if (IsFeatureSupported(new_version, FEATURE_HD) && !IsHDEnabled()) {
        WalletLogPrintf("Upgrading wallet to HD\n");
        m_storage.SetMinVersion(FEATURE_HD);

        // generate a new master key
        CPubKey masterPubKey = GenerateNewSeed();
        SetHDSeed(masterPubKey);
        hd_upgrade = true;
    }

    // Upgrade to HD chain split if necessary
    if (!IsFeatureSupported(prev_version, FEATURE_HD_SPLIT) && IsFeatureSupported(new_version, FEATURE_HD_SPLIT)) {
        WalletLogPrintf("Upgrading wallet to use HD chain split\n");
        m_storage.SetMinVersion(FEATURE_PRE_SPLIT_KEYPOOL);
        split_upgrade = FEATURE_HD_SPLIT > prev_version;
    }
    // Mark all keys currently in the keypool as pre-split
    if (split_upgrade) {
        MarkPreSplitKeys();
    }

    // Upgrade to MWEB if necessary
    if (!IsFeatureSupported(prev_version, FEATURE_MWEB) && IsFeatureSupported(new_version, FEATURE_MWEB)) {
        WalletBatch batch(m_storage.GetDatabase());
        m_storage.SetMinVersion(FEATURE_MWEB, &batch);
        
        // Upgrade CHDChain(s) to support MWEB fields
        if (m_hd_chain.nVersion < CHDChain::VERSION_HD_MWEB) { // MW: TODO - Should we also upgrade inactive HD chains?
            m_hd_chain.nVersion = CHDChain::VERSION_HD_MWEB;
            if (!batch.WriteHDChain(m_hd_chain)) {
                error = _("Unable to write HD chain");
                return false;
            }
        }
    }
    // Regenerate the keypool if upgraded to HD
    if (hd_upgrade) {
        if (!NewKeyPool()) {
            error = _("Unable to generate keys");
            return false;
        }
    }
    return true;
}

bool LegacyScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_KeyStore);
    return !mapKeys.empty() || !mapCryptedKeys.empty();
}

void LegacyScriptPubKeyMan::RewriteDB()
{
    LOCK(cs_KeyStore);
    setInternalKeyPool.clear();
    setExternalKeyPool.clear();
    set_mweb_keypool.clear();
    m_pool_key_to_index.clear();
    // Note: can't top-up keypool here, because wallet is locked.
    // User will be prompted to unlock wallet the next operation
    // that requires a new key.
}

static int64_t GetOldestKeyTimeInPool(const std::set<int64_t>& setKeyPool, WalletBatch& batch) {
    if (setKeyPool.empty()) {
        return GetTime();
    }

    CKeyPool keypool;
    int64_t nIndex = *(setKeyPool.begin());
    if (!batch.ReadPool(nIndex, keypool)) {
        throw std::runtime_error(std::string(__func__) + ": read oldest key in keypool failed");
    }
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

std::optional<int64_t> LegacyScriptPubKeyMan::GetOldestKeyPoolTime() const
{
    LOCK(cs_KeyStore);

    WalletBatch batch(m_storage.GetDatabase());

    // load oldest key from keypool, get time and return
    int64_t oldestKey = GetOldestKeyTimeInPool(setExternalKeyPool, batch);
    if (IsHDEnabled() && m_storage.CanSupportFeature(FEATURE_HD_SPLIT)) {
        oldestKey = std::max(GetOldestKeyTimeInPool(setInternalKeyPool, batch), oldestKey);
        if (!set_pre_split_keypool.empty()) {
            oldestKey = std::max(GetOldestKeyTimeInPool(set_pre_split_keypool, batch), oldestKey);
        }
        if (!set_mweb_keypool.empty()) {
            oldestKey = std::max(GetOldestKeyTimeInPool(set_mweb_keypool, batch), oldestKey);
        }
    }

    return oldestKey;
}

size_t LegacyScriptPubKeyMan::KeypoolCountExternalKeys() const
{
    LOCK(cs_KeyStore);
    return setExternalKeyPool.size() + set_pre_split_keypool.size();
}

unsigned int LegacyScriptPubKeyMan::GetKeyPoolSize() const
{
    LOCK(cs_KeyStore);
    return setInternalKeyPool.size() + setExternalKeyPool.size() + set_pre_split_keypool.size();
}

int64_t LegacyScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_KeyStore);
    return nTimeFirstKey;
}

std::unique_ptr<SigningProvider> LegacyScriptPubKeyMan::GetSolvingProvider(const GenericAddress& dest_addr) const
{
    return std::make_unique<LegacySigningProvider>(*this);
}

bool LegacyScriptPubKeyMan::CanProvide(const GenericAddress& dest_addr, SignatureData& sigdata)
{
    if (dest_addr.IsMWEB()) {
        isminetype mweb_ismine = IsMine(dest_addr);
        return mweb_ismine == ISMINE_SPENDABLE || mweb_ismine == ISMINE_WATCH_ONLY;
    }
    IsMineResult ismine = IsMineInner(*this, dest_addr.GetScript(), IsMineSigVersion::TOP, /* recurse_scripthash= */ false);
    if (ismine == IsMineResult::SPENDABLE || ismine == IsMineResult::WATCH_ONLY) {
        // If ismine, it means we recognize keys or script ids in the script, or
        // are watching the script itself, and we can at least provide metadata
        // or solving information, even if not able to sign fully.
        return true;
    } else {
        // If, given the stuff in sigdata, we could make a valid sigature, then we can provide for this script
        ProduceSignature(*this, DUMMY_SIGNATURE_CREATOR, dest_addr.GetScript(), sigdata);
        if (!sigdata.signatures.empty()) {
            // If we could make signatures, make sure we have a private key to actually make a signature
            bool has_privkeys = false;
            for (const auto& key_sig_pair : sigdata.signatures) {
                has_privkeys |= HaveKey(key_sig_pair.first);
            }
            return has_privkeys;
        }
        return false;
    }
}

bool LegacyScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<GenericOutputID, GenericCoin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    return ::SignTransaction(tx, this, coins, sighash, input_errors);
}

SigningResult LegacyScriptPubKeyMan::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    CKey key;
    if (!GetKey(ToKeyID(pkhash), key)) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    if (MessageSign(key, message, str_sig)) {
        return SigningResult::OK;
    }
    return SigningResult::SIGNING_FAILED;
}

TransactionError LegacyScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbtx, const PrecomputedTransactionData& txdata, int sighash_type, bool sign, bool bip32derivs, int* n_signed, bool finalize) const
{
    if (n_signed) {
        *n_signed = 0;
    }

    // MW: TODO - if sign == true, sign MWEB components here?
    if (sign) {
        PSBTSignMWEBTx(HidingSigningProvider(this, !sign, !bip32derivs), psbtx);
    }

    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // Get the Sighash type
        if (sign && input.sighash_type != std::nullopt && *input.sighash_type != sighash_type) {
            return TransactionError::SIGHASH_MISMATCH;
        }

        // Check non_witness_utxo has specified prevout
        if (input.non_witness_utxo) {
            if (*input.prev_out >= input.non_witness_utxo->vout.size()) {
                return TransactionError::MISSING_INPUTS;
            }
        } else if (input.witness_utxo.IsNull()) {
            // There's no UTXO so we can just skip this now
            continue;
        }
        SignatureData sigdata;
        input.FillSignatureData(sigdata);
        SignPSBTInput(HidingSigningProvider(this, !sign, !bip32derivs), psbtx, i, &txdata, sighash_type, nullptr, finalize);

        bool signed_one = PSBTInputSigned(input);
        if (n_signed && (signed_one || !sign)) {
            // If sign is false, we assume that we _could_ sign if we get here. This
            // will never have false negatives; it is hard to tell under what i
            // circumstances it could have false positives.
            (*n_signed)++;
        }
    }

    // Fill in the bip32 keypaths and redeemscripts for the outputs so that hardware wallets can identify change
    for (unsigned int i = 0; i < psbtx.outputs.size(); ++i) {
        UpdatePSBTOutput(HidingSigningProvider(this, true, !bip32derivs), psbtx, i);
    }

    return TransactionError::OK;
}

std::unique_ptr<CKeyMetadata> LegacyScriptPubKeyMan::GetMetadata(const CTxDestination& dest) const
{
    LOCK(cs_KeyStore);

    CKeyID key_id = GetKeyForDestination(*this, dest);
    if (!key_id.IsNull()) {
        auto it = mapKeyMetadata.find(key_id);
        if (it != mapKeyMetadata.end()) {
            return std::make_unique<CKeyMetadata>(it->second);
        }
    }

    CScript scriptPubKey = GetScriptForDestination(dest);
    auto it = m_script_metadata.find(CScriptID(scriptPubKey));
    if (it != m_script_metadata.end()) {
        return std::make_unique<CKeyMetadata>(it->second);
    }

    return nullptr;
}

uint256 LegacyScriptPubKeyMan::GetID() const
{
    return uint256::ONE;
}

/**
 * Update wallet first key creation time. This should be called whenever keys
 * are added to the wallet, with the oldest key creation time.
 */
void LegacyScriptPubKeyMan::UpdateTimeFirstKey(int64_t nCreateTime)
{
    AssertLockHeld(cs_KeyStore);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

bool LegacyScriptPubKeyMan::LoadKey(const CKey& key, const CPubKey &pubkey)
{
    return AddKeyPubKeyInner(key, pubkey);
}

bool LegacyScriptPubKeyMan::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    WalletBatch batch(m_storage.GetDatabase());
    return LegacyScriptPubKeyMan::AddKeyPubKeyWithDB(batch, secret, pubkey);
}

bool LegacyScriptPubKeyMan::AddKeyPubKeyWithDB(WalletBatch& batch, const CKey& secret, const CPubKey& pubkey)
{
    AssertLockHeld(cs_KeyStore);

    // Make sure we aren't adding private keys to private key disabled wallets
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // FillableSigningProvider has no concept of wallet databases, but calls AddCryptedKey
    // which is overridden below.  To avoid flushes, the database handle is
    // tunneled through to it.
    bool needsDB = !encrypted_batch;
    if (needsDB) {
        encrypted_batch = &batch;
    }
    if (!AddKeyPubKeyInner(secret, pubkey)) {
        if (needsDB) encrypted_batch = nullptr;
        return false;
    }
    if (needsDB) encrypted_batch = nullptr;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(PKHash(pubkey));
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }

    if (!m_storage.HasEncryptionKeys()) {
        return batch.WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

bool LegacyScriptPubKeyMan::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptHash(redeemScript));
        WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return FillableSigningProvider::AddCScript(redeemScript);
}

void LegacyScriptPubKeyMan::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    UpdateTimeFirstKey(meta.nCreateTime);
    mapKeyMetadata[keyID] = meta;
}

void LegacyScriptPubKeyMan::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    UpdateTimeFirstKey(meta.nCreateTime);
    m_script_metadata[script_id] = meta;
}

bool LegacyScriptPubKeyMan::AddKeyPubKeyInner(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::AddKeyPubKey(key, pubkey);
    }

    if (m_storage.IsLocked()) {
        return false;
    }

    std::vector<unsigned char> vchCryptedSecret;
    CKeyingMaterial vchSecret(key.begin(), key.end());
    if (!EncryptSecret(m_storage.GetEncryptionKey(), vchSecret, pubkey.GetHash(), vchCryptedSecret)) {
        return false;
    }

    if (!AddCryptedKey(pubkey, vchCryptedSecret)) {
        return false;
    }
    return true;
}

bool LegacyScriptPubKeyMan::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret, bool checksum_valid)
{
    // Set fDecryptionThoroughlyChecked to false when the checksum is invalid
    if (!checksum_valid) {
        fDecryptionThoroughlyChecked = false;
    }

    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool LegacyScriptPubKeyMan::AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    assert(mapKeys.empty());

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool LegacyScriptPubKeyMan::AddCryptedKey(const CPubKey &vchPubKey,
                            const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!AddCryptedKeyInner(vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_KeyStore);
        if (encrypted_batch)
            return encrypted_batch->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return WalletBatch(m_storage.GetDatabase()).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
}

bool LegacyScriptPubKeyMan::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool LegacyScriptPubKeyMan::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    std::vector<std::vector<unsigned char>> solutions;
    return Solver(dest, solutions) == TxoutType::PUBKEY &&
        (pubKeyOut = CPubKey(solutions[0])).IsFullyValid();
}

bool LegacyScriptPubKeyMan::RemoveWatchOnly(const CScript &dest)
{
    {
        LOCK(cs_KeyStore);
        setWatchOnly.erase(dest);
        CPubKey pubKey;
        if (ExtractPubKey(dest, pubKey)) {
            mapWatchKeys.erase(pubKey.GetID());
        }
        // Related CScripts are not removed; having superfluous scripts around is
        // harmless (see comment in ImplicitlyLearnRelatedKeyScripts).
    }

    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (!WalletBatch(m_storage.GetDatabase()).EraseWatchOnly(dest))
        return false;

    return true;
}

bool LegacyScriptPubKeyMan::LoadWatchOnly(const CScript &dest)
{
    return AddWatchOnlyInMem(dest);
}

bool LegacyScriptPubKeyMan::AddWatchOnlyInMem(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys[pubKey.GetID()] = pubKey;
        ImplicitlyLearnRelatedKeyScripts(pubKey);
    }
    return true;
}

bool LegacyScriptPubKeyMan::AddWatchOnlyWithDB(WalletBatch &batch, const CScript& dest)
{
    if (!AddWatchOnlyInMem(dest))
        return false;
    const CKeyMetadata& meta = m_script_metadata[CScriptID(dest)];
    UpdateTimeFirstKey(meta.nCreateTime);
    NotifyWatchonlyChanged(true);
    if (batch.WriteWatchOnly(dest, meta)) {
        m_storage.UnsetBlankWalletFlag(batch);
        return true;
    }
    return false;
}

bool LegacyScriptPubKeyMan::AddWatchOnlyWithDB(WalletBatch &batch, const CScript& dest, int64_t create_time)
{
    m_script_metadata[CScriptID(dest)].nCreateTime = create_time;
    return AddWatchOnlyWithDB(batch, dest);
}

bool LegacyScriptPubKeyMan::AddWatchOnly(const CScript& dest)
{
    WalletBatch batch(m_storage.GetDatabase());
    return AddWatchOnlyWithDB(batch, dest);
}

bool LegacyScriptPubKeyMan::AddWatchOnly(const CScript& dest, int64_t nCreateTime)
{
    m_script_metadata[CScriptID(dest)].nCreateTime = nCreateTime;
    return AddWatchOnly(dest);
}

void LegacyScriptPubKeyMan::LoadHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    m_hd_chain = chain;
}

void LegacyScriptPubKeyMan::AddHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    // Store the new chain
    if (!WalletBatch(m_storage.GetDatabase()).WriteHDChain(chain)) {
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");
    }
    // When there's an old chain, add it as an inactive chain as we are now rotating hd chains
    if (!m_hd_chain.seed_id.IsNull()) {
        AddInactiveHDChain(m_hd_chain);
    }

    m_hd_chain = chain;
}

void LegacyScriptPubKeyMan::AddInactiveHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    assert(!chain.seed_id.IsNull());
    m_inactive_hd_chains[chain.seed_id] = chain;
}

bool LegacyScriptPubKeyMan::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::HaveKey(address);
    }
    return mapCryptedKeys.count(address) > 0;
}

bool LegacyScriptPubKeyMan::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return DecryptKey(m_storage.GetEncryptionKey(), vchCryptedSecret, vchPubKey, keyOut);
    }
    return false;
}

bool LegacyScriptPubKeyMan::GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const
{
    CKeyMetadata meta;
    {
        LOCK(cs_KeyStore);
        auto it = mapKeyMetadata.find(keyID);
        if (it == mapKeyMetadata.end()) {
            return false;
        }
        meta = it->second;
    }
    if (meta.has_key_origin) {
        std::copy(meta.key_origin.fingerprint, meta.key_origin.fingerprint + 4, info.fingerprint);
        info.hdkeypath = meta.key_origin.hdkeypath;
    } else { // Single pubkeys get the master fingerprint of themselves
        std::copy(keyID.begin(), keyID.begin() + 4, info.fingerprint);
    }
    return true;
}

bool LegacyScriptPubKeyMan::GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const
{
    LOCK(cs_KeyStore);
    WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
    if (it != mapWatchKeys.end()) {
        pubkey_out = it->second;
        return true;
    }
    return false;
}

bool LegacyScriptPubKeyMan::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        if (!FillableSigningProvider::GetPubKey(address, vchPubKeyOut)) {
            return GetWatchPubKey(address, vchPubKeyOut);
        }
        return true;
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return GetWatchPubKey(address, vchPubKeyOut);
}

CPubKey LegacyScriptPubKeyMan::GenerateNewKey(WalletBatch &batch, CHDChain& hd_chain, const KeyPurpose purpose)
{
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    AssertLockHeld(cs_KeyStore);
    bool fCompressed = m_storage.CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // use HD key derivation if HD was enabled during wallet creation and a seed is present
    if (IsHDEnabled()) {
        DeriveNewChildKey(batch, metadata, secret, hd_chain, m_storage.CanSupportFeature(FEATURE_HD_SPLIT) ? purpose : KeyPurpose::EXTERNAL);
    } else {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed) {
        m_storage.SetMinVersion(FEATURE_COMPRPUBKEY);
    }

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    UpdateTimeFirstKey(nCreationTime);

    WalletLogPrintf("DEBUG: Generated key: Pubkey(%s), Type(%u)\n", HexStr(pubkey), (unsigned int)purpose);
    if (!AddKeyPubKeyWithDB(batch, secret, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": AddKey failed");
    }
    return pubkey;
}

//! Try to derive an extended key, throw if it fails.
static void DeriveExtKey(const CExtKey& key_in, unsigned int index, CExtKey& key_out) {
    if (!key_in.Derive(key_out, index)) {
        throw std::runtime_error("Could not derive extended key");
    }
}

void LegacyScriptPubKeyMan::DeriveNewChildKey(WalletBatch& batch, CKeyMetadata& metadata, CKey& secret, CHDChain& hd_chain, const KeyPurpose purpose)
{
    // for now we use a fixed keypath scheme of m/0'/0'/k
    CKey seed;                     //seed (256bit)
    CExtKey masterKey;             //hd master key
    CExtKey accountKey;            //key at m/0'
    CExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
    CExtKey childKey;              //key at m/0'/0'/<n>'

    // try to get the seed
    if (!GetKey(hd_chain.seed_id, seed))
        throw std::runtime_error(std::string(__func__) + ": seed not found");

    if (purpose == KeyPurpose::MWEB && m_mwebKeychain == nullptr) {
        throw std::runtime_error(std::string(__func__) + ": MWEB keychain not found");
    }

    masterKey.SetSeed(seed);

    // derive m/0'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    DeriveExtKey(masterKey, BIP32_HARDENED_KEY_LIMIT, accountKey);

    // derive m/0'/0' (external chain) OR m/0'/1' (internal chain)
    assert(purpose == KeyPurpose::INTERNAL ? m_storage.CanSupportFeature(FEATURE_HD_SPLIT) : true);
    assert(purpose == KeyPurpose::MWEB ? m_storage.CanSupportFeature(FEATURE_HD_SPLIT) : true);
    DeriveExtKey(accountKey, BIP32_HARDENED_KEY_LIMIT + (uint32_t)purpose, chainChildKey);

    // derive child key at next index, skip keys already known to the wallet
    uint32_t& chain_counter = *GetMutChainCounter(hd_chain, purpose);

    do {
        // always derive hardened keys
        // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
        // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
        if (purpose == KeyPurpose::MWEB) {
            SecretKey spend_key = m_mwebKeychain->GetSpendKey(chain_counter);
            childKey.key.Set(spend_key.vec().begin(), spend_key.vec().end(), true);
            metadata.hdKeypath = "x/" + ToString(chain_counter);
            metadata.key_origin.hdkeypath.path.push_back(chain_counter); // MW: TODO - Provide upgrade method that adds an mweb_index field to KeyOriginPath
            metadata.key_origin.hdkeypath.mweb_index = chain_counter;
        } else {
            DeriveExtKey(chainChildKey, chain_counter | BIP32_HARDENED_KEY_LIMIT, childKey);
            metadata.hdKeypath = "m/0'/" + ToString((uint32_t)purpose) + "'/" + ToString(chain_counter) + "'";
            metadata.key_origin.hdkeypath.path.push_back(0 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.hdkeypath.path.push_back((uint32_t)purpose | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.hdkeypath.path.push_back(chain_counter | BIP32_HARDENED_KEY_LIMIT);
        }

        chain_counter++;
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secret = childKey.key;
    metadata.hd_seed_id = hd_chain.seed_id;
    CKeyID master_id = masterKey.key.GetPubKey().GetID();
    std::copy(master_id.begin(), master_id.begin() + 4, metadata.key_origin.fingerprint);
    metadata.has_key_origin = true;
    // update the chain model in the database
    if (hd_chain.seed_id == m_hd_chain.seed_id && !batch.WriteHDChain(hd_chain))
        throw std::runtime_error(std::string(__func__) + ": writing HD chain model failed");
}

void LegacyScriptPubKeyMan::LoadKeyPool(int64_t nIndex, const CKeyPool &keypool)
{
    LOCK(cs_KeyStore);
    if (keypool.fMWEB) {
        set_mweb_keypool.insert(nIndex);
    } else if (keypool.m_pre_split) {
        set_pre_split_keypool.insert(nIndex);
    } else if (keypool.fInternal) {
        setInternalKeyPool.insert(nIndex);
    } else {
        setExternalKeyPool.insert(nIndex);
    }
    m_max_keypool_index = std::max(m_max_keypool_index, nIndex);
    m_pool_key_to_index[keypool.vchPubKey.GetID()] = nIndex;

    // If no metadata exists yet, create a default with the pool key's
    // creation time. Note that this may be overwritten by actually
    // stored metadata for that key later, which is fine.
    CKeyID keyid = keypool.vchPubKey.GetID();
    if (mapKeyMetadata.count(keyid) == 0)
        mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
}

bool LegacyScriptPubKeyMan::CanGenerateKeys() const
{
    // A wallet can generate keys if it has an HD seed (IsHDEnabled) or it is a non-HD wallet (pre FEATURE_HD)
    LOCK(cs_KeyStore);
    return IsHDEnabled() || !m_storage.CanSupportFeature(FEATURE_HD);
}

CPubKey LegacyScriptPubKeyMan::GenerateNewSeed()
{
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    CKey key;
    key.MakeNewKey(true);
    return DeriveNewSeed(key);
}

CPubKey LegacyScriptPubKeyMan::DeriveNewSeed(const CKey& key)
{
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the seed
    CPubKey seed = key.GetPubKey();
    assert(key.VerifyPubKey(seed));

    // set the hd keypath to "s" -> Seed, refers the seed to itself
    metadata.hdKeypath     = "s";
    metadata.has_key_origin = false;
    metadata.hd_seed_id = seed.GetID();

    {
        LOCK(cs_KeyStore);

        // mem store the metadata
        mapKeyMetadata[seed.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, seed))
            throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");
    }

    return seed;
}

void LegacyScriptPubKeyMan::SetHDSeed(const CPubKey& seed)
{
    LOCK(cs_KeyStore);
    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.nVersion = m_storage.CanSupportFeature(FEATURE_HD_SPLIT) ? CHDChain::VERSION_HD_MWEB : CHDChain::VERSION_HD_BASE; // MW: TODO - Shouldn't this choose VERSION_HD_MWEB, VERSION_HD_SPLIT, or VERSION_HD_BASE based on supported features?
    newHdChain.seed_id = seed.GetID();
    AddHDChain(newHdChain);
    LoadMWEBKeychain();
    NotifyCanGetAddressesChanged();
    WalletBatch batch(m_storage.GetDatabase());
    m_storage.UnsetBlankWalletFlag(batch);
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool LegacyScriptPubKeyMan::NewKeyPool()
{
    if (m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return false;
    }
    {
        LOCK(cs_KeyStore);
        WalletBatch batch(m_storage.GetDatabase());

        for (const int64_t nIndex : setInternalKeyPool) {
            batch.ErasePool(nIndex);
        }
        setInternalKeyPool.clear();

        for (const int64_t nIndex : setExternalKeyPool) {
            batch.ErasePool(nIndex);
        }
        setExternalKeyPool.clear();

        for (const int64_t nIndex : set_pre_split_keypool) {
            batch.ErasePool(nIndex);
        }
        set_pre_split_keypool.clear();

        for (const int64_t nIndex : set_mweb_keypool) {
            batch.ErasePool(nIndex);
        }
        set_mweb_keypool.clear();

        m_pool_key_to_index.clear();

        if (!TopUp()) {
            return false;
        }
        WalletLogPrintf("LegacyScriptPubKeyMan::NewKeyPool rewrote keypool\n");
    }
    return true;
}

bool LegacyScriptPubKeyMan::TopUp(unsigned int kpSize)
{
    if (!CanGenerateKeys()) {
        return false;
    }

    if (!TopUpChain(m_hd_chain, kpSize)) {
        return false;
    }
    for (auto& [chain_id, chain] : m_inactive_hd_chains) {
        if (!TopUpChain(chain, kpSize)) {
            return false;
        }
    }
    NotifyCanGetAddressesChanged();
    return true;
}

bool LegacyScriptPubKeyMan::TopUpChain(CHDChain& chain, unsigned int kpSize)
{
    LOCK(cs_KeyStore);

    if (m_storage.IsLocked()) return false;

    // Top up key pool
    unsigned int nTargetSize;
    if (kpSize > 0) {
        nTargetSize = kpSize;
    } else {
        nTargetSize = std::max(gArgs.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE), int64_t{0});
    }
    int64_t target = std::max((int64_t) nTargetSize, int64_t{1});

    // count amount of available keys (internal, external)
    // make sure the keypool of external and internal keys fits the user selected target (-keypool)
    int64_t missingExternal;
    int64_t missingInternal;
	int64_t missingMWEB;
    if (chain == m_hd_chain) {
        missingExternal = std::max(target - (int64_t)setExternalKeyPool.size(), int64_t{0});
        missingInternal = std::max(target - (int64_t)setInternalKeyPool.size(), int64_t{0});
        missingMWEB = std::max(target - (int64_t)set_mweb_keypool.size(), int64_t{0});
    } else {
        missingExternal = std::max(target - (chain.nExternalChainCounter - chain.m_next_external_index), int64_t{0});
        missingInternal = std::max(target - (chain.nInternalChainCounter - chain.m_next_internal_index), int64_t{0});
		missingMWEB = std::max(target - (chain.nMWEBIndexCounter - chain.m_next_mweb_index), int64_t{0});
    }

    if (!IsHDEnabled() || !m_storage.CanSupportFeature(FEATURE_HD_SPLIT)) {
        // don't create extra internal keys
        missingInternal = 0;
    }
    if (m_mwebKeychain == nullptr) {
        missingMWEB = 0;
    }
	
    WalletBatch batch(m_storage.GetDatabase());
    for (int64_t i = missingInternal + missingExternal + missingMWEB; i--;) {
        KeyPurpose purpose = KeyPurpose::EXTERNAL;
        if (i < missingInternal) {
            purpose = KeyPurpose::INTERNAL;
        } else if (i < (missingInternal + missingMWEB)) {
            purpose = KeyPurpose::MWEB;
        }

        CPubKey pubkey(GenerateNewKey(batch, chain, purpose));
        if (chain == m_hd_chain) {
            AddKeypoolPubkeyWithDB(pubkey, purpose, batch);
        }
    }
    if (missingInternal + missingExternal + missingMWEB > 0) {
        if (chain == m_hd_chain) {
            WalletLogPrintf("keypool added %d keys (%d internal, %d MWEB), size=%u (%u internal, %u MWEB)\n", missingInternal + missingExternal + missingMWEB, missingInternal, missingMWEB, setInternalKeyPool.size() + setExternalKeyPool.size() + set_pre_split_keypool.size() + set_mweb_keypool.size(), setInternalKeyPool.size(), set_mweb_keypool.size());
        } else {
            WalletLogPrintf("inactive seed with id %s added %d external keys, %d internal keys, %d MWEB keys\n", HexStr(chain.seed_id), missingExternal, missingInternal, missingMWEB);
        }
    }
    return true;
}

void LegacyScriptPubKeyMan::AddKeypoolPubkeyWithDB(const CPubKey& pubkey, const KeyPurpose purpose, WalletBatch& batch)
{
    LOCK(cs_KeyStore);
    assert(m_max_keypool_index < std::numeric_limits<int64_t>::max()); // How in the hell did you use so many keys?
    int64_t index = ++m_max_keypool_index;
    if (!batch.WritePool(index, CKeyPool(pubkey, purpose == KeyPurpose::INTERNAL, purpose == KeyPurpose::MWEB))) {
        throw std::runtime_error(std::string(__func__) + ": writing imported pubkey failed");
    }
    if (purpose == KeyPurpose::INTERNAL) {
        setInternalKeyPool.insert(index);
    } else if (purpose == KeyPurpose::MWEB) {
        set_mweb_keypool.insert(index);
    } else {
        setExternalKeyPool.insert(index);
    }
    m_pool_key_to_index[pubkey.GetID()] = index;
}

void LegacyScriptPubKeyMan::KeepDestination(int64_t nIndex, const OutputType& type)
{
    assert(type != OutputType::BECH32M);
    // Remove from key pool
    WalletBatch batch(m_storage.GetDatabase());
    batch.ErasePool(nIndex);
    CPubKey pubkey;
    bool have_pk = GetPubKey(m_index_to_reserved_key.at(nIndex), pubkey);
    assert(have_pk);
    LearnRelatedScripts(pubkey, type);
    m_index_to_reserved_key.erase(nIndex);
    WalletLogPrintf("keypool keep %d\n", nIndex);
}

void LegacyScriptPubKeyMan::ReturnDestination(int64_t nIndex, const KeyPurpose purpose, const CTxDestination&)
{
    // Return to key pool
    {
        LOCK(cs_KeyStore);
        if (purpose == KeyPurpose::INTERNAL) {
            setInternalKeyPool.insert(nIndex);
        } else if (purpose == KeyPurpose::MWEB) {
            set_mweb_keypool.insert(nIndex);
        } else if (!set_pre_split_keypool.empty()) {
            set_pre_split_keypool.insert(nIndex);
        } else {
            setExternalKeyPool.insert(nIndex);
        }
        CKeyID& pubkey_id = m_index_to_reserved_key.at(nIndex);
        m_pool_key_to_index[pubkey_id] = nIndex;
        m_index_to_reserved_key.erase(nIndex);
        NotifyCanGetAddressesChanged();
    }
    WalletLogPrintf("keypool return %d\n", nIndex);
}

bool LegacyScriptPubKeyMan::GetKeyFromPool(CPubKey& result, const OutputType type, bool internal)
{
    assert(type != OutputType::BECH32M);
    KeyPurpose purpose = GetPurpose(type, internal);
	if (!CanGetAddresses(purpose)) {
        return false;
    }

    CKeyPool keypool;
    {
        LOCK(cs_KeyStore);
        int64_t nIndex;
        if (!ReserveKeyFromKeyPool(nIndex, keypool, purpose) && !m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            if (m_storage.IsLocked()) return false;
            WalletBatch batch(m_storage.GetDatabase());
            result = GenerateNewKey(batch, m_hd_chain, purpose);
            return true;
        }
        KeepDestination(nIndex, type);
        result = keypool.vchPubKey;
    }
    return true;
}

bool LegacyScriptPubKeyMan::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, const KeyPurpose purpose)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_KeyStore);

        bool fReturningInternal = (purpose == KeyPurpose::INTERNAL);
        fReturningInternal &= (IsHDEnabled() && m_storage.CanSupportFeature(FEATURE_HD_SPLIT)) || m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        bool fMWEB = (purpose == KeyPurpose::MWEB) && IsHDEnabled() && m_storage.CanSupportFeature(FEATURE_HD_SPLIT);
        bool use_pre_split = !fMWEB && !set_pre_split_keypool.empty();

        auto fn_get_keypool = [this](const bool internal, const bool mweb) -> std::set<int64_t>& {
             if (mweb) {
                return set_mweb_keypool;
             } else if (!set_pre_split_keypool.empty()) {
                 return set_pre_split_keypool;
             } else if (internal) {
                return setInternalKeyPool;
            }

            return setExternalKeyPool;
        };

        std::set<int64_t>& setKeyPool = fn_get_keypool(fReturningInternal, fMWEB);

        // Get the oldest key
        if (setKeyPool.empty()) {
            return false;
        }

        WalletBatch batch(m_storage.GetDatabase());

        auto it = setKeyPool.begin();
        nIndex = *it;
        setKeyPool.erase(it);
        if (!batch.ReadPool(nIndex, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read failed");
        }
        CPubKey pk;
        if (!GetPubKey(keypool.vchPubKey.GetID(), pk)) {
            throw std::runtime_error(std::string(__func__) + ": unknown key in key pool");
        }
        if (keypool.fMWEB != fMWEB) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry misclassified");
        }
        // If the key was pre-split keypool, we don't care about what type it is
        if (!use_pre_split && keypool.fInternal != fReturningInternal) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry misclassified");
        }
        if (!keypool.vchPubKey.IsValid()) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry invalid");
        }

        assert(m_index_to_reserved_key.count(nIndex) == 0);
        m_index_to_reserved_key[nIndex] = keypool.vchPubKey.GetID();
        m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        WalletLogPrintf("keypool reserve %d\n", nIndex);
    }
    NotifyCanGetAddressesChanged();
    return true;
}

void LegacyScriptPubKeyMan::LearnRelatedScripts(const CPubKey& key, OutputType type)
{
    assert(type != OutputType::BECH32M);
    if (key.IsCompressed() && (type == OutputType::P2SH_SEGWIT || type == OutputType::BECH32)) {
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        // Make sure the resulting program is solvable.
        const auto desc = InferDescriptor(witprog, *this);
        assert(desc && desc->IsSolvable());
        AddCScript(witprog);
    }
}

void LegacyScriptPubKeyMan::LearnAllRelatedScripts(const CPubKey& key)
{
    // OutputType::P2SH_SEGWIT always adds all necessary scripts for all types.
    LearnRelatedScripts(key, OutputType::P2SH_SEGWIT);
}

std::vector<CKeyPool> LegacyScriptPubKeyMan::MarkReserveKeysAsUsed(int64_t keypool_id)
{
    AssertLockHeld(cs_KeyStore);
    bool mweb = set_mweb_keypool.count(keypool_id);
    bool internal = !mweb && setInternalKeyPool.count(keypool_id);
    if (!internal && !mweb) assert(setExternalKeyPool.count(keypool_id) || set_pre_split_keypool.count(keypool_id));

    std::set<int64_t>* setKeyPool = nullptr;
    if (mweb) {
        setKeyPool = &set_mweb_keypool;
    } else if (internal) {
        setKeyPool = &setInternalKeyPool;
    } else {
        setKeyPool = (set_pre_split_keypool.empty() ? &setExternalKeyPool : &set_pre_split_keypool);
    }
    auto it = setKeyPool->begin();

    std::vector<CKeyPool> result;
    WalletBatch batch(m_storage.GetDatabase());
    while (it != std::end(*setKeyPool)) {
        const int64_t& index = *(it);
        if (index > keypool_id) break; // set*KeyPool is ordered

        CKeyPool keypool;
        if (batch.ReadPool(index, keypool)) { //TODO: This should be unnecessary
            m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        }

        if (!mweb) {
            LearnAllRelatedScripts(keypool.vchPubKey);
        }

        batch.ErasePool(index);
        WalletLogPrintf("keypool index %d removed\n", index);
        it = setKeyPool->erase(it);
        result.push_back(std::move(keypool));
    }

    return result;
}

std::vector<CKeyID> GetAffectedKeys(const GenericAddress& spk, const SigningProvider& provider)
{
    if (spk.IsMWEB()) {
        return std::vector<CKeyID>{spk.GetMWEBAddress().GetSpendPubKey().GetID()};
    }

    std::vector<GenericAddress> dummy;
    FlatSigningProvider out;
    InferDescriptor(spk.GetScript(), provider)->Expand(0, DUMMY_SIGNING_PROVIDER, dummy, out);
    std::vector<CKeyID> ret;
    for (const auto& entry : out.pubkeys) {
        ret.push_back(entry.first);
    }
    return ret;
}

void LegacyScriptPubKeyMan::MarkPreSplitKeys()
{
    WalletBatch batch(m_storage.GetDatabase());
    for (auto it = setExternalKeyPool.begin(); it != setExternalKeyPool.end();) {
        int64_t index = *it;
        CKeyPool keypool;
        if (!batch.ReadPool(index, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read keypool entry failed");
        }
        keypool.m_pre_split = true;
        if (!batch.WritePool(index, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": writing modified keypool entry failed");
        }
        set_pre_split_keypool.insert(index);
        it = setExternalKeyPool.erase(it);
    }
}

bool LegacyScriptPubKeyMan::AddCScript(const CScript& redeemScript)
{
    WalletBatch batch(m_storage.GetDatabase());
    return AddCScriptWithDB(batch, redeemScript);
}

bool LegacyScriptPubKeyMan::AddCScriptWithDB(WalletBatch& batch, const CScript& redeemScript)
{
    if (!FillableSigningProvider::AddCScript(redeemScript))
        return false;
    if (batch.WriteCScript(Hash160(redeemScript), redeemScript)) {
        m_storage.UnsetBlankWalletFlag(batch);
        return true;
    }
    return false;
}

bool LegacyScriptPubKeyMan::AddKeyOriginWithDB(WalletBatch& batch, const CPubKey& pubkey, const KeyOriginInfo& info)
{
    LOCK(cs_KeyStore);
    std::copy(info.fingerprint, info.fingerprint + 4, mapKeyMetadata[pubkey.GetID()].key_origin.fingerprint);
    mapKeyMetadata[pubkey.GetID()].key_origin.hdkeypath = info.hdkeypath;
    mapKeyMetadata[pubkey.GetID()].has_key_origin = true;
    mapKeyMetadata[pubkey.GetID()].hdKeypath = WriteHDKeypath(info.hdkeypath);
    return batch.WriteKeyMetadata(mapKeyMetadata[pubkey.GetID()], pubkey, true);
}

bool LegacyScriptPubKeyMan::ImportScripts(const std::set<CScript> scripts, int64_t timestamp)
{
    WalletBatch batch(m_storage.GetDatabase());
    for (const auto& entry : scripts) {
        CScriptID id(entry);
        if (HaveCScript(id)) {
            WalletLogPrintf("Already have script %s, skipping\n", HexStr(entry));
            continue;
        }
        if (!AddCScriptWithDB(batch, entry)) {
            return false;
        }

        if (timestamp > 0) {
            m_script_metadata[CScriptID(entry)].nCreateTime = timestamp;
        }
    }
    if (timestamp > 0) {
        UpdateTimeFirstKey(timestamp);
    }

    return true;
}

bool LegacyScriptPubKeyMan::ImportPrivKeys(const std::map<CKeyID, CKey>& privkey_map, const int64_t timestamp)
{
    WalletBatch batch(m_storage.GetDatabase());
    for (const auto& entry : privkey_map) {
        const CKey& key = entry.second;
        CPubKey pubkey = key.GetPubKey();
        const CKeyID& id = entry.first;
        assert(key.VerifyPubKey(pubkey));
        // Skip if we already have the key
        if (HaveKey(id)) {
            WalletLogPrintf("Already have key with pubkey %s, skipping\n", HexStr(pubkey));
            continue;
        }
        mapKeyMetadata[id].nCreateTime = timestamp;
        // If the private key is not present in the wallet, insert it.
        if (!AddKeyPubKeyWithDB(batch, key, pubkey)) {
            return false;
        }
        UpdateTimeFirstKey(timestamp);
    }
    return true;
}

bool LegacyScriptPubKeyMan::ImportPubKeys(const std::vector<CKeyID>& ordered_pubkeys, const std::map<CKeyID, CPubKey>& pubkey_map, const std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>>& key_origins, const bool add_keypool, const KeyPurpose purpose, const int64_t timestamp)
{
    WalletBatch batch(m_storage.GetDatabase());
    for (const auto& entry : key_origins) {
        AddKeyOriginWithDB(batch, entry.second.first, entry.second.second);
    }
    for (const CKeyID& id : ordered_pubkeys) {
        auto entry = pubkey_map.find(id);
        if (entry == pubkey_map.end()) {
            continue;
        }
        const CPubKey& pubkey = entry->second;
        CPubKey temp;
        if (GetPubKey(id, temp)) {
            // Already have pubkey, skipping
            WalletLogPrintf("Already have pubkey %s, skipping\n", HexStr(temp));
            continue;
        }
        if (!AddWatchOnlyWithDB(batch, GetScriptForRawPubKey(pubkey), timestamp)) {
            return false;
        }
        mapKeyMetadata[id].nCreateTime = timestamp;

        // Add to keypool only works with pubkeys
        if (add_keypool) {
            AddKeypoolPubkeyWithDB(pubkey, purpose, batch);
            NotifyCanGetAddressesChanged();
        }
    }
    return true;
}

bool LegacyScriptPubKeyMan::ImportScriptPubKeys(const std::set<GenericAddress>& script_pub_keys, const bool have_solving_data, const int64_t timestamp)
{
    WalletBatch batch(m_storage.GetDatabase());
    for (const GenericAddress& script : script_pub_keys) {
        if (script.IsMWEB()) {
            continue;
        }

        if (!have_solving_data || !IsMine(script)) { // Always call AddWatchOnly for non-solvable watch-only, so that watch timestamp gets updated
            if (!AddWatchOnlyWithDB(batch, script.GetScript(), timestamp)) {
                return false;
            }
        }
    }
    return true;
}

std::set<CKeyID> LegacyScriptPubKeyMan::GetKeys() const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::GetKeys();
    }
    std::set<CKeyID> set_address;
    for (const auto& mi : mapCryptedKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

const std::unordered_set<GenericAddress, SaltedGenericAddressHasher> LegacyScriptPubKeyMan::GetScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<GenericAddress, SaltedGenericAddressHasher> spks;
    std::set<CScriptID> scriptsToIgnore;

    // All keys have at least P2PK and P2PKH
    for (const auto& key_pair : mapKeys) {
        auto metadata = mapKeyMetadata.find(key_pair.first);
        if (metadata != mapKeyMetadata.end()) {
            if (metadata->second.key_origin.hdkeypath.mweb_index.has_value()) {
                scriptsToIgnore.insert(CScriptID(GetScriptForDestination(WitnessV0KeyHash(key_pair.first))));
                continue;
            }
        }

        const CPubKey& pub = key_pair.second.GetPubKey();
        spks.insert(GetScriptForRawPubKey(pub));
        spks.insert(GetScriptForDestination(PKHash(pub)));
    }
    for (const auto& key_pair : mapCryptedKeys) {
        auto metadata = mapKeyMetadata.find(key_pair.first);
        if (metadata != mapKeyMetadata.end()) {
            if (metadata->second.key_origin.hdkeypath.mweb_index.has_value()) {
                scriptsToIgnore.insert(CScriptID(GetScriptForDestination(WitnessV0KeyHash(key_pair.first))));
                continue;
            }
        }

        const CPubKey& pub = key_pair.second.first;
        spks.insert(GetScriptForRawPubKey(pub));
        spks.insert(GetScriptForDestination(PKHash(pub)));
    }

    // For every script in mapScript, only the ISMINE_SPENDABLE ones are being tracked.
    // The watchonly ones will be in setWatchOnly which we deal with later
    // For all keys, if they have segwit scripts, those scripts will end up in mapScripts
    for (const auto& script_pair : mapScripts) {
        if (scriptsToIgnore.count(script_pair.first) != 0) {
            LogPrintf("DEBUG: Ignoring MWEB script_id\n");
            continue;
        }
        const CScript& script = script_pair.second;
        if (IsMine(script) == ISMINE_SPENDABLE) {
            // Add ScriptHash for scripts that are not already P2SH
            if (!script.IsPayToScriptHash()) {
                spks.insert(GetScriptForDestination(ScriptHash(script)));
            }
            // For segwit scripts, we only consider them spendable if we have the segwit spk
            int wit_ver = -1;
            std::vector<unsigned char> witprog;
            if (script.IsWitnessProgram(wit_ver, witprog) && wit_ver == 0) {
                spks.insert(script);
            }
        } else {
            // Multisigs are special. They don't show up as ISMINE_SPENDABLE unless they are in a P2SH
            // So check the P2SH of a multisig to see if we should insert it
            std::vector<std::vector<unsigned char>> sols;
            TxoutType type = Solver(script, sols);
            if (type == TxoutType::MULTISIG) {
                CScript ms_spk = GetScriptForDestination(ScriptHash(script));
                if (IsMine(ms_spk) != ISMINE_NO) {
                    spks.insert(ms_spk);
                }
            }
        }
    }

    // All watchonly scripts are raw
    spks.insert(setWatchOnly.begin(), setWatchOnly.end());

    return spks;
}

//std::unique_ptr<DescriptorScriptPubKeyMan> LegacyScriptPubKeyMan::MigrateToDescriptor(const CHDChain& chain, const KeyPurpose purpose)
//{
//    if (chain.seed_id.IsNull()) {
//        return nullptr;
//    }
//
//    if (purpose != KeyPurpose::EXTERNAL && !m_storage.CanSupportFeature(FEATURE_HD_SPLIT)) {
//        return nullptr;
//    }
//
//    if (purpose == KeyPurpose::MWEB && !m_storage.CanSupportFeature(FEATURE_MWEB)) {
//        return nullptr;
//    }
//
//    // Get the master xprv
//    CKey seed_key;
//    if (!GetKey(chain.seed_id, seed_key)) {
//        assert(false);
//    }
//    CExtKey master_key;
//    master_key.SetSeed(seed_key);
//
//    // Make the combo descriptor
//    std::string xpub = EncodeExtPubKey(master_key.Neuter());
//    std::string desc_str = "combo(" + xpub + "/0'/" + ToString(purpose) + "'/*')";
//    FlatSigningProvider keys;
//    std::string error;
//    std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
//    uint32_t chain_counter = std::max(GetChainCounter(chain, purpose), (uint32_t)0);
//    WalletDescriptor w_desc(std::move(desc), 0, 0, chain_counter, 0);
//
//    // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
//    auto desc_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(m_storage, w_desc));
//    desc_spk_man->AddDescriptorKey(master_key.key, master_key.key.GetPubKey());
//    desc_spk_man->TopUp();
//
//    return desc_spk_man;
//}

std::optional<MigrationData> LegacyScriptPubKeyMan::MigrateToDescriptor()
{
    LOCK(cs_KeyStore);
    if (m_storage.IsLocked()) {
        return std::nullopt;
    }

    MigrationData out;

    std::unordered_set<GenericAddress, SaltedGenericAddressHasher> spks{GetScriptPubKeys()};

    // Get all key ids
    std::set<CKeyID> keyids;
    for (const auto& key_pair : mapKeys) {
        keyids.insert(key_pair.first);
    }
    for (const auto& key_pair : mapCryptedKeys) {
        keyids.insert(key_pair.first);
    }

    LogPrintf("keyids.size() == %u, spks.size() == %u\n", keyids.size(), spks.size());

    // Get key metadata and figure out which keys don't have a seed
    // Note that we do not ignore the seeds themselves because they are considered IsMine!
    for (auto keyid_it = keyids.begin(); keyid_it != keyids.end();) {
        const CKeyID& keyid = *keyid_it;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            const CKeyMetadata& meta = it->second;
            if (meta.hdKeypath == "s" || meta.hdKeypath == "m") {
                keyid_it++;
                continue;
            }
            if (m_hd_chain.seed_id == meta.hd_seed_id || m_inactive_hd_chains.count(meta.hd_seed_id) > 0) {
                keyid_it = keyids.erase(keyid_it);
                continue;
            }
        }
        keyid_it++;
    }

    // keyids is now all non-HD keys. Each key will have its own combo descriptor
    for (const CKeyID& keyid : keyids) {
        CKey key;
        if (!GetKey(keyid, key)) {
            assert(false);
        }

        // Get birthdate from key meta
        uint64_t creation_time = 0;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // Get the key origin
        // Maybe this doesn't matter because floating keys here shouldn't have origins
        KeyOriginInfo info;
        bool has_info = GetKeyOrigin(keyid, info);
        std::string origin_str = has_info ? "[" + HexStr(info.fingerprint) + FormatHDKeypath(info.hdkeypath) + "]" : "";

        // Construct the combo descriptor
        std::string desc_str = "combo(" + origin_str + HexStr(key.GetPubKey()) + ")";
        FlatSigningProvider keys;
        std::string error;
        std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
        WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);

        // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
        auto desc_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(m_storage, w_desc));
        desc_spk_man->AddDescriptorKey(key, key.GetPubKey());
        desc_spk_man->TopUp();
        auto desc_spks = desc_spk_man->GetScriptPubKeys();

        // Remove the scriptPubKeys from our current set
        for (const GenericAddress& spk : desc_spks) {
            size_t erased = spks.erase(spk);
            assert(erased == 1);
            assert(IsMine(spk) == ISMINE_SPENDABLE);
        }

        out.desc_spkms.push_back(std::move(desc_spk_man));
    }

    // Handle HD keys by using the CHDChains
    std::vector<CHDChain> chains;
    chains.push_back(m_hd_chain);
    for (const auto& chain_pair : m_inactive_hd_chains) {
        chains.push_back(chain_pair.second);
    }
    LogPrintf("DEBUG: Chains=%u\n", chains.size());
    for (const CHDChain& chain : chains) {
        LogPrintf("DEBUG: Chain counters - %u external, %u internal, %u MWEB\n", chain.nExternalChainCounter, chain.nInternalChainCounter, chain.nMWEBIndexCounter);
        //for (const KeyPurpose purpose : std::vector<KeyPurpose>{ KeyPurpose::EXTERNAL, KeyPurpose::INTERNAL, KeyPurpose::MWEB}) {
        //    auto desc_spk_man = MigrateToDescriptor(chain, purpose);
        //    if (desc_spk_man != nullptr) {
        //        auto desc_spks = desc_spk_man->GetScriptPubKeys();

        //        // Remove the scriptPubKeys from our current set
        //        for (const GenericAddress& spk : desc_spks) {
        //            size_t erased = spks.erase(spk);
        //            assert(erased == 1);
        //            assert(IsMine(spk) == ISMINE_SPENDABLE);
        //        }

        //        out.desc_spkms.push_back(std::move(desc_spk_man));
        //    }
        //}

        for (int i = 0; i < 2; ++i) {
            // Skip if doing internal chain and split chain is not supported
            if (chain.seed_id.IsNull() || (i == 1 && !m_storage.CanSupportFeature(FEATURE_HD_SPLIT))) {
                continue;
            }
            // Get the master xprv
            CKey seed_key;
            if (!GetKey(chain.seed_id, seed_key)) {
                assert(false);
            }
            CExtKey master_key;
            master_key.SetSeed(seed_key);

            // Make the combo descriptor
            std::string xpub = EncodeExtPubKey(master_key.Neuter());
            std::string desc_str = "combo(" + xpub + "/0'/" + ToString(i) + "'/*')";
            FlatSigningProvider keys;
            std::string error;
            std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
            uint32_t chain_counter = std::max((i == 1 ? chain.nInternalChainCounter : chain.nExternalChainCounter), (uint32_t)0);
            WalletDescriptor w_desc(std::move(desc), 0, 0, chain_counter, 0);

            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            auto desc_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(m_storage, w_desc));
            desc_spk_man->AddDescriptorKey(master_key.key, master_key.key.GetPubKey());
            desc_spk_man->TopUp();
            auto desc_spks = desc_spk_man->GetScriptPubKeys();

            // Remove the scriptPubKeys from our current set
            for (const GenericAddress& spk : desc_spks) {
                size_t erased = spks.erase(spk);
                assert(erased == 1);
                assert(IsMine(spk) == ISMINE_SPENDABLE);
            }

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // MW: TODO - Remove MWEB pubkeys from spks

    }
    // Add the current master seed to the migration data
    if (!m_hd_chain.seed_id.IsNull()) {
        CKey seed_key;
        if (!GetKey(m_hd_chain.seed_id, seed_key)) {
            assert(false);
        }
        out.master_key.SetSeed(seed_key);
    }

    LogPrintf("DEBUG: Keys remaining in spks: %u\n", spks.size());

    // Handle the rest of the scriptPubKeys which must be imports and may not have all info
    for (auto it = spks.begin(); it != spks.end();) {
        const GenericAddress& spk = *it;
        LogPrintf("DEBUG: SPK: %s, %s\n", spk.Encode(), CScriptID(spk.GetScript()).ToString());

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& mit = m_script_metadata.find(CScriptID(spk.GetScript()));
        if (mit != m_script_metadata.end()) {
            LogPrintf("DEBUG: origin=%s\n", FormatHDKeypath(mit->second.key_origin.hdkeypath));
            if (mit->second.key_origin.hdkeypath.mweb_index.has_value()) {
                LogPrintf("DEBUG: Erasing MWEB key\n");
                it = spks.erase(it);
                continue;
            }

            creation_time = mit->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(spk, *GetSolvingProvider(spk));
        LogPrintf("DEBUG: Descriptor=%s, address=%s\n", desc->ToString(), spk.Encode());
        // Get the private keys for this descriptor
        std::vector<GenericAddress> scripts;
        FlatSigningProvider keys;
        if (!desc->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, keys)) {
            assert(false);
        }
        std::set<CKeyID> privkeyids;
        for (const auto& key_orig_pair : keys.origins) {
            privkeyids.insert(key_orig_pair.first);
        }

        std::vector<GenericAddress> desc_spks;

        // Make the descriptor string with private keys
        std::string desc_str;
        bool watchonly = !desc->ToPrivateString(*this, desc_str);
        if (watchonly && !m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            out.watch_descs.push_back({desc->ToString(), creation_time});

            // Get the scriptPubKeys without writing this to the wallet
            FlatSigningProvider provider;
            desc->Expand(0, provider, desc_spks, provider);
        } else {
            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
            auto desc_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(m_storage, w_desc));
            for (const auto& keyid : privkeyids) {
                CKey key;
                if (!GetKey(keyid, key)) {
                    continue;
                }
                desc_spk_man->AddDescriptorKey(key, key.GetPubKey());
            }
            desc_spk_man->TopUp();
            auto desc_spks_set = desc_spk_man->GetScriptPubKeys();
            desc_spks.insert(desc_spks.end(), desc_spks_set.begin(), desc_spks_set.end());

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // Remove the scriptPubKeys from our current set
        for (const GenericAddress& desc_spk : desc_spks) {
            auto del_it = spks.find(desc_spk);
            assert(del_it != spks.end());
            assert(IsMine(desc_spk) != ISMINE_NO);
            it = spks.erase(del_it);
        }
    }

    // Multisigs are special. They don't show up as ISMINE_SPENDABLE unless they are in a P2SH
    // So we have to check if any of our scripts are a multisig and if so, add the P2SH
    for (const auto& script_pair : mapScripts) {
        const CScript script = script_pair.second;

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& it = m_script_metadata.find(CScriptID(script));
        if (it != m_script_metadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        std::vector<std::vector<unsigned char>> sols;
        TxoutType type = Solver(script, sols);
        if (type == TxoutType::MULTISIG) {
            CScript sh_spk = GetScriptForDestination(ScriptHash(script));
            CTxDestination witdest = WitnessV0ScriptHash(script);
            CScript witprog = GetScriptForDestination(witdest);
            CScript sh_wsh_spk = GetScriptForDestination(ScriptHash(witprog));

            // We only want the multisigs that we have not already seen, i.e. they are not watchonly and not spendable
            // For P2SH, a multisig is not ISMINE_NO when:
            // * All keys are in the wallet
            // * The multisig itself is watch only
            // * The P2SH is watch only
            // For P2SH-P2WSH, if the script is in the wallet, then it will have the same conditions as P2SH.
            // For P2WSH, a multisig is not ISMINE_NO when, other than the P2SH conditions:
            // * The P2WSH script is in the wallet and it is being watched
            std::vector<std::vector<unsigned char>> keys(sols.begin() + 1, sols.begin() + sols.size() - 1);
            if (HaveWatchOnly(sh_spk) || HaveWatchOnly(script) || HaveKeys(keys, *this) || (HaveCScript(CScriptID(witprog)) && HaveWatchOnly(witprog))) {
                // The above emulates IsMine for these 3 scriptPubKeys, so double check that by running IsMine
                assert(IsMine(sh_spk) != ISMINE_NO || IsMine(witprog) != ISMINE_NO || IsMine(sh_wsh_spk) != ISMINE_NO);
                continue;
            }
            assert(IsMine(sh_spk) == ISMINE_NO && IsMine(witprog) == ISMINE_NO && IsMine(sh_wsh_spk) == ISMINE_NO);

            std::unique_ptr<Descriptor> sh_desc = InferDescriptor(sh_spk, *GetSolvingProvider(sh_spk));
            out.solvable_descs.push_back({sh_desc->ToString(), creation_time});

            const auto desc = InferDescriptor(witprog, *this);
            if (desc->IsSolvable()) {
                std::unique_ptr<Descriptor> wsh_desc = InferDescriptor(witprog, *GetSolvingProvider(witprog));
                out.solvable_descs.push_back({wsh_desc->ToString(), creation_time});
                std::unique_ptr<Descriptor> sh_wsh_desc = InferDescriptor(sh_wsh_spk, *GetSolvingProvider(sh_wsh_spk));
                out.solvable_descs.push_back({sh_wsh_desc->ToString(), creation_time});
            }
        }
    }

    // Make sure that we have accounted for all scriptPubKeys
    assert(spks.size() == 0);
    return out;
}

bool LegacyScriptPubKeyMan::DeleteRecords()
{
    LOCK(cs_KeyStore);
    WalletBatch batch(m_storage.GetDatabase());
    return batch.EraseRecords(DBKeys::LEGACY_TYPES);
}

void LegacyScriptPubKeyMan::LoadMWEBKeychain()
{
    if (!m_storage.CanSupportFeature(FEATURE_HD_SPLIT)) {
        return;
    }

    if (m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) || m_storage.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
        return;
    }

    m_storage.SetMinVersion(FEATURE_MWEB);

    // try to get the seed
    CKey seed;
    if (!GetKey(m_hd_chain.seed_id, seed)) {
        if (m_hd_chain.mweb_scan_key) {
            // MW: TODO - Include m_hd_chain.mweb_spend_pubkey?
            m_mwebKeychain = std::make_shared<mw::Keychain>(this, *m_hd_chain.mweb_scan_key);
        }

        return;
    }

    CExtKey masterKey;
    masterKey.SetSeed(seed);

    // derive m/0'
    CExtKey accountKey;
    DeriveExtKey(masterKey, BIP32_HARDENED_KEY_LIMIT, accountKey);

    // derive m/0'/100' (MWEB)
    CExtKey chainChildKey;
    DeriveExtKey(accountKey, BIP32_HARDENED_KEY_LIMIT + (uint32_t)KeyPurpose::MWEB, chainChildKey);

    CExtKey scanKey;
    DeriveExtKey(chainChildKey, BIP32_HARDENED_KEY_LIMIT, scanKey);

    CExtKey spendKey;
    DeriveExtKey(chainChildKey, BIP32_HARDENED_KEY_LIMIT + 1, spendKey);

    m_hd_chain.nVersion = std::max(m_hd_chain.nVersion, CHDChain::VERSION_HD_MWEB_WATCH);
    m_mwebKeychain = std::make_shared<mw::Keychain>(
        this,
        SecretKey(scanKey.key.begin()),
        SecretKey(spendKey.key.begin())
    );

    WalletBatch batch(m_storage.GetDatabase());
    // Add the MWEB scan key to the CHDChain
    if (!m_hd_chain.mweb_scan_key) { // MW: TODO - || !m_hd_chain.mweb_spend_pubkey) {
        m_hd_chain.mweb_scan_key = SecretKey(scanKey.key.begin());
        // MW: TODO - m_hd_chain.mweb_spend_pubkey = PublicKey(spendKey.key.GetPubKey().begin());

        if (!batch.WriteHDChain(m_hd_chain)) {
            throw std::runtime_error(std::string(__func__) + ": writing chain failed");
        }
    }

    // Mark change and peg-in addresses as used
    if (m_hd_chain.nMWEBIndexCounter == 0) {
        // Generate CHANGE pubkey
        GenerateNewKey(batch, m_hd_chain, KeyPurpose::MWEB);

        // Generate PEGIN pubkey
        GenerateNewKey(batch, m_hd_chain, KeyPurpose::MWEB);
    }
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    // Returns true if this descriptor supports getting new addresses. Conditions where we may be unable to fetch them (e.g. locked) are caught later
    if (!CanGetAddresses(KeyPurpose::EXTERNAL)) {
        return util::Error{_("No addresses available")};
    }
    {
        LOCK(cs_desc_man);
        assert(m_wallet_descriptor.descriptor->IsSingleType()); // This is a combo descriptor which should not be an active descriptor
        std::optional<OutputType> desc_addr_type = m_wallet_descriptor.descriptor->GetOutputType();
        assert(desc_addr_type);
        if (type != *desc_addr_type) {
            throw std::runtime_error(std::string(__func__) + ": Types are inconsistent");
        }

        TopUp();

        // Get the scriptPubKey from the descriptor
        FlatSigningProvider out_keys;
        std::vector<GenericAddress> addresses_temp;
        if (m_wallet_descriptor.range_end <= m_max_cached_index && !TopUp(1)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, addresses_temp, out_keys)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }

        CTxDestination dest;
        if (!addresses_temp[0].ExtractDestination(dest)) {
            return util::Error{_("Error: Cannot extract destination from the generated scriptpubkey")}; // shouldn't happen
        }
        m_wallet_descriptor.next_index++;
        WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
        return dest;
    }
}

isminetype DescriptorScriptPubKeyMan::IsMine(const GenericAddress& script) const
{
    LOCK(cs_desc_man);
    if (m_map_addresses.count(script) > 0) {
        return ISMINE_SPENDABLE;
    }
    return ISMINE_NO;
}

bool DescriptorScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key, bool accept_no_keys)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    bool keyPass = m_map_crypted_keys.empty(); // Always pass when there are no encrypted keys
    bool keyFail = false;
    for (const auto& mi : m_map_crypted_keys) {
        const CPubKey &pubkey = mi.second.first;
        const std::vector<unsigned char> &crypted_secret = mi.second.second;
        CKey key;
        if (!DecryptKey(master_key, crypted_secret, pubkey, key)) {
            keyFail = true;
            break;
        }
        keyPass = true;
        if (m_decryption_thoroughly_checked)
            break;
    }
    if (keyPass && keyFail) {
        LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
        throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
    }
    if (keyFail || (!keyPass && !accept_no_keys)) {
        return false;
    }
    m_decryption_thoroughly_checked = true;
    return true;
}

bool DescriptorScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_desc_man);
    if (!m_map_crypted_keys.empty()) {
        return false;
    }

    for (const KeyMap::value_type& key_in : m_map_keys)
    {
        const CKey &key = key_in.second;
        CPubKey pubkey = key.GetPubKey();
        CKeyingMaterial secret(key.begin(), key.end());
        std::vector<unsigned char> crypted_secret;
        if (!EncryptSecret(master_key, secret, pubkey.GetHash(), crypted_secret)) {
            return false;
        }
        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        batch->WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    }
    m_map_keys.clear();
    return true;
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, int64_t& index, CKeyPool& keypool)
{
    LOCK(cs_desc_man);
    auto op_dest = GetNewDestination(type);
    index = m_wallet_descriptor.next_index - 1;
    return op_dest;
}

void DescriptorScriptPubKeyMan::ReturnDestination(int64_t index, const KeyPurpose purpose, const CTxDestination& addr)
{
    LOCK(cs_desc_man);
    // Only return when the index was the most recent
    if (m_wallet_descriptor.next_index - 1 == index) {
        m_wallet_descriptor.next_index--;
    }
    WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
    NotifyCanGetAddressesChanged();
}

std::map<CKeyID, CKey> DescriptorScriptPubKeyMan::GetKeys() const
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.HasEncryptionKeys() && !m_storage.IsLocked()) {
        KeyMap keys;
        for (const auto& key_pair : m_map_crypted_keys) {
            const CPubKey& pubkey = key_pair.second.first;
            const std::vector<unsigned char>& crypted_secret = key_pair.second.second;
            CKey key;
            DecryptKey(m_storage.GetEncryptionKey(), crypted_secret, pubkey, key);
            keys[pubkey.GetID()] = key;
        }
        return keys;
    }
    return m_map_keys;
}

bool DescriptorScriptPubKeyMan::TopUp(unsigned int size)
{
    LOCK(cs_desc_man);
    unsigned int target_size;
    if (size > 0) {
        target_size = size;
    } else {
        target_size = std::max(gArgs.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 1);
    }

    // Calculate the new range_end
    int32_t new_range_end = std::max(m_wallet_descriptor.next_index + (int32_t)target_size, m_wallet_descriptor.range_end);

    // If the descriptor is not ranged, we actually just want to fill the first cache item
    if (!m_wallet_descriptor.descriptor->IsRange()) {
        new_range_end = 1;
        m_wallet_descriptor.range_end = 1;
        m_wallet_descriptor.range_start = 0;
    }

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    WalletBatch batch(m_storage.GetDatabase());
    uint256 id = GetID();
    for (int32_t i = m_max_cached_index + 1; i < new_range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<GenericAddress> addresses_temp;
        DescriptorCache temp_cache;
        // Maybe we have a cached xpub and we can expand from the cache first
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, addresses_temp, out_keys)) {
            if (!m_wallet_descriptor.descriptor->Expand(i, provider, addresses_temp, out_keys, &temp_cache)) return false;
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        for (const GenericAddress& address : addresses_temp) {
            m_map_addresses[address] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and it's private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        // Merge and write the cache
        DescriptorCache new_items = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
        if (!batch.WriteDescriptorCacheItems(id, new_items)) {
            throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
        }
        m_max_cached_index++;
    }
    m_wallet_descriptor.range_end = new_range_end;
    batch.WriteDescriptor(GetID(), m_wallet_descriptor);

    // By this point, the cache size should be the size of the entire range
    assert(m_wallet_descriptor.range_end - 1 == m_max_cached_index);

    NotifyCanGetAddressesChanged();
    return true;
}

std::vector<WalletDestination> DescriptorScriptPubKeyMan::MarkUnusedAddresses(const GenericAddress& address)
{
    LOCK(cs_desc_man);
    std::vector<WalletDestination> result;
    if (IsMine(address)) {
        int32_t index = m_map_addresses[address];
        if (index >= m_wallet_descriptor.next_index) {
            WalletLogPrintf("%s: Detected a used keypool item at index %d, mark all keypool items up to this item as used\n", __func__, index);
            auto out_keys = std::make_unique<FlatSigningProvider>();
            std::vector<GenericAddress> scripts_temp;
            while (index >= m_wallet_descriptor.next_index) {
                if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) {
                    throw std::runtime_error(std::string(__func__) + ": Unable to expand descriptor from cache");
                }
                CTxDestination dest;
                scripts_temp[0].ExtractDestination(dest);
                result.push_back({dest, std::nullopt});
                m_wallet_descriptor.next_index++;
            }
        }
        if (!TopUp()) {
            WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
        }
    }

    return result;
}

void DescriptorScriptPubKeyMan::AddDescriptorKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!AddDescriptorKeyWithDB(batch, key, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor private key failed");
    }
}

bool DescriptorScriptPubKeyMan::AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey)
{
    AssertLockHeld(cs_desc_man);
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // Check if provided key already exists
    if (m_map_keys.find(pubkey.GetID()) != m_map_keys.end() ||
        m_map_crypted_keys.find(pubkey.GetID()) != m_map_crypted_keys.end()) {
        return true;
    }

    if (m_storage.HasEncryptionKeys()) {
        if (m_storage.IsLocked()) {
            return false;
        }

        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret(key.begin(), key.end());
        if (!EncryptSecret(m_storage.GetEncryptionKey(), secret, pubkey.GetHash(), crypted_secret)) {
            return false;
        }

        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        return batch.WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    } else {
        m_map_keys[pubkey.GetID()] = key;
        return batch.WriteDescriptorKey(GetID(), pubkey, key.GetPrivKey());
    }
}

bool DescriptorScriptPubKeyMan::SetupDescriptorGeneration(const CExtKey& master_key, OutputType addr_type, const bool internal)
{
    LOCK(cs_desc_man);
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    // Ignore when there is already a descriptor
    if (m_wallet_descriptor.descriptor) {
        return false;
    }

    int64_t creation_time = GetTime();

    std::string xpub = EncodeExtPubKey(master_key.Neuter());

    // Build descriptor string
    std::string desc_prefix;
    std::string desc_suffix = "/*)";
    switch (addr_type) {
    case OutputType::LEGACY: {
        desc_prefix = "pkh(" + xpub + "/44'";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_prefix = "sh(wpkh(" + xpub + "/49'";
        desc_suffix += ")";
        break;
    }
    case OutputType::BECH32: {
        desc_prefix = "wpkh(" + xpub + "/84'";
        break;
    }
    case OutputType::BECH32M: {
        desc_prefix = "tr(" + xpub  + "/86'";
        break;
    }
    case OutputType::MWEB: {
        if (internal) return false;
        desc_prefix = "mweb(" + xpub + "/100'";
        desc_suffix = "/*')";
        break;
    }
    case OutputType::UNKNOWN: {
        // We should never have a DescriptorScriptPubKeyMan for an UNKNOWN OutputType,
        // so if we get to this point something is wrong
        assert(false);
    }
    } // no default case, so the compiler can warn about missing cases
    assert(!desc_prefix.empty());

    // Mainnet derives at 2', testnet and regtest derive at 1'
    if (Params().IsTestChain()) {
        desc_prefix += "/1'";
    } else {
        desc_prefix += "/2'";
    }

    std::string internal_path = internal ? "/1" : "/0";
    std::string desc_str = desc_prefix + "/0'" + internal_path + desc_suffix;
    if (addr_type == OutputType::MWEB) {
        // MWEB addresses must follow the same paths as legacy wallets,
        // to avoid the need to check outputs against multiple scan keys
        desc_str = "mweb(" + xpub + "/0'/100'/*)"; // MW: TODO - Needs to support "mweb(<xpub>/0'/100'/x)"
    }

    // Make the descriptor
    FlatSigningProvider keys;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
    WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
    m_wallet_descriptor = w_desc;
    uint256 id = GetID();

    // Store the master private key, and descriptor
    WalletBatch batch(m_storage.GetDatabase());
    if (!AddDescriptorKeyWithDB(batch, master_key.key, master_key.key.GetPubKey())) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor master private key failed");
    }
    if (!batch.WriteDescriptor(id, m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    if (addr_type == OutputType::MWEB) {
        DescriptorCache temp_cache;
        std::vector<GenericAddress> tmp_addresses;
        keys.keys.emplace(master_key.key.GetPubKey().GetID(), master_key.key);

        // derive m/0'
        CExtKey account_key;
        DeriveExtKey(master_key, BIP32_HARDENED_KEY_LIMIT, account_key);

        // derive m/0'/100' (MWEB)
        CExtKey purpose_key;
        DeriveExtKey(account_key, BIP32_HARDENED_KEY_LIMIT + (uint32_t)KeyPurpose::MWEB, purpose_key);

        CExtKey scan_key;
        DeriveExtKey(purpose_key, BIP32_HARDENED_KEY_LIMIT, scan_key);
        temp_cache.CacheMWEBMasterScanKey(SecretKey(scan_key.key.begin()));
        keys.keys.emplace(scan_key.key.GetPubKey().GetID(), scan_key.key);

        if (!AddDescriptorKeyWithDB(batch, scan_key.key, scan_key.key.GetPubKey())) {
            throw std::runtime_error(std::string(__func__) + ": writing descriptor master scan key failed");
        }

        CExtKey spend_key;
        DeriveExtKey(purpose_key, BIP32_HARDENED_KEY_LIMIT + 1, spend_key);
        temp_cache.CacheMWEBMasterSpendPubKey(PublicKey(spend_key.key.GetPubKey().begin()));
        keys.keys.emplace(spend_key.key.GetPubKey().GetID(), spend_key.key);

        if (!AddDescriptorKeyWithDB(batch, spend_key.key, spend_key.key.GetPubKey())) {
            throw std::runtime_error(std::string(__func__) + ": writing descriptor master spend key failed");
        }

        // Merge and write the cache
        DescriptorCache new_items = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
        if (!batch.WriteDescriptorCacheItems(id, new_items)) {
            throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
        }

        LoadMWEBKeychain();
    }

    // TopUp
    TopUp();

    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

bool DescriptorScriptPubKeyMan::IsHDEnabled() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.descriptor->IsRange();
}

bool DescriptorScriptPubKeyMan::CanGetAddresses(const KeyPurpose /*purpose*/) const
{
    // We can only give out addresses from descriptors that are single type (not combo), ranged,
    // and either have cached keys or can generate more keys (ignoring encryption)
    LOCK(cs_desc_man);
    return m_wallet_descriptor.descriptor->IsSingleType() &&
           m_wallet_descriptor.descriptor->IsRange() &&
           (HavePrivateKeys() || m_wallet_descriptor.next_index < m_wallet_descriptor.range_end);
}

bool DescriptorScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_desc_man);
    return m_map_keys.size() > 0 || m_map_crypted_keys.size() > 0;
}

bool DescriptorScriptPubKeyMan::GetKey(const CKeyID& address, CKey& keyOut) const
{
    LOCK(cs_desc_man);
    auto keys = GetKeys();
    auto it = keys.find(address);
    if (it == keys.end()) return false;
    keyOut = it->second;
    return true;
}

std::optional<int64_t> DescriptorScriptPubKeyMan::GetOldestKeyPoolTime() const
{
    // This is only used for getwalletinfo output and isn't relevant to descriptor wallets.
    return std::nullopt;
}


unsigned int DescriptorScriptPubKeyMan::GetKeyPoolSize() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.range_end - m_wallet_descriptor.next_index;
}

int64_t DescriptorScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.creation_time;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const GenericAddress& script, bool include_private) const
{
    LOCK(cs_desc_man);

    // Find the index of the script
    auto it = m_map_addresses.find(script);
    if (it == m_map_addresses.end()) {
        return nullptr;
    }
    int32_t index = it->second;

    return GetSigningProvider(index, include_private);
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CPubKey& pubkey) const
{
    LOCK(cs_desc_man);

    // Find index of the pubkey
    auto it = m_map_pubkeys.find(pubkey);
    if (it == m_map_pubkeys.end()) {
        return nullptr;
    }
    int32_t index = it->second;

    // Always try to get the signing provider with private keys. This function should only be called during signing anyways
    return GetSigningProvider(index, true);
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(int32_t index, bool include_private) const
{
    AssertLockHeld(cs_desc_man);

    std::unique_ptr<FlatSigningProvider> out_keys = std::make_unique<FlatSigningProvider>();

    // Fetch SigningProvider from cache to avoid re-deriving
    auto it = m_map_signing_providers.find(index);
    if (it != m_map_signing_providers.end()) {
        out_keys->Merge(FlatSigningProvider{it->second});
    } else {
        // Get the scripts, keys, and key origins for this script
        std::vector<GenericAddress> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) return nullptr;

        // Cache SigningProvider so we don't need to re-derive if we need this SigningProvider again
        m_map_signing_providers[index] = *out_keys;
    }

    if (HavePrivateKeys() && include_private) {
        FlatSigningProvider master_provider;
        master_provider.keys = GetKeys();
        m_wallet_descriptor.descriptor->ExpandPrivate(index, master_provider, *out_keys);
    }

    return out_keys;
}

std::unique_ptr<SigningProvider> DescriptorScriptPubKeyMan::GetSolvingProvider(const GenericAddress& dest_addr) const
{
    return GetSigningProvider(dest_addr, false);
}

bool DescriptorScriptPubKeyMan::CanProvide(const GenericAddress& dest_addr, SignatureData& sigdata)
{
    return IsMine(dest_addr);
}

bool DescriptorScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<GenericOutputID, GenericCoin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    for (const auto& coin_pair : coins) {
        if (coin_pair.second.IsMWEB()) {
            // MW: TODO - Get signing provider
            continue;
        }
        std::unique_ptr<FlatSigningProvider> coin_keys = GetSigningProvider(coin_pair.second.ToLTC().out.scriptPubKey, true);
        if (!coin_keys) {
            continue;
        }
        keys->Merge(std::move(*coin_keys));
    }

    return ::SignTransaction(tx, keys.get(), coins, sighash, input_errors);
}

SigningResult DescriptorScriptPubKeyMan::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(GetScriptForDestination(pkhash), true);
    if (!keys) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    CKey key;
    if (!keys->GetKey(ToKeyID(pkhash), key)) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    if (!MessageSign(key, message, str_sig)) {
        return SigningResult::SIGNING_FAILED;
    }
    return SigningResult::OK;
}

TransactionError DescriptorScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbtx, const PrecomputedTransactionData& txdata, int sighash_type, bool sign, bool bip32derivs, int* n_signed, bool finalize) const
{
    if (n_signed) {
        *n_signed = 0;
    }

    // MW: TODO - if sign == true, sign MWEB components here?
    if (sign) {
        PSBTSignMWEBTx(FlatSigningProvider(), psbtx);
    }

    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // Get the Sighash type
        if (sign && input.sighash_type != std::nullopt && *input.sighash_type != sighash_type) {
            return TransactionError::SIGHASH_MISMATCH;
        }

        // Get the scriptPubKey to know which SigningProvider to use
        CScript script;
        if (!input.witness_utxo.IsNull()) {
            script = input.witness_utxo.scriptPubKey;
        } else if (input.non_witness_utxo) {
            if (*input.prev_out >= input.non_witness_utxo->vout.size()) {
                return TransactionError::MISSING_INPUTS;
            }
            script = input.non_witness_utxo->vout[*input.prev_out].scriptPubKey;
        } else {
            // There's no UTXO so we can just skip this now
            continue;
        }
        SignatureData sigdata;
        input.FillSignatureData(sigdata);

        std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
        std::unique_ptr<FlatSigningProvider> script_keys = GetSigningProvider(script, sign);
        if (script_keys) {
            keys->Merge(std::move(*script_keys));
        } else {
            // Maybe there are pubkeys listed that we can sign for
            std::vector<CPubKey> pubkeys;

            // ECDSA Pubkeys
            for (const auto& [pk, _] : input.hd_keypaths) {
                pubkeys.push_back(pk);
            }

            // Taproot output pubkey
            std::vector<std::vector<unsigned char>> sols;
            if (Solver(script, sols) == TxoutType::WITNESS_V1_TAPROOT) {
                sols[0].insert(sols[0].begin(), 0x02);
                pubkeys.emplace_back(sols[0]);
                sols[0][0] = 0x03;
                pubkeys.emplace_back(sols[0]);
            }

            // Taproot pubkeys
            for (const auto& pk_pair : input.m_tap_bip32_paths) {
                const XOnlyPubKey& pubkey = pk_pair.first;
                for (unsigned char prefix : {0x02, 0x03}) {
                    unsigned char b[33] = {prefix};
                    std::copy(pubkey.begin(), pubkey.end(), b + 1);
                    CPubKey fullpubkey;
                    fullpubkey.Set(b, b + 33);
                    pubkeys.push_back(fullpubkey);
                }
            }

            for (const auto& pubkey : pubkeys) {
                std::unique_ptr<FlatSigningProvider> pk_keys = GetSigningProvider(pubkey);
                if (pk_keys) {
                    keys->Merge(std::move(*pk_keys));
                }
            }
        }

        SignPSBTInput(HidingSigningProvider(keys.get(), !sign, !bip32derivs), psbtx, i, &txdata, sighash_type, nullptr, finalize);

        bool signed_one = PSBTInputSigned(input);
        if (n_signed && (signed_one || !sign)) {
            // If sign is false, we assume that we _could_ sign if we get here. This
            // will never have false negatives; it is hard to tell under what i
            // circumstances it could have false positives.
            (*n_signed)++;
        }
    }

    // Fill in the bip32 keypaths and redeemscripts for the outputs so that hardware wallets can identify change
    for (unsigned int i = 0; i < psbtx.outputs.size(); ++i) {
        if (!psbtx.outputs.at(i).script.has_value()) {
            continue;
        }
        std::unique_ptr<SigningProvider> keys = GetSolvingProvider(*psbtx.outputs.at(i).script);
        if (!keys) {
            continue;
        }
        UpdatePSBTOutput(HidingSigningProvider(keys.get(), true, !bip32derivs), psbtx, i);
    }

    return TransactionError::OK;
}

std::unique_ptr<CKeyMetadata> DescriptorScriptPubKeyMan::GetMetadata(const CTxDestination& dest) const
{
    std::unique_ptr<SigningProvider> provider = GetSigningProvider(dest);
    if (provider) {
        KeyOriginInfo orig;
        CKeyID key_id = GetKeyForDestination(*provider, dest);
        if (provider->GetKeyOrigin(key_id, orig)) {
            LOCK(cs_desc_man);
            std::unique_ptr<CKeyMetadata> meta = std::make_unique<CKeyMetadata>();
            meta->key_origin = orig;
            meta->has_key_origin = true;
            meta->nCreateTime = m_wallet_descriptor.creation_time;
            return meta;
        }
    }
    return nullptr;
}

uint256 DescriptorScriptPubKeyMan::GetID() const
{
    LOCK(cs_desc_man);
    std::string desc_str = m_wallet_descriptor.descriptor->ToString();
    uint256 id;
    CSHA256().Write((unsigned char*)desc_str.data(), desc_str.size()).Finalize(id.begin());
    return id;
}

void DescriptorScriptPubKeyMan::SetCache(const DescriptorCache& cache)
{
    LOCK(cs_desc_man);
    m_wallet_descriptor.cache = cache;
    for (int32_t i = m_wallet_descriptor.range_start; i < m_wallet_descriptor.range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<GenericAddress> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            WalletLogPrintf("DEBUG: Unable to ExpandFromCache for descriptor=%s. cache.scan_secret=%s, cache.spend_pubkey=%s\n", GetID().GetHex(), m_wallet_descriptor.cache.GetCachedMWEBScanKey().has_value() ? "YES" : "NO", m_wallet_descriptor.cache.GetCachedMWEBSpendPubKey().has_value() ? "YES" : "NO");
            throw std::runtime_error("Error: Unable to expand wallet descriptor from cache");
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        for (const GenericAddress& script : scripts_temp) {
            if (m_map_addresses.count(script) != 0) {
                throw std::runtime_error(strprintf("Error: Already loaded script at index %d as being at index %d", i, m_map_addresses[script]));
            }
            m_map_addresses[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and it's private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        m_max_cached_index++;
    }
}

bool DescriptorScriptPubKeyMan::AddKey(const CKeyID& key_id, const CKey& key)
{
    LOCK(cs_desc_man);
    m_map_keys[key_id] = key;
    return true;
}

bool DescriptorScriptPubKeyMan::AddCryptedKey(const CKeyID& key_id, const CPubKey& pubkey, const std::vector<unsigned char>& crypted_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    m_map_crypted_keys[key_id] = make_pair(pubkey, crypted_key);
    return true;
}

bool DescriptorScriptPubKeyMan::HasWalletDescriptor(const WalletDescriptor& desc) const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.descriptor != nullptr && desc.descriptor != nullptr && m_wallet_descriptor.descriptor->ToString() == desc.descriptor->ToString();
}

void DescriptorScriptPubKeyMan::WriteDescriptor()
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }
}

const WalletDescriptor DescriptorScriptPubKeyMan::GetWalletDescriptor() const
{
    return m_wallet_descriptor;
}

const std::unordered_set<GenericAddress, SaltedGenericAddressHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys() const
{
    LOCK(cs_desc_man);
    std::unordered_set<GenericAddress, SaltedGenericAddressHasher> script_pub_keys;
    script_pub_keys.reserve(m_map_addresses.size());

    for (auto const& script_pub_key : m_map_addresses) {
        script_pub_keys.insert(script_pub_key.first);
    }
    return script_pub_keys;
}

bool DescriptorScriptPubKeyMan::GetDescriptorString(std::string& out, const bool priv) const
{
    LOCK(cs_desc_man);

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    if (priv) {
        // For the private version, always return the master key to avoid
        // exposing child private keys. The risk implications of exposing child
        // private keys together with the parent xpub may be non-obvious for users.
        return m_wallet_descriptor.descriptor->ToPrivateString(provider, out);
    }

    return m_wallet_descriptor.descriptor->ToNormalizedString(provider, out, &m_wallet_descriptor.cache);
}

void DescriptorScriptPubKeyMan::UpgradeDescriptorCache()
{
    LOCK(cs_desc_man);
    if (m_storage.IsLocked() || m_storage.IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    // Skip if we have the last hardened xpub cache
    if (m_wallet_descriptor.cache.GetCachedLastHardenedExtPubKeys().size() > 0) {
        return;
    }

    // Expand the descriptor
    FlatSigningProvider provider;
    provider.keys = GetKeys();
    FlatSigningProvider out_keys;
    std::vector<GenericAddress> scripts_temp;
    DescriptorCache temp_cache;
    if (!m_wallet_descriptor.descriptor->Expand(0, provider, scripts_temp, out_keys, &temp_cache)){
        LogPrintf("DEBUG: Unable to expand descriptor\n");
        throw std::runtime_error("Unable to expand descriptor");
    }

    // Cache the last hardened xpubs
    DescriptorCache diff = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
    if (!WalletBatch(m_storage.GetDatabase()).WriteDescriptorCacheItems(GetID(), diff)) {
        LogPrintf("DEBUG: Writing cache items failed\n");
        throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
    }
}

void DescriptorScriptPubKeyMan::UpdateWalletDescriptor(WalletDescriptor& descriptor)
{
    LOCK(cs_desc_man);
    std::string error;
    if (!CanUpdateToWalletDescriptor(descriptor, error)) {
        throw std::runtime_error(std::string(__func__) + ": " + error);
    }

    m_map_pubkeys.clear();
    m_map_addresses.clear();
    m_max_cached_index = -1;
    m_wallet_descriptor = descriptor;
}

bool DescriptorScriptPubKeyMan::CanUpdateToWalletDescriptor(const WalletDescriptor& descriptor, std::string& error)
{
    LOCK(cs_desc_man);
    if (!HasWalletDescriptor(descriptor)) {
        error = "can only update matching descriptor";
        return false;
    }

    if (descriptor.range_start > m_wallet_descriptor.range_start ||
        descriptor.range_end < m_wallet_descriptor.range_end) {
        // Use inclusive range for error
        error = strprintf("new range must include current range = [%d,%d]",
                          m_wallet_descriptor.range_start,
                          m_wallet_descriptor.range_end - 1);
        return false;
    }

    return true;
}

void DescriptorScriptPubKeyMan::LoadMWEBKeychain()
{
    if (m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) || m_storage.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
        return;
    }

    m_storage.SetMinVersion(FEATURE_MWEB);

    LOCK(cs_desc_man);
    FlatSigningProvider provider, out_keys;
    provider.keys = GetKeys();
    if (provider.keys.empty()) {
        return;
    }

    std::optional<SecretKey> scan_key = m_wallet_descriptor.cache.GetCachedMWEBScanKey();
    std::optional<PublicKey> spend_pubkey = m_wallet_descriptor.cache.GetCachedMWEBSpendPubKey();
    if (!scan_key || !spend_pubkey) {
        WalletLogPrintf("DEBUG: scan_key or spend_pubkey not found\n");
        return;
    }

    CKey spend_key;
    if (provider.GetKey(spend_pubkey->GetID(), spend_key)) {
        WalletLogPrintf("DEBUG: Creating MWEB keychain with spend_key\n");
        m_mwebKeychain = std::make_shared<mw::Keychain>(
            this,
            *scan_key,
            SecretKey(spend_key.begin())
        );
    } else {
        WalletLogPrintf("DEBUG: spend_key not found\n");
        m_mwebKeychain = std::make_shared<mw::Keychain>(
            this,
            *scan_key,
            *spend_pubkey
        );
        return;
    }
}
} // namespace wallet
