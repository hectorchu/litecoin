#pragma once

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <univalue.h>
#include <optional>
#include <variant>

namespace wallet {

// Forward Declarations
class CWallet;
class CWalletTx;

struct PegoutIndex {
    // The ID of the kernel containing the pegout.
    mw::Hash kernel_id;

    // The position of the PegOutCoin within the kernel.
    // Ex: If a kernel has 3 pegouts, the last one will have a pos of 2.
    size_t pos;

    bool operator==(const PegoutIndex& pegout_idx) const noexcept { return pegout_idx.kernel_id == kernel_id && pegout_idx.pos == pos; }
};

class GenericComponentID
{
    std::variant<COutPoint, mw::Hash, PegoutIndex> m_value;

public:
    GenericComponentID() = default;
    GenericComponentID(COutPoint outpoint) : m_value(std::move(outpoint)) {}
    GenericComponentID(mw::Hash hash) : m_value(std::move(hash)) {}
    GenericComponentID(PegoutIndex pegout_idx) : m_value(std::move(pegout_idx)) {}

    bool operator==(const GenericComponentID& id) const noexcept { return id.m_value == m_value; }
    bool operator==(const COutPoint& outpoint) const noexcept { return IsOutPoint() && ToOutPoint() == outpoint; }
    bool operator==(const mw::Hash& mweb_hash) const noexcept { return IsMWEBOutputID() && ToMWEBOutputID() == mweb_hash; }
    bool operator==(const PegoutIndex& pegout_idx) const noexcept { return IsPegoutIndex() && ToPegoutIndex() == pegout_idx; }

    bool IsOutPoint() const noexcept { return std::holds_alternative<COutPoint>(m_value); }
    bool IsMWEBOutputID() const noexcept { return std::holds_alternative<mw::Hash>(m_value); }
    bool IsPegoutIndex() const noexcept { return std::holds_alternative<PegoutIndex>(m_value); }

    const mw::Hash& ToMWEBOutputID() const noexcept
    {
        assert(IsMWEBOutputID());
        return std::get<mw::Hash>(m_value);
    }

    const COutPoint& ToOutPoint() const noexcept
    {
        assert(IsOutPoint());
        return std::get<COutPoint>(m_value);
    }

    const PegoutIndex& ToPegoutIndex() const noexcept
    {
        assert(IsPegoutIndex());
        return std::get<PegoutIndex>(m_value);
    }

    std::string ToString() const noexcept
    {
        if (IsOutPoint()) {
            return std::to_string(ToOutPoint().n);
        } else if (IsMWEBOutputID()) {
            return "MWEB Output (" + ToMWEBOutputID().ToHex() + ")";
        } else {
            const PegoutIndex& pegout_idx = ToPegoutIndex();
            return "Pegout (" + pegout_idx.kernel_id.ToHex() + ":" + std::to_string(pegout_idx.pos) + ")";
        }
    }
};

struct TxRecordStatus {
    enum Status {
        Confirmed, /**< Have 6 or more confirmations (normal tx) or fully mature (mined tx) **/
        /// Normal (sent/received) transactions
        Unconfirmed,    /**< Not yet mined into a block **/
        Confirming,     /**< Confirmed, but waiting for the recommended number of confirmations **/
        Conflicted,     /**< Conflicts with other transaction or mempool **/
        Abandoned,      /**< Abandoned from the wallet **/
        /// Generated (mined) transactions
        Immature,   /**< Mined but waiting for maturity */
        NotAccepted /**< Mined but not accepted */
    };

    /// Transaction counts towards available balance
    bool countsForBalance;
    /// Sorting key based on status
    std::string sortKey;

    /** @name Generated (mined) transactions
       @{*/
    int matures_in;
    /**@}*/

    /** @name Reported status
       @{*/
    Status status;
    int64_t depth;
    int64_t open_for; /**< Timestamp if status==OpenUntilDate, otherwise number
                      of additional blocks that need to be mined before
                      finalization */
    /**@}*/

    /** Current block hash (to know whether cached status is still valid) */
    uint256 m_cur_block_hash{};

    bool needsUpdate;
};

class WalletTxRecord
{
public:
    WalletTxRecord(const CWallet* pWallet, const CWalletTx* wtx, const GenericOutputID& output_id)
        : m_pWallet(pWallet), m_wtx(wtx), index(std::make_optional(output_id.IsMWEB() ? GenericComponentID(output_id.ToMWEB()) : GenericComponentID(output_id.ToOutPoint()))) {}
    WalletTxRecord(const CWallet* pWallet, const CWalletTx* wtx, const PegoutIndex& pegout_index)
        : m_pWallet(pWallet), m_wtx(wtx), index(std::make_optional(GenericComponentID(pegout_index))) {}
    WalletTxRecord(const CWallet* pWallet, const CWalletTx* wtx)
        : m_pWallet(pWallet), m_wtx(wtx), index(std::nullopt) {}

    static const int RecommendedNumConfirmations = 6;

    enum Type {
        Other,
        Generated,
        SendToAddress,
        SendToOther,
        RecvWithAddress,
        RecvFromOther,
        SendToSelf,
    };

    Type type{Type::Other};
    std::string address{};
    CAmount debit{0};
    CAmount credit{0};
    CAmount fee{0};
    bool involvesWatchAddress{false};

    // Cached status attributes
    TxRecordStatus status;

    // Updates the transaction record's cached status attributes.
    bool UpdateStatusIfNeeded(const uint256& block_hash);

    const CWalletTx& GetWTX() const noexcept { return *m_wtx; }
    const uint256& GetTxHash() const;
    std::string GetTxString() const;
    int64_t GetTxTime() const;
    CAmount GetAmount() const noexcept { return credit > 0 ? credit : debit; }
    // CAmount GetAmount() const noexcept { return credit + debit; }
    CAmount GetNet() const noexcept { return credit + debit + fee; }

    UniValue ToUniValue() const;

    // Returns the formatted component index.
    std::string GetComponentIndex() const { return index.has_value() ? index->ToString() : ""; }

private:
    // Pointer to the CWallet instance
    const CWallet* m_pWallet;

    // The actual CWalletTx
    const CWalletTx* m_wtx;

    // The index of the transaction component this record is for.
    std::optional<GenericComponentID> index;

    std::string GetType() const;
};

} // namespace wallet
