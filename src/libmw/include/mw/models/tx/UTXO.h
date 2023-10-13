#pragma once

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/tx/Output.h>
#include <mw/mmr/LeafIndex.h>
#include <serialize.h>

MW_NAMESPACE

class UTXO : public Traits::ISerializable
{
    static constexpr int32_t MEMPOOL_BLOCK_HEIGHT{std::numeric_limits<int32_t>::max()};
    static constexpr uint64_t MEMPOOL_LEAF_IDX{std::numeric_limits<uint64_t>::max() / 2};

public:
    using CPtr = std::shared_ptr<const UTXO>;

    UTXO() : m_blockHeight(0), m_leafIdx(), m_output() { }
    UTXO(const int32_t blockHeight, mmr::LeafIndex leafIdx, mw::Output output)
        : m_blockHeight(blockHeight), m_leafIdx(std::move(leafIdx)), m_output(std::move(output)) { }

    static UTXO ForMempool(mw::Output output) noexcept { return UTXO(MEMPOOL_BLOCK_HEIGHT, mmr::LeafIndex::At(MEMPOOL_LEAF_IDX), std::move(output)); }

    bool IsInMempool() const noexcept { return m_blockHeight == MEMPOOL_BLOCK_HEIGHT && m_leafIdx.Get() == MEMPOOL_LEAF_IDX; }
    int32_t GetBlockHeight() const noexcept { return m_blockHeight; }
    const mmr::LeafIndex& GetLeafIndex() const noexcept { return m_leafIdx; }
    const mw::Output& GetOutput() const noexcept { return m_output; }

    const mw::Hash& GetOutputID() const noexcept { return m_output.GetOutputID(); }
    const Commitment& GetCommitment() const noexcept { return m_output.GetCommitment(); }
    const PublicKey& GetReceiverPubKey() const noexcept { return m_output.GetReceiverPubKey(); }
    const RangeProof::CPtr& GetRangeProof() const noexcept { return m_output.GetRangeProof(); }
    ProofData BuildProofData() const noexcept { return m_output.BuildProofData(); }

    IMPL_SERIALIZABLE(UTXO, obj)
    {
        READWRITE(obj.m_blockHeight, obj.m_leafIdx, obj.m_output);
    }

private:
    int32_t m_blockHeight;
    mmr::LeafIndex m_leafIdx;
    mw::Output m_output;
};

END_NAMESPACE
