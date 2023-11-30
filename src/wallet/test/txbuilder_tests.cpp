// Copyright (c) 2023 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <validation.h>
#include <wallet/txbuilder.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

class TxBuilderTestingSetup : public TestChain100Setup
{
    CWallet m_wallet;
public:
    TxBuilderTestingSetup()
        : m_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase())
    {
        m_wallet.LoadWallet();
        m_wallet.LoadMinVersion(FEATURE_MWEB);
        m_wallet.SetupLegacyScriptPubKeyMan();
        m_wallet.GetLegacyScriptPubKeyMan()->AddKey(coinbaseKey);
        m_wallet.GetLegacyScriptPubKeyMan()->SetupGeneration();
        m_wallet.SetBroadcastTransactions(true);
        SetMockTime(1601450001);
        mineBlocks(331); // Pre-MWEB activation blocks
        m_build_block_with_mempool = true;
    }

    void mineBlocks(int num_blocks)
    {
        LOCK2(m_node.chainman->GetMutex(), m_wallet.cs_wallet);
        const CChain& cchain = m_node.chainman->ActiveChain();
        uint256 prev_block = cchain.Tip()->GetBlockHash();
        int prev_height = cchain.Height();

        TestChain100Setup::mineBlocks(num_blocks);
        m_wallet.SetLastBlockProcessed(cchain.Height(), cchain.Tip()->GetBlockHash());

        WalletRescanReserver reserver(m_wallet);
        reserver.reserve();
        auto res = m_wallet.ScanForWalletTransactions(prev_block, prev_height, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK(res.status == res.SUCCESS);
    }

    std::pair<CWalletTx*, CMutableTransaction> AddTx(const std::vector<CRecipient>& recipients, const std::vector<GenericWalletUTXO>& select_coins = {})
    {
        CCoinControl coin_control;
        if (!select_coins.empty()) {
            for (const auto& coin : select_coins) {
                coin_control.Select(coin.GetID());
            }
        }

        auto res = TxBuilder::New(m_wallet, coin_control, recipients, std::nullopt)->Build(true);
        BOOST_REQUIRE(res);
        auto tx = MakeTransactionRef(res->tx);
        m_wallet.CommitTransaction(tx, {}, {});
        mineBlocks(1);

        LOCK2(m_node.chainman->GetMutex(), m_wallet.cs_wallet);
        const CChain& cchain = m_node.chainman->ActiveChain();
        auto it = m_wallet.mapWallet.find(tx->GetHash());
        BOOST_REQUIRE(it != m_wallet.mapWallet.end());
        it->second.m_state = TxStateConfirmed{cchain.Tip()->GetBlockHash(), cchain.Height(), /*index=*/1};
        return std::make_pair(&it->second, res->tx);
    }

    CTxDestination NewDestination(OutputType type)
    {
        auto dest = m_wallet.GetNewDestination(type, "");
        BOOST_REQUIRE(dest);
        return *dest;
    }

    void ExpectInputs(const CWalletTx& wtx, size_t ltc, size_t mweb)
    {
        const auto& inputs = wtx.GetInputs();
        BOOST_REQUIRE_EQUAL(inputs.size(), ltc + mweb);
        for (size_t i = 0; i < ltc; i++) {
            BOOST_CHECK(!inputs[i].IsMWEB());
        }
        for (size_t i = ltc; i < inputs.size(); i++) {
            BOOST_CHECK(inputs[i].IsMWEB());
        }
    }

    void ExpectOutputs(const CWalletTx& wtx, size_t ltc, size_t mweb)
    {
        const auto& outputs = wtx.GetOutputs();
        BOOST_REQUIRE_EQUAL(outputs.size(), ltc + mweb);
        for (size_t i = 0; i < ltc; i++) {
            BOOST_CHECK(!outputs[i].IsMWEB());
        }
        for (size_t i = ltc; i < outputs.size(); i++) {
            BOOST_CHECK(outputs[i].IsMWEB());
        }
    }

    template<typename T, typename F>
    void ExpectAmounts(const std::vector<T>& v, F fn, std::vector<CAmount> expected)
    {
        BOOST_REQUIRE_EQUAL(v.size(), expected.size());
        std::vector<CAmount> amounts;
        std::transform(v.cbegin(), v.cend(), std::back_inserter(amounts), fn);
        std::sort(amounts.begin(), amounts.end());
        std::sort(expected.begin(), expected.end());
        for (size_t i = 0; i < amounts.size(); i++) {
            BOOST_CHECK_LT(std::abs(amounts[i] - expected[i]), 100000);
        }
    }

    void ExpectCoins(const std::vector<CAmount>& ltc, const std::vector<CAmount>& mweb)
    {
        LOCK(m_wallet.cs_wallet);
        auto coins = AvailableCoins(m_wallet).coins;
        auto fn = [](const GenericWalletUTXO& utxo) { return utxo.GetValue(); };
        ExpectAmounts(coins[OutputType::BECH32], fn, ltc);
        ExpectAmounts(coins[OutputType::MWEB], fn, mweb);
    }

    GenericWalletUTXO SmallestCoin(const std::vector<GenericWalletUTXO>& coins)
    {
        BOOST_REQUIRE(!coins.empty());
        return *std::min_element(coins.begin(), coins.end(), [](const GenericWalletUTXO& a, const GenericWalletUTXO& b) { return a.GetValue() < b.GetValue(); });
    }

    void RunTest(bool fSubtractFeeFromAmount)
    {
        auto voutfn = [](const CTxOut& utxo) { return utxo.nValue; };
        auto mwoutfn = [](const mw::MutableOutput& utxo) { return *utxo.amount; };
        auto peginfn = [](const PegInCoin& pegin) { return pegin.GetAmount(); };
        auto pegoutfn = [](const PegOutCoin& pegout) { return pegout.GetAmount(); };

        {   // Pegin & Activate MWEB
            auto [wtx, mtx] = AddTx({{{NewDestination(OutputType::MWEB)}, 5 * COIN, fSubtractFeeFromAmount}});
            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 1, 2); // Single LTC pegin output (all pegged-in), MWEB pegin output and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {125 * COIN/10});
            ExpectAmounts(mtx.mweb_tx.GetPegIns(), peginfn, {125 * COIN/10});
            ExpectAmounts(mtx.mweb_tx.outputs, mwoutfn, {5 * COIN, 75 * COIN/10});
            ExpectCoins({}, {5 * COIN, 75 * COIN/10});
        }

        {   // LTC to LTC
            auto [wtx, mtx] = AddTx({{{NewDestination(OutputType::BECH32)}, 2 * COIN, fSubtractFeeFromAmount}});
            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 2, 0);
            ExpectAmounts(mtx.vout, voutfn, {2 * COIN, 105 * COIN/10});
            ExpectCoins({2 * COIN, 105 * COIN/10}, {5 * COIN, 75 * COIN/10});
        }

        {   // MWEB to MWEB
            auto [wtx, mtx] = AddTx({{{NewDestination(OutputType::MWEB)}, 2 * COIN, fSubtractFeeFromAmount}});
            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 2);
            ExpectAmounts(mtx.mweb_tx.outputs, mwoutfn, {2 * COIN, 3 * COIN});
            ExpectCoins({2 * COIN, 105 * COIN/10}, {2 * COIN, 3 * COIN, 75 * COIN/10});
        }

        {   // Pegout
            LOCK(m_wallet.cs_wallet);
            auto [wtx, mtx] = AddTx({{{NewDestination(OutputType::BECH32)}, 1 * COIN, fSubtractFeeFromAmount}}, {SmallestCoin(AvailableCoins(m_wallet).coins[OutputType::MWEB])});
            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 1);
            ExpectAmounts(mtx.mweb_tx.outputs, mwoutfn, {1 * COIN});
            ExpectAmounts(mtx.mweb_tx.GetPegOutCoins(), pegoutfn, {1 * COIN});
            mineBlocks(PEGOUT_MATURITY);
            ExpectCoins({1 * COIN, 2 * COIN, 105 * COIN/10}, {1 * COIN, 3 * COIN, 75 * COIN/10});
        }

        {   // Pegin & Pegout
            LOCK(m_wallet.cs_wallet);
            auto coins = AvailableCoins(m_wallet).coins;
            auto [wtx, mtx] = AddTx({{{NewDestination(OutputType::BECH32)}, 5 * COIN/10, fSubtractFeeFromAmount}}, {SmallestCoin(coins[OutputType::BECH32]), SmallestCoin(coins[OutputType::MWEB])});
            ExpectInputs(*wtx, 1, 1);
            ExpectOutputs(*wtx, 1, 1); // LTC pegin output and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {1 * COIN});
            ExpectAmounts(mtx.mweb_tx.GetPegIns(), peginfn, {1 * COIN});
            ExpectAmounts(mtx.mweb_tx.outputs, mwoutfn, {15 * COIN/10});
            ExpectAmounts(mtx.mweb_tx.GetPegOutCoins(), pegoutfn, {5 * COIN/10});
            mineBlocks(PEGOUT_MATURITY);
            ExpectCoins({5 * COIN/10, 2 * COIN, 105 * COIN/10}, {15 * COIN/10, 3 * COIN, 75 * COIN/10});
        }
    }
};

BOOST_FIXTURE_TEST_SUITE(txbuilder_tests, TxBuilderTestingSetup)

BOOST_AUTO_TEST_CASE(AddFeeToInputsTest)
{
    RunTest(false);
}

BOOST_AUTO_TEST_CASE(SubtractFeeFromOutputsTest)
{
    RunTest(true);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
