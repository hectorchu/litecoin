// Copyright (c) 2023 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
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
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();

        FlatSigningProvider provider;
        std::string error;
        WalletDescriptor desc(Parse("combo(" + EncodeSecret(coinbaseKey) + ")", provider, error, false), 0, 0, 1, 1);
        m_wallet.AddWalletDescriptor(desc, provider, "", false);

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

    std::pair<CWalletTx*, CMutableTransaction> AddTx(
        const std::vector<CRecipient>& recipients,
        const std::vector<GenericWalletUTXO>& select_coins,
        std::optional<CTxDestination> change_address,
        const std::optional<int32_t>& nVersion = std::nullopt,
        const std::optional<uint32_t>& nLockTime = std::nullopt)
    {
        CCoinControl coin_control;
        if (!select_coins.empty()) {
            for (const auto& coin : select_coins) {
                coin_control.Select(coin.GetID());
            }
        }
        if (change_address) {
            coin_control.destChange = *change_address;
        }

        auto res = TxBuilder::New(m_wallet, coin_control, recipients, recipients.size())->Build(nVersion, nLockTime, true);
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
    void ExpectAmounts(const std::vector<T>& v, F fn, std::vector<CAmount> expected, bool sort = false)
    {
        BOOST_REQUIRE_EQUAL(v.size(), expected.size());
        std::vector<CAmount> amounts;
        std::transform(v.cbegin(), v.cend(), std::back_inserter(amounts), fn);
        if (sort) {
            std::sort(amounts.begin(), amounts.end());
            std::sort(expected.begin(), expected.end());
        }
        for (size_t i = 0; i < amounts.size(); i++) {
            BOOST_CHECK_LT(std::abs(amounts[i] - expected[i]), 100000);
        }
    }

    void ExpectCoins(const std::vector<CAmount>& ltc, const std::vector<CAmount>& mweb)
    {
        LOCK(m_wallet.cs_wallet);
        auto coins = AvailableCoins(m_wallet).coins;
        auto fn = [](const GenericWalletUTXO& utxo) { return utxo.GetValue(); };
        ExpectAmounts(coins[OutputType::BECH32], fn, ltc, true);
        ExpectAmounts(coins[OutputType::MWEB], fn, mweb, true);
    }

    GenericWalletUTXO SmallestCoin(const std::vector<GenericWalletUTXO>& coins)
    {
        BOOST_REQUIRE(!coins.empty());
        return *std::min_element(coins.begin(), coins.end(), [](const GenericWalletUTXO& a, const GenericWalletUTXO& b) { return a.GetValue() < b.GetValue(); });
    }

    static constexpr auto voutfn = [](const CTxOut& utxo) { return utxo.nValue; };
    static constexpr auto mwoutfn = [](const mw::MutableOutput& utxo) { return *utxo.amount; };
    static constexpr auto peginfn = [](const PegInCoin& pegin) { return pegin.GetAmount(); };
    static constexpr auto pegoutfn = [](const PegOutCoin& pegout) { return pegout.GetAmount(); };

    void SingleRecipientTest(bool fSubtractFeeFromAmount, bool use_custom_change)
    {
        std::optional<CTxDestination> ltc_change, mweb_change;
        if (use_custom_change) {
            ltc_change = NewDestination(OutputType::BECH32);
            mweb_change = NewDestination(OutputType::MWEB);
        }

        {   // Pegin & Activate MWEB
            auto mweb_addr = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({{mweb_addr, 5 * COIN, fSubtractFeeFromAmount}}, {}, mweb_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 1, 2); // Single LTC pegin output (all pegged-in), MWEB recipient output and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {125 * COIN/10});

            auto pegins = mtx.mweb_tx.GetPegIns();
            ExpectAmounts(pegins, peginfn, {125 * COIN/10});
            BOOST_CHECK(mtx.vout[0].scriptPubKey == GetScriptForPegin(pegins[0].GetKernelID()));

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {5 * COIN, 75 * COIN/10});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_change);

            ExpectCoins({}, {5 * COIN, 75 * COIN/10});
        }

        {   // LTC to LTC
            auto ltc_addr = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({{ltc_addr, 2 * COIN, fSubtractFeeFromAmount}}, {}, ltc_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 2, 0);
            ExpectAmounts(mtx.vout, voutfn, {2 * COIN, 105 * COIN/10});

            BOOST_CHECK(GenericAddress(mtx.vout[0].scriptPubKey) == ltc_addr);
            if (ltc_change) BOOST_CHECK(GenericAddress(mtx.vout[1].scriptPubKey) == ltc_change);

            ExpectCoins({2 * COIN, 105 * COIN/10}, {5 * COIN, 75 * COIN/10});
        }

        {   // MWEB to MWEB
            auto mweb_addr = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({{mweb_addr, 2 * COIN, fSubtractFeeFromAmount}}, {}, mweb_change);

            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 2);

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {2 * COIN, 3 * COIN});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_change);

            ExpectCoins({2 * COIN, 105 * COIN/10}, {2 * COIN, 3 * COIN, 75 * COIN/10});
        }

        {   // Pegout
            LOCK(m_wallet.cs_wallet);
            auto ltc_addr = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({{ltc_addr, 1 * COIN, fSubtractFeeFromAmount}}, {SmallestCoin(AvailableCoins(m_wallet).coins[OutputType::MWEB])}, mweb_change);

            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 1);

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {1 * COIN});
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_change);

            auto pegouts = mtx.mweb_tx.GetPegOutCoins();
            ExpectAmounts(pegouts, pegoutfn, {1 * COIN});
            BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == ltc_addr);

            mineBlocks(PEGOUT_MATURITY);
            ExpectCoins({1 * COIN, 2 * COIN, 105 * COIN/10}, {1 * COIN, 3 * COIN, 75 * COIN/10});
        }

        {   // Pegin & Pegout
            LOCK(m_wallet.cs_wallet);
            auto coins = AvailableCoins(m_wallet).coins;
            auto ltc_addr = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({{ltc_addr, 5 * COIN/10, fSubtractFeeFromAmount}}, {SmallestCoin(coins[OutputType::BECH32]), SmallestCoin(coins[OutputType::MWEB])}, mweb_change);

            ExpectInputs(*wtx, 1, 1);
            ExpectOutputs(*wtx, 1, 1); // LTC pegin output and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {1 * COIN});

            auto pegins = mtx.mweb_tx.GetPegIns();
            ExpectAmounts(pegins, peginfn, {1 * COIN});
            BOOST_CHECK(mtx.vout[0].scriptPubKey == GetScriptForPegin(pegins[0].GetKernelID()));

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {15 * COIN/10});
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_change);

            auto pegouts = mtx.mweb_tx.GetPegOutCoins();
            ExpectAmounts(pegouts, pegoutfn, {5 * COIN/10});
            BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == ltc_addr);

            mineBlocks(PEGOUT_MATURITY);
            ExpectCoins({5 * COIN/10, 2 * COIN, 105 * COIN/10}, {15 * COIN/10, 3 * COIN, 75 * COIN/10});
        }
    }

    void MultipleRecipientsTest(bool fSubtractFeeFromAmount, bool use_custom_change)
    {
        std::optional<CTxDestination> ltc_change, mweb_change;
        if (use_custom_change) {
            ltc_change = NewDestination(OutputType::BECH32);
            mweb_change = NewDestination(OutputType::MWEB);
        }

        {   // Pegin & Activate MWEB
            auto mweb_addr1 = NewDestination(OutputType::MWEB);
            auto mweb_addr2 = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({
                {mweb_addr1, 2 * COIN, fSubtractFeeFromAmount},
                {mweb_addr2, 3 * COIN, fSubtractFeeFromAmount},
            }, {}, mweb_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 1, 3); // Single LTC pegin output (all pegged-in), MWEB recipient outputs and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {125 * COIN/10});

            auto pegins = mtx.mweb_tx.GetPegIns();
            ExpectAmounts(pegins, peginfn, {125 * COIN/10});
            BOOST_CHECK(mtx.vout[0].scriptPubKey == GetScriptForPegin(pegins[0].GetKernelID()));

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {2 * COIN, 3 * COIN, 75 * COIN/10});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr1);
            BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_addr2);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[2].address) == mweb_change);

            ExpectCoins({}, {2 * COIN, 3 * COIN, 75 * COIN/10});
        }

        {   // LTC to LTC
            auto ltc_addr1 = NewDestination(OutputType::BECH32);
            auto ltc_addr2 = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({
                {ltc_addr1, 2 * COIN, fSubtractFeeFromAmount},
                {ltc_addr2, 3 * COIN, fSubtractFeeFromAmount},
            }, {}, ltc_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 3, 0);
            ExpectAmounts(mtx.vout, voutfn, {2 * COIN, 3 * COIN, 75 * COIN/10});

            BOOST_CHECK(GenericAddress(mtx.vout[0].scriptPubKey) == ltc_addr1);
            BOOST_CHECK(GenericAddress(mtx.vout[1].scriptPubKey) == ltc_addr2);
            if (ltc_change) BOOST_CHECK(GenericAddress(mtx.vout[2].scriptPubKey) == ltc_change);

            ExpectCoins({2 * COIN, 3 * COIN, 75 * COIN/10}, {2 * COIN, 3 * COIN, 75 * COIN/10});
        }

        {   // MWEB to MWEB
            auto mweb_addr1 = NewDestination(OutputType::MWEB);
            auto mweb_addr2 = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({
                {mweb_addr1, 2 * COIN, fSubtractFeeFromAmount},
                {mweb_addr2, 3 * COIN, fSubtractFeeFromAmount},
            }, {}, mweb_change);

            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 3);

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {2 * COIN, 3 * COIN, 25 * COIN/10});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr1);
            BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_addr2);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[2].address) == mweb_change);

            ExpectCoins({2 * COIN, 3 * COIN, 75 * COIN/10}, {2 * COIN, 2 * COIN, 3 * COIN, 3 * COIN, 25 * COIN/10});
        }

        // Pegout to multiple recipients currently disallowed
    }
};

BOOST_FIXTURE_TEST_SUITE(txbuilder_tests, TxBuilderTestingSetup)

BOOST_AUTO_TEST_CASE(SingleRecipientBasicTest)
{
    SingleRecipientTest(false, false);
}

BOOST_AUTO_TEST_CASE(SingleRecipientSubtractFeeFromOutputsTest)
{
    SingleRecipientTest(true, false);
}

BOOST_AUTO_TEST_CASE(SingleRecipientCustomChangeTest)
{
    SingleRecipientTest(false, true);
}

BOOST_AUTO_TEST_CASE(MultipleRecipientsBasicTest)
{
    MultipleRecipientsTest(false, false);
}

BOOST_AUTO_TEST_CASE(MultipleRecipientsSubtractFeeFromOutputsTest)
{
    MultipleRecipientsTest(true, false);
}

BOOST_AUTO_TEST_CASE(MultipleRecipientsCustomChangeTest)
{
    MultipleRecipientsTest(false, true);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
