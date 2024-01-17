#pragma once

#include <mw/common/Logger.h>
#include <mw/models/tx/UTXO.h>
#include <mw/models/crypto/SecretKey.h>
#include <unordered_map>

struct CoinAction {
    bool IsSpend() const noexcept { return pUTXO == nullptr; }

    mw::UTXO::CPtr pUTXO;
};

class CoinsViewUpdates
{
    mw::Hash update_id{SecretKey::Random().data()};
public:
    CoinsViewUpdates() = default;

    void AddUTXO(const mw::UTXO::CPtr& pUTXO)
    {
        //LOG_INFO("UTXO({}): Add UTXO {}", update_id.ToHex().substr(0, 8), pUTXO->GetOutputID().ToHex());
        AddAction(pUTXO->GetOutputID(), CoinAction{pUTXO});
    }

    void SpendUTXO(const mw::Hash& output_id)
    {
        //LOG_INFO("UTXO({}): Spend UTXO {}", update_id.ToHex().substr(0, 8), output_id.ToHex());
        AddAction(output_id, CoinAction{nullptr});
    }

    const std::unordered_map<mw::Hash, std::vector<CoinAction>>& GetActions() const noexcept { return m_actions; }

    std::vector<CoinAction> GetActions(const mw::Hash& output_id) const noexcept
    {
        //LOG_INFO("UTXO({}): Get UTXO {}", update_id.ToHex().substr(0, 8), output_id.ToHex());
        auto iter = m_actions.find(output_id);
        if (iter != m_actions.cend()) {
            return iter->second;
        }

        return {};
    }

    void Clear() noexcept
    {
        m_actions.clear();
    }

private:
    void AddAction(const mw::Hash& output_id, CoinAction&& action)
    {
        auto iter = m_actions.find(output_id);
        if (iter != m_actions.end()) {
            std::vector<CoinAction>& actions = iter->second;
            actions.emplace_back(std::move(action));
        } else {
            std::vector<CoinAction> actions;
            actions.emplace_back(std::move(action));
            m_actions.insert({output_id, actions});
        }
    }

    std::unordered_map<mw::Hash, std::vector<CoinAction>> m_actions;
};
