#include <mweb/mweb_models.h>

using namespace mweb;

mw::Transaction::CPtr MutableTx::Finalize() const noexcept
{
    if (IsNull()) {
        return nullptr;
    }

    return mw::Transaction::Create(
        m_transaction->kernel_offset,
        m_transaction->stealth_offset,
        m_transaction->inputs,
        m_transaction->outputs,
        m_transaction->kernels
    );
}