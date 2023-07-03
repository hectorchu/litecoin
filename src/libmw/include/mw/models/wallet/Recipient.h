#pragma once

#include <mw/common/Macros.h>
#include <mw/models/wallet/StealthAddress.h>
#include <consensus/amount.h>

MW_NAMESPACE

struct Recipient {
    CAmount amount;
    StealthAddress address;
};

END_NAMESPACE
