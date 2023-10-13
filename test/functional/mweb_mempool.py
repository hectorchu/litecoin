#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests mempool functionality for MWEB transactions
"""

from test_framework.test_framework import LitecoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

class MWEBMempoolTest(LitecoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            [
                "-rpcserialversion=0",
                '-whitelist=noban@127.0.0.1'
            ],
            [
                "-rpcserialversion=1",
                '-whitelist=noban@127.0.0.1'
            ],
            [
                '-whitelist=noban@127.0.0.1'
            ],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node2 = self.nodes[2]
        
        #node0_w1 = node0.createwallet(wallet_name="w1")
        #node0_w1_rpc = node0.get_wallet_rpc("w1")

        self.log.info("Setup MWEB chain")
        self.setup_mweb_chain(node0)
        
        self.log.info("Pegin some coins")
        node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), 10)
        self.generatetoaddress(node0, nblocks=1, address=node0.getnewaddress(), sync_fun=self.no_op)
        
        self.log.info("Create an MWEB-to-MWEB transaction")
        txid = node0.sendtoaddress(node0.getnewaddress(address_type='mweb'), 2)
        self.sync_all()

        self.log.info("Assert txid is returned in getrawmempool but tx not returned from getmempoolentry for rpcserialversion=0")
        assert_equal([txid], node0.getrawmempool())
        assert_raises_rpc_error(-22, "MWEB-only transaction not serializable for rpcserialversion<2", node0.getmempoolentry, txid)

        self.log.info("Assert txid is returned in getrawmempool but tx not returned from getmempoolentry for rpcserialversion=1")
        assert_equal([txid], node1.getrawmempool())
        assert_raises_rpc_error(-22, "MWEB-only transaction not serializable for rpcserialversion<2", node1.getmempoolentry, txid)

        self.log.info("Assert txid is returned in getrawmempool and tx is returned for getmempoolentry for rpcserialversion=2")
        assert_equal([txid], node2.getrawmempool())
        assert node2.getmempoolentry(txid) is not None

if __name__ == '__main__':
    MWEBMempoolTest().main()
