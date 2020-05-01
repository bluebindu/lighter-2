# Copyright (C) 2018 inbitcoin s.r.l.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

""" Fixtures for test_light_electrum module """


ADD_LIGHTNING_REQUEST = "lnbcrt7771pw72z07pp5ze6qq950y4473kn8f5u3s2mncz0ddntthxh7ey3f3l06e892a29qdqqcqzynxqrrss4x77jvtcuhyquzss40uwdfctah603394n9kcvt0wvt2x7yvrwt44dj547j7f48acfamfpeh6vh67dvkr5qukjueem3xjt6ndm4ltzscpfjp6c8"


BROADCAST = 'a7c44df8cdd35ec0f822140960306a5b6196edf606f12aa5b635ea4ae224e5a7'


BADRESPONSE = {
    "code" : -32601,
    "message" : "A strange error occurred"
}


CHANNEL_CLOSED = {
    "channel_id": "bae86cd8c08b7ab61f53154ac1a0313da8c66c7d279711e91a59205c13984518",
    "channel_point": "184598135c20591ae91197277d6cc6a83d31a0c14a15531fb67a8bc0d86ce8ba:0",
    "local_balance": 78898,
    "local_reserve": 546,
    "local_unsettled_sent": 0,
    "peer_state": "DISCONNECTED",
    "remote_balance": 1,
    "remote_pubkey": "039613cbfa2f2887fa14b7be685d30e2ede74ba838346239aa5f91ee4255d972a6",
    "remote_reserve": 788,
    "remote_unsettled_sent": 0,
    "short_channel_id": None,
    "state": "CLOSED"
}


CHANNEL_CLOSING = {
    "channel_id": "36ce99335e94acf4f966ccc9e5620e4f03f6ed0546fcb33c2ce1a4e31c99f3f1",
    "channel_point": "f1f3991ce3a4e12c3cb3fc4605edf6034f0e62e5c9cc66f9f4ac945e3399ce36:0",
    "local_balance": 59999,
    "local_reserve": 546,
    "local_unsettled_sent": 0,
    "peer_state": "DISCONNECTED",
    "remote_balance": 60000,
    "remote_pubkey": "02920996e88fee2f555e0a699252598a6d839be1f3889ba58a51f9b32cd3c6327d",
    "remote_reserve": 546,
    "remote_unsettled_sent": 0,
    "short_channel_id": "3201x2x0",
    "state": "CLOSING"
}


CHANNEL_FORCE_CLOSING =     {
    "channel_id": "36ce99335e94acf4f966ccc9e5620e4f03f6ed0546fcb33c2ce1a4e31c99f3f1",
    "channel_point": "f1f3991ce3a4e12c3cb3fc4605edf6034f0e62e5c9cc66f9f4ac945e3399ce36:0",
    "local_balance": 59999,
    "local_reserve": None,
    "local_unsettled_sent": 0,
    "peer_state": "DISCONNECTED",
    "remote_balance": 60000,
    "remote_pubkey": "02920996e88fee2f555e0a699252598a6d839be1f3889ba58a51f9b32cd3c6327d",
    "remote_reserve": None,
    "remote_unsettled_sent": 0,
    "short_channel_id": None,
    "state": "FORCE_CLOSING"
}


CHANNEL_FUNDED = {
    "channel_id": "36ce99335e94acf4f966ccc9e5620e4f03f6ed0546fcb33c2ce1a4e31c99f3f1",
    "channel_point": "f1f3991ce3a4e12c3cb3fc4605edf6034f0e62e5c9cc66f9f4ac945e3399ce36:0",
    "local_balance": 59999,
    "local_reserve": None,
    "local_unsettled_sent": 0,
    "peer_state": "GOOD",
    "remote_balance": 60000,
    "remote_pubkey": "02920996e88fee2f555e0a699252598a6d839be1f3889ba58a51f9b32cd3c6327d",
    "remote_reserve": None,
    "remote_unsettled_sent": 0,
    "short_channel_id": "3291x2x0",
    "state": "FUNDED"
}


CHANNEL_OPEN = {
    "channel_id": "36ce99335e94acf4f966ccc9e5620e4f03f6ed0546fcb33c2ce1a4e31c99f3f1",
    "channel_point": "f1f3991ce3a4e12c3cb3fc4605edf6034f0e62e5c9cc66f9f4ac945e3399ce36:0",
    "local_balance": 59999,
    "local_reserve": 5435,
    "local_unsettled_sent": 0,
    "peer_state": "GOOD",
    "remote_balance": 60000,
    "remote_pubkey": "02920996e88fee2f555e0a699252598a6d839be1f3889ba58a51f9b32cd3c6327d",
    "remote_reserve": 356,
    "remote_unsettled_sent": 0,
    "short_channel_id": "3291x2x0",
    "state": "OPEN"
}


CHANNEL_OPENING = {
    "channel_id": "36ce99335e94acf4f966ccc9e5620e4f03f6ed0546fcb33c2ce1a4e31c99f3f1",
    "channel_point": "f1f3991ce3a4e12c3cb3fc4605edf6034f0e62e5c9cc66f9f4ac945e3399ce36:0",
    "local_balance": 59999,
    "local_reserve": None,
    "local_unsettled_sent": 0,
    "peer_state": "DISCONNECTED",
    "remote_balance": 60000,
    "remote_pubkey": "02920996e88fee2f555e0a699252598a6d839be1f3889ba58a51f9b32cd3c6327d",
    "remote_reserve": None,
    "remote_unsettled_sent": 0,
    "short_channel_id": None,
    "state": "OPENING"
}


CHANNEL_UNKNOWN = {
    "state": "NOT MAPPED"
}


DECODE_INVOICE = {
    "amount": 420000,
    "exp": 123456,
    "invoice": "lnbcrt4200u1p0fdk0spp59tuf8h4vpy9fu3mkd92s5szxewsj856m728q2am3lm3cz5u4ue8ssp5cy43x5f3nlyxnj94hcmt59l83mf9e8yrecs0deafhhafdd55pscsdq9wa6xvcqzynxqyrcjq9qypqsqrzjq2fqn9hg3lhz7427pf5ey5je3fkc8xlp7wyfhfv228umxtxncce86qqv5sqqqqsqqqqqqqqqqqqqqqqqqyd6duae5ez76p5h0msynpw43t2wx642d2cee3k2s0rsxkr0y0ajfpnhymu5auve9cqzazu6z67yutxydknn323e8zk7w2l07ruw3sedqq7k9kdy",
    "message": "witness",
    "pubkey": "0328b6b5f3b348b0c503962a7d5f830db96937951ee7f3e83c7a844656bb151131",
    "rhash": "2af893deac090a9e477669550a4046cba123d35bf28e057771fee3815395e64f",
    "time": 1586944496,
    "type": 2
}


EMPTY_TX = {}


EMPTY_INVOICE = {}


GETBALANCE = {
    "confirmed": "99.5374808",
    "lightning": "0.34971599",
    "unconfirmed": "0.10945639"
}


GETBALANCE_NO_UCONFIRMED = {
    "confirmed": "99.5374808",
    "lightning": "0.34971599",
}


GETBALANCE_EMPTY = {
    "confirmed": "0"
}


GETINFO = {
    "auto_connect": False,
    "blockchain_height": 215,
    "connected": True,
    "default_wallet": "/srv/wallet/alice/regtest/wallets/default_wallet",
    "fee_per_kb": 180000,
    "path": "/srv/wallet/alice/regtest",
    "server": "electrumx",
    "server_height": 215,
    "spv_nodes": 1,
    "version": "4.0.0a0"
}


GETINFO_MAINNET = {
    "auto_connect": False,
    "blockchain_height": 605361,
    "connected": True,
    "default_wallet": "/srv/wallet/alice/wallets/default_wallet",
    "fee_per_kb": None,
    "path": "/srv/wallet/alice",
    "server": "electrumx",
    "server_height": 605361,
    "spv_nodes": 4,
    "version": "4.0.0a0"
}


LISTADDRESSES = [
    "bcrt1qgldp4n50hram2wf3e8fsfcemy0r3dgddht3rtu",
    "bcrt1qqugfzy52s50nkfl29qngqhpzccwxwsd89gykd4",
    "bcrt1qsd25l6pchks4hezm9evd3w0e9m4qe7tmrjtjef",
    "bcrt1qex4trqtu0367rluz09uh8937u7t7tacpjrastc",
    "bcrt1qkvm7s2yqnfjsdlcameetnwuuja32knhsjgvavv",
    "bcrt1qz3vtddd4vh942nm47tftsc6zrxz2mrv0460xym",
    "bcrt1q6zk0r7ch0xde65fmaz5g95stqeq8pncf4emx33",
    "bcrt1qjesyd0s2r0dlr67gse4qfvzd0m33x60kshspsn",
    "bcrt1q807jfksms9qyrpzrthnsvfj2zaqevk00gmsuf9",
    "bcrt1quvknu9a4q98t829qpkp8u9zzn2ule4yqmxn5mh",
    "bcrt1q7s8zrsslayc7l2u6u6pcer7h826unf4zcj9nr7",
    "bcrt1qw85cq2utwd2rn2p9t3fk0lhjjvgmejr99xddvl",
    "bcrt1qhsd7cur0c5c02j0yvu3p588fkw0je3qjvleugd",
    "bcrt1q63t7hsp4v35smjj9wf3wuge87tvsaezkrlpags",
    "bcrt1qaujehpf5wrw7vf62r5f5edfrud44xjdqwpxyvs",
    "bcrt1q5pvgp0k8up9f5l2yszz2ga5ljt44jfc7p7e4ae",
    "bcrt1q20n0m87vcwt4d9x5nf6cfmp48appxvygnsw5rf",
    "bcrt1qkneksyjmhk78pdf48rmd49c9m3rv70c25q2tg2",
    "bcrt1qwtgrxxvxz4tdzfrpdak6duckayxrran4a364r3",
    "bcrt1qfxf9ry665ngaazkc3v4slamazx7hj8fpkn0r85",
    "bcrt1qrf5kz9a085xrdd73t3sdqj4mvmejhx74pj4wu7",
    "bcrt1qdve4ukg3xk9dqwhpefx2ayh2ga4dkeag7z98yu",
    "bcrt1qmzq4yp0r5mdkj3mqqsy8xsqt7wtv6kvmcyu2gp",
    "bcrt1qkzc797ev9qtupcds0uzjev8h948ef0t7flgahx",
    "bcrt1qvlkkjaxgee8n2lkzsqjuzap2q9h0qf7lya87ds",
    "bcrt1q6a68rs477h3xyshxn7wdd9c0vzwxx6w5w7du0m",
    "bcrt1qu92j43cgcgpgjlf2thgq9lya0yta54la00adq0",
    "bcrt1qy0mj2h55djtd2w3uqlm00vl3k8cp8j4dm752v5"
]


LIST_CHANNELS = [
    CHANNEL_OPENING,
    CHANNEL_OPEN,
    CHANNEL_CLOSED,
    CHANNEL_FUNDED
]


LIST_INVOICES = [
    {
        "amount": 1000000,
        "amount_BTC": "0.01",
        "exp": 3600,
        "invoice": "lnbcrt10m1p083qdmpp5wk09xle9nm0lm79l54782r4w9h8zskk7m2zd0e655x7lwp5rqj5qdqqcqzynxqrrssgx5uj23qhw50clkthp9jj5599sazlazv2ltlg3gtlrl407s6jpvyl3a3hp67nkurks4vavuhcnpjn5rvtwt6ha4x0vjj3trdmc3gwncpq4uq73",
        "message": "Thanks for all the fish!",
        "rhash": "759e537f259edffdf8bfa57c750eae2dce285adeda84d7e754a1bdf7068304a8",
        "status": 0,
        "status_str": "Expires in about 1 hour",
        "time": 1584955835,
        "type": 2
    },
    {
        "amount": 42000,
        "amount_BTC": "0.00042",
        "exp": 3600,
        "invoice": "lnbcrt420u1p0xupm7pp5vd0rrtjvq7rxq22s56wgqs8skfdhx2gv30vgehplw3p8yhdtpg6qdqqcqzynxqrrssrzjqf98wpm6t5rckh7667cd0kpr53qevc2x6ygup7e8mux2z4j403fguqqtjgqqqqsqqqqqqqqqqqqqqqqqqyy82z7cz9lt5l4w04zlagq50zt3ul403uumf4ljyd8mkpcksw6evxa4zes292gwwpz0qp24ftcqvreepje3mlfyngdxw272nt02wpgccpehpwnc",
        "message": "",
        "rhash": "635e31ae4c0786602950a69c8040f0b25b73290c8bd88cdc3f7442725dab0a34",
        "status": 1,
        "status_str": "Expired",
        "time": 1584269382,
        "type": 2
    },
    {
        "amount": 42000,
        "amount_BTC": "0.00042",
        "exp": 3600,
        "invoice": "lnbcrt420u1p0xupm7pp5vd0rrtjvq7rxq22s56wgqs8skfdhx2gv30vgehplw3p8yhdtpg6qdqqcqzynxqrrssrzjqf98wpm6t5rckh7667cd0kpr53qevc2x6ygup7e8mux2z4j403fguqqtjgqqqqsqqqqqqqqqqqqqqqqqqyy82z7cz9lt5l4w04zlagq50zt3ul403uumf4ljyd8mkpcksw6evxa4zes292gwwpz0qp24ftcqvreepje3mlfyngdxw272nt02wpgccpehpwnc",
        "message": "",
        "rhash": "635e31ae4c0786602950a69c8040f0b25b73290c8bd88cdc3f7442725dab0a34",
        "status": 2,
        "status_str": "Unknown",
        "time": 15842691823,
        "type": 2
    },
    {
        "amount": 1000000,
        "amount_BTC": "0.01",
        "exp": 3600,
        "invoice": "lnbcrt10m1p09y4y6pp5z4g4h34cepd6432ewn9rv63ddq4323vr850824yqv70mfcapgu9sdqqcqzynxqrrssrzjqf98wpm6t5rckh7667cd0kpr53qevc2x6ygup7e8mux2z4j403fguqqtjgqqqqsqqqqqqqqqqqqqqqqqqyxqfslt2l7z7vfsftr9cfxq9n3nwenmuy5hn8z24g6zdfzlv46ce46mq6hkwh76xn7m95n0zq530hv9h4ky9u04uwudlhh90a949z8vspwvvp2m",
        "message": "",
        "rhash": "15515bc6b8c85baac55974ca366a2d682b1545833d1e755480679fb4e3a1470b",
        "status": 3,
        "status_str": "Paid",
        "time": 1582453914,
        "type": 2
    },
    {
        "amount": 42000,
        "amount_BTC": "0.00042",
        "exp": 3600,
        "invoice": "lnbcrt420u1p0xupm7pp5vd0rrtjvq7rxq22s56wgqs8skfdhx2gv30vgehplw3p8yhdtpg6qdqqcqzynxqrrssrzjqf98wpm6t5rckh7667cd0kpr53qevc2x6ygup7e8mux2z4j403fguqqtjgqqqqsqqqqqqqqqqqqqqqqqqyy82z7cz9lt5l4w04zlagq50zt3ul403uumf4ljyd8mkpcksw6evxa4zes292gwwpz0qp24ftcqvreepje3mlfyngdxw272nt02wpgccpehpwnc",
        "message": "",
        "rhash": "635e31ae4c0786602950a69c8040f0b25b73290c8bd88cdc3f7442725dab0a34",
        "status": 4,
        "status_str": "In flight",
        "time": 1584469182,
        "type": 2
    },
    {
        "amount": 42000,
        "amount_BTC": "0.00042",
        "exp": 3600,
        "invoice": "lnbcrt420u1p0xupm7pp5vd0rrtjvq7rxq22s56wgqs8skfdhx2gv30vgehplw3p8yhdtpg6qdqqcqzynxqrrssrzjqf98wpm6t5rckh7667cd0kpr53qevc2x6ygup7e8mux2z4j403fguqqtjgqqqqsqqqqqqqqqqqqqqqqqqyy82z7cz9lt5l4w04zlagq50zt3ul403uumf4ljyd8mkpcksw6evxa4zes292gwwpz0qp24ftcqvreepje3mlfyngdxw272nt02wpgccpehpwnc",
        "message": "",
        "rhash": "635e31ae4c0786602950a69c8040f0b25b73290c8bd88cdc3f7442725dab0a34",
        "status": 5,
        "status_str": "Failed",
        "time": 1584260182,
        "type": 2
    },
    {
        "amount": 42000,
        "amount_BTC": "0.00042",
        "exp": 3600,
        "invoice": "lnbcrt420u1p0xupm7pp5vd0rrtjvq7rxq22s56wgqs8skfdhx2gv30vgehplw3p8yhdtpg6qdqqcqzynxqrrssrzjqf98wpm6t5rckh7667cd0kpr53qevc2x6ygup7e8mux2z4j403fguqqtjgqqqqsqqqqqqqqqqqqqqqqqqyy82z7cz9lt5l4w04zlagq50zt3ul403uumf4ljyd8mkpcksw6evxa4zes292gwwpz0qp24ftcqvreepje3mlfyngdxw272nt02wpgccpehpwnc",
        "message": "",
        "rhash": "635e31ae4c0786602950a69c8040f0b25b73290c8bd88cdc3f7442725dab0a34",
        "status": 6,
        "status_str": "Routing",
        "time": 1574269182,
        "type": 2
    },
    {
        "amount": 1000000,
        "amount_BTC": "0.01",
        "exp": 3600,
        "invoice": "lnbcrt10m1p083qdmpp5wk09xle9nm0lm79l54782r4w9h8zskk7m2zd0e655x7lwp5rqj5qdqqcqzynxqrrssgx5uj23qhw50clkthp9jj5599sazlazv2ltlg3gtlrl407s6jpvyl3a3hp67nkurks4vavuhcnpjn5rvtwt6ha4x0vjj3trdmc3gwncpq4uq73",
        "message": "",
        "rhash": "759e537f259edffdf8bfa57c750eae2dce285adeda84d7e754a1bdf7068304a8",
        "time": 1584955835,
        "type": 2
    }
]


LIST_PEERS = [
    {
        "address": "c-lightning:9738",
        "channels": [
            "0d4fc5080d3deffc04871c8cbba19592b68d00b95656c0fb02137658a29abe3a:0",
            "ad30a8547a2ed09a1bfa2eb6969f19ea313a6095f41df61079c30691ece0a47c:0",
            "184598135c20591ae91197277d6cc6a83d31a0c14a15531fb67a8bc0d86ce8ba:0",
            "285c7dae46a93a7c7db08be01f89c27005c80cffb2e0b2df6fc252cc20e8daf0:0"
        ],
        "initialized": True,
        "node_id": "039613cbfa2f2887fa14b7be685d30e2ede74ba838346239aa5f91ee4255d972a6"
    },
    {
        "address": "electrum_bob:9736",
        "channels": [
            "082128ccacfa0f4d3ac6cbe6e643c7df5d13c70abf1b6ba0da52436ec182902e:0",
            "f1f3991ce3a4e12c3cb3fc4605edf6034f0e62e5c9cc66f9f4ac945e3399ce36:0",
            "ab2688e55c9b6666c9a0b701f70a4a953dc76145e2a7ae17549df8d595c9608c:0"
        ],
        "initialized": True,
        "node_id": "0328b6b5f3b348b0c503962a7d5f830db96937951ee7f3e83c7a844656bb151131"
    }
]


LIST_TRANSACTIONS = {
    "summary": {
        "end_balance": "99.6976311",
        "end_date": None,
        "incoming": "100.3038742",
        "outgoing": "0.6062431",
        "start_balance": "0.",
        "start_date": None
    },
    "transactions": [
        {
            "bc_balance": "100.",
            "bc_value": "100.",
            "confirmations": 408,
            "date": "2020-02-22 17:30",
            "fee": None,
            "fee_sat": None,
            "height": 2659,
            "incoming": True,
            "label": "",
            "monotonic_timestamp": 1582392608,
            "timestamp": 1582392608,
            "txid": "3386ee526e1c58f70f46f0b880030f9d98ce90c41377c9c8020e91f7c18e5f16",
            "txpos_in_block": 2
        },
        {
            "bc_balance": "99.6997246",
            "bc_value": "-0.3002754",
            "confirmations": 307,
            "date": "2020-02-22 17:32",
            "fee": "0.0002754",
            "fee_sat": 27540,
            "height": 2760,
            "incoming": False,
            "label": "Open channel",
            "monotonic_timestamp": 1582392734,
            "timestamp": 1582392734,
            "txid": "a3b5048ab7cc337fc3e66444377a7202808f7e3d8c54140af902942f3d1ce4d3",
            "txpos_in_block": 2
        },
        {
            "bc_balance": "99.69490649",
            "bc_value": "-0.00421691",
            "confirmations": 4,
            "date": "2020-03-15 11:43",
            "fee": "0.00001692",
            "fee_sat": 1692,
            "height": 3063,
            "incoming": False,
            "label": "",
            "monotonic_timestamp": 1584272603,
            "timestamp": 1584272603,
            "txid": "acd0179da8700f1622f4d4a65739326315297d8942589e332ddd9154d7780dc4",
            "txpos_in_block": 2
        },
        {
            "bc_balance": "99.69910649",
            "bc_value": "0.0042",
            "confirmations": 3,
            "date": "2020-03-16 17:01",
            "fee": None,
            "fee_sat": None,
            "height": 3064,
            "incoming": True,
            "label": "",
            "monotonic_timestamp": 1584378081,
            "timestamp": 1584378081,
            "txid": "a9c99edba1c6bb00163a24f3abec76743ac061bcba4006d19e25b6086a5f1d18",
            "txpos_in_block": 1
        },
        {
            "bc_balance": "99.6976311",
            "bc_value": "-0.00147539",
            "confirmations": 2,
            "date": "2020-03-16 17:02",
            "fee": "0.0002754",
            "fee_sat": 27540,
            "height": 3065,
            "incoming": False,
            "label": "Open channel",
            "monotonic_timestamp": 1584378127,
            "timestamp": 1584378127,
            "txid": "8236ad29560c65e580e962f02228f0ff1b4c4ada9269a33a8aec33492ed13af1",
            "txpos_in_block": 1
        }
    ]
}


LNPAY_SUCCESS = {
    "payment_hash": "6593df0299705c7cfc1f7ff0a5efb44722c85994a4985637c4098946a1da6310",
    "preimage": "198c19d4ad88a299c718a92cab85b6e904ffa0d261af14b9b54552000e3dafa6",
    "success": True
}


LNPAY_EXPIRED = 'This invoice has expired'


NODEID = '03512f7e9432bc29e987ee7c18712f9aecf4ae6244e6b4a8cf0bc79b65d8cfccec@0.0.0.0:9735'


NODEID_INCOMPLETE = '03512f7e9432bc29e987ee7c18712f9aecf4ae6244e6b4a8cf0bc79b65d8cfccec'


OPEN_CHANNEL = 'b3c6ba3014fbadb34aee3a340c763d0389ece520e524de5a748eb01367400b88:0'


PAYMENTS = [
    {
        "amount_msat": -15000000000,
        "balance_msat": 6000000000,
        "date": "2020-02-23 11:48",
        "direction": "sent",
        "fee_msat": 0,
        "label": "",
        "payment_hash": "3b7b531f24a06484a02565e578ec51decae185737aaddce6a93dcd56d3f43b4d",
        "preimage": "16e2baaaad4ad56a63ed3bc0f002612a471fe3418ba8e939b54620a0b0601236",
        "timestamp": 1582458505,
        "type": "payment"
    },
    {
        "amount_msat": -30000000000,
        "balance_msat": 0,
        "channel_id": "d3e41c3d2f9402f90a14548c3d7e8f8002727a374464e6c37f33ccb78a04b5a3",
        "direction": "sent",
        "fee_msat": None,
        "label": "Close channel",
        "timestamp": 1582392839,
        "txid": "0c26c370449871a3b8f8b27d8c5f878b178f1b15ea02853129b2160849faedda",
        "type": "channel_closure"
    },
    {
        "amount_msat": 1000000000,
        "balance_msat": 21000000000,
        "date": "2020-02-23 10:32",
        "direction": "received",
        "fee_msat": None,
        "label": "",
        "payment_hash": "15515bc6b8c85baac55974ca366a2d682b1545833d1e755480679fb4e3a1470b",
        "preimage": "5a3b5fe13c0a747f4f44e6b0f0b75bbc7d5b1a938a484956190a3d22e71a360c",
        "timestamp": 1582453942,
        "type": "payment"
    },
    {
        "amount_msat": 30000000000,
        "balance_msat": 30000000000,
        "channel_id": "d3e41c3d2f9402f90a14548c3d7e8f8002727a374464e6c37f33ccb78a04b5a3",
        "direction": "received",
        "fee_msat": None,
        "label": "Open channel",
        "timestamp": 1582392734,
        "txid": "a3b5048ab7cc337fc3e66444377a7202808f7e3d8c54140af902942f3d1ce4d3",
        "type": "channel_opening"
    },
]


PAYTO = '02000000000101c8db14b9604256139344a59a098dbe8cf120f1fdaa98686f16c332d029bf34a20100000000fdffffff02801d2c0400000000160014da0ba0ffb05e29b4cb17b3f910ffb27527239947cca31d4d02000000160014b0b1e2fb2c2817c0e1b07f052cb0f72d4f94bd7e02483045022100b3d8740ecc57c37e176f711cc52b1b7c58a49a93b8d91169b8fd04acd63ad06c022067903c112fd42c55350af18d48c034bd513002b1459615784e27a1460aa8f936012102629eadf818aea8892ea8c752efd27172151ade4cc7ae6589bcff5c3462221abb00000000'


UNKNOWN_CHANNEL_ID = "f0dae820cc52c26fdfb2e0b2ff0cc80570c2891fe08bb07d7c3aa946ae7d5c28"
