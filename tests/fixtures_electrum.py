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


CHANNEL_CLOSED = {
    "channel_id": "208x4x0",
    "channel_point": "4830ebc404575f9c9e689f6a9aabfc1e089e511fff415166cb452059d37194a4:0",
    "full_channel_id": "a49471d3592045cb665141ff1f519e081efcab9a6a9f689e9c5f5704c4eb3048",
    "local_balance": 10999999,
    "local_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_balance": 1,
    "remote_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_pubkey": "03749407fa51c2fba5078b0b8b970052922f5b249b38e776337665bb048c187644",
    "state": "CLOSED"
}


CHANNEL_CLOSING = {
    "state": "CLOSING"
}


CHANNEL_FORCE_CLOSING =     {
    "channel_id": None,
    "channel_point": "c1df9960de5cdb42bbf6e0cadfc059c9ff7a76e9a68c036659e272aff76e9f15:0",
    "full_channel_id": "159f6ef7af72e25966038ca6e9767affc959c0dfcae0f6bb42db5cde6099dfc1",
    "local_balance": 90000,
    "local_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_balance": 10000,
    "remote_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_pubkey": "038f548556317329f59ee3a049583e0f3fc571c8955595ce44a6f729cabd92cf0c",
    "state": "FORCE_CLOSING"
}


CHANNEL_FUNDED = {
    "channel_id": "317x1x0",
    "channel_point": "435a7de6908f0795c4b0349eb865a01063020e016df957a5ee5be059af3a7af4:0",
    "full_channel_id": "f47a3aaf59e05beea557f96d010e026310a065b89e34b0c495078f90e67d5a43",
    "local_balance": 0,
    "local_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_balance": 15000000,
    "remote_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_pubkey": "02d8b1ef1197b36afe907b13b96068f49f592cc847e210e1b7a7e6e10ecb556363",
    "state": "FUNDED"
}


CHANNEL_OPEN = {
    "channel_id": "208x1x0",
    "channel_point": "26f257a6757631a03781099f5380d3cb927e9bfb5e7408cd5bc1d0c4daaf1029:0",
    "full_channel_id": "2910afdac4d0c15bcd08745efb9b7e92cbd380539f098137a0317675a657f226",
    "local_balance": 11905000,
    "local_htlcs": {
        "adds": {},
        "ctn": 2,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_balance": 95000,
    "remote_htlcs": {
        "adds": {
            "0": [
                5000000,
                "35d97eae701e05fca03c1653731519af432439d0e22522232a96483684ccd531",
                362,
                0,
                1574608495
            ]
        },
        "ctn": 2,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {
            "0": {
                "-1": 1,
                "1": 1
            }
        },
        "next_htlc_id": 1,
        "revack_pending": False,
        "settles": {
            "0": {
                "-1": 2,
                "1": 2
            }
        }
    },
    "remote_pubkey": "03749407fa51c2fba5078b0b8b970052922f5b249b38e776337665bb048c187644",
    "state": "OPEN"
}


CHANNEL_OPENING = {
    "channel_id": None,
    "channel_point": "c61765314a2289eae3e3edcd2f30f63b07a3a572ea9b8220c342bef2e68eadb8:0",
    "full_channel_id": "b8ad8ee6f2be42c320829bea72a5a3073bf6302fcdede3e3ea89224a316517c6",
    "local_balance": 14000000,
    "local_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_balance": 0,
    "remote_htlcs": {
        "adds": {},
        "ctn": 0,
        "fails": {},
        "fee_updates": [
            [
                45000,
                {
                    "-1": 0,
                    "1": 0
                }
            ]
        ],
        "locked_in": {},
        "next_htlc_id": 0,
        "revack_pending": False,
        "settles": {}
    },
    "remote_pubkey": "02499549bb401fd403bac331057f99c2a6ecc39d081b7d9aa50f3487a9d3cf5009",
    "state": "OPENING"
}


CHANNEL_UNKNOWN = {
    "state": "NOT MAPPED"
}


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


NODEID = '03512f7e9432bc29e987ee7c18712f9aecf4ae6244e6b4a8cf0bc79b65d8cfccec@0.0.0.0:9735'


NODEID_INCOMPLETE = '03512f7e9432bc29e987ee7c18712f9aecf4ae6244e6b4a8cf0bc79b65d8cfccec'


OPEN_CHANNEL = 'b3c6ba3014fbadb34aee3a340c763d0389ece520e524de5a748eb01367400b88:0'


PAYTO = '02000000000101c8db14b9604256139344a59a098dbe8cf120f1fdaa98686f16c332d029bf34a20100000000fdffffff02801d2c0400000000160014da0ba0ffb05e29b4cb17b3f910ffb27527239947cca31d4d02000000160014b0b1e2fb2c2817c0e1b07f052cb0f72d4f94bd7e02483045022100b3d8740ecc57c37e176f711cc52b1b7c58a49a93b8d91169b8fd04acd63ad06c022067903c112fd42c55350af18d48c034bd513002b1459615784e27a1460aa8f936012102629eadf818aea8892ea8c752efd27172151ade4cc7ae6589bcff5c3462221abb00000000'
