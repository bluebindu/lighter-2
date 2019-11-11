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

""" Fixtures for test_light_clightning module """


TXID = "3cd3ffcbe695e53f92b057baec9a6fff3f936702512769129eb1053b0350e351"
ADDRESS = "n1ER93kV9ox9ccrA4fxGZa9JXEGnhLDGnF"

NODE_ID = "021f7b8bbfbca12b6520683fe39aa80316b729b49db6735a164ad019f81485a684"
HOST = "snoopy"
PORT = 9735
NODE_URI = '{}@{}:{}'.format(NODE_ID, HOST, PORT)

BADRESPONSE = {
    "code" : -32601,
    "message" : "A strange error occurred"
}


CHANNEL_AWAITING_LOCKIN = {
   "state" : "CHANNELD_AWAITING_LOCKIN",
   "scratch_txid" : "931c0cf0e56685c24c1f0340e67e433509ca3b2ad24bf051f6ef7050ab98840e",
   "short_channel_id" : "1454271x65x0",
   "direction" : 1,
   "channel_id" : "fe262d44dd800ac46ae705cfb9bd1fe530b65a943cbc3a485b45a45d9c70897a",
   "funding_txid" : "7a89709c5da4455b483abc3c945ab630e51fbdb9cf05e76ac40a80dd442d26fe",
   "private" : False,
   "funding_allocation_msat" : {
      "024286158184e3ad3601289f0900c1d4af5c72d97f01e9aafa3b97d2c9ab13ede5" : 0,
      "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : 200000000
   },
   "funding_msat" : {
      "024286158184e3ad3601289f0900c1d4af5c72d97f01e9aafa3b97d2c9ab13ede5" : "0msat",
      "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : "200000000msat"
   },
   "msatoshi_to_us" : 200000000,
   "to_us_msat" : "200000000msat",
   "msatoshi_to_us_min" : 200000000,
   "min_to_us_msat" : "200000000msat",
   "msatoshi_to_us_max" : 200000000,
   "max_to_us_msat" : "200000000msat",
   "msatoshi_total" : 200000000,
   "total_msat" : "200000000msat",
   "dust_limit_satoshis" : 546,
   "dust_limit_msat" : "546000msat",
   "max_htlc_value_in_flight_msat" : 18446744073709551615,
   "max_total_htlc_in_msat" : "18446744073709551615msat",
   "their_channel_reserve_satoshis" : 2000,
   "their_reserve_msat" : "2000000msat",
   "our_channel_reserve_satoshis" : 2000,
   "our_reserve_msat" : "2000000msat",
   "spendable_msatoshi" : 197774000,
   "spendable_msat" : "197774000msat",
   "htlc_minimum_msat" : 0,
   "minimum_htlc_in_msat" : "0msat",
   "their_to_self_delay" : 6,
   "our_to_self_delay" : 144,
   "max_accepted_htlcs" : 483,
   "status" : [
      "CHANNELD_AWAITING_LOCKIN:Attempting to reconnect"
   ],
   "in_payments_offered" : 0,
   "in_msatoshi_offered" : 0,
   "in_offered_msat" : "0msat",
   "in_payments_fulfilled" : 0,
   "in_msatoshi_fulfilled" : 0,
   "in_fulfilled_msat" : "0msat",
   "out_payments_offered" : 0,
   "out_msatoshi_offered" : 0,
   "out_offered_msat" : "0msat",
   "out_payments_fulfilled" : 0,
   "out_msatoshi_fulfilled" : 0,
   "out_fulfilled_msat" : "0msat",
   "htlcs" : []
}


CHANNEL_AWAITING_UNILATERAL = {
   "state" : "AWAITING_UNILATERAL",
   "status" : [],
}


CHANNEL_CLOSED = {
   "state" : "CLOSED",
   "status" : [],
}


CHANNEL_MUTUAL = {
     "state" : "ONCHAIN",
     "status" : [
        "CLOSINGD_SIGEXCHANGE:We agreed on a closing fee of 183 satoshi for tx:8f2fc20d68965d211db1c944769f771b55910e6a6c6ce65ab1972308387643ea",
        "ONCHAIN:Tracking mutual close transaction"
     ],
}


CHANNEL_NORMAL = {
   "state" : "CHANNELD_NORMAL",
   "status" : [
      "CHANNELD_NORMAL:Reconnected, and reestablished.",
      "CHANNELD_NORMAL:Funding transaction locked."
   ],
}


CHANNEL_RESOLVED = {
   "state" : "ONCHAIN",
    "status" : [
      "ONCHAIN:Tracking our own unilateral close",
      "ONCHAIN:All outputs resolved: waiting 81 more blocks before forgetting channel"
   ],
}


CHANNEL_SHUTTING_DOWN = {
   "state" : "CHANNELD_SHUTTING_DOWN",
   "status" : [],
}


CHANNEL_UNILATERAL = {
    "state" : "ONCHAIN",
    "status" : [
      "CHANNELD_AWAITING_LOCKIN:Reconnected, and reestablished.",
      "ONCHAIN:Tracking our own unilateral close",
      "ONCHAIN:2 outputs unresolved: in 143 blocks will spend DELAYED_OUTPUT_TO_US (c68a9dd676c32e09280a9656fef9fe25854cb1f130ded3e8b4f4207c3af72d61:0) using OUR_DELAYED_RETURN_TO_WALLET"
   ],
}


CHANNEL_UNKNOWN = {
   "state" : "UNKNOWN",
   "status" : [
      "CHANNELD_NORMAL:Attempting to reconnect"
   ],
}


CLOSE_FORCED = {
    "tx" : "020000000170ddc5fdf8115c9610bc81b793f7716bb2551c83380d6187c0172b4bc9c4eb1f0000000000da9a688001334c030000000000160014b459db3caf2b397e934fd3051b138e223ae29fbcbd36fc20",
    "txid" : "3359e521f63527847c739071a129afe0a4705bb1b805ea20cf5b2dbe36409f77",
    "type" : "unilateral"
}

CLOSE_MUTUAL = {
    "tx" : "0200000001fbbbca3ec48dc4ffd6f72ab47cba8f6e693717d1fd75d3eb2095ce28fb19285c0000000000ffffffff01694d000000000000160014cdb5837e5330e8c981d94f00514388328badde8500000000",
    "txid" : "0332da7696c4d22bb0bffbb3bf49e257e1834469b70cd2737aa1a43437e0cf16",
    "type" : "mutual"
}


CONNECT = {
    "id": "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7"
}


DECODEPAY = {
    "currency": "tb",
    "timestamp": 1533127505,
    "created_at": 1533127505,
    "expiry": 3600,
    "payee": "02212d3ec887188b284dbb7b2e6eb40629a6e14fb049673f22d2a0aa05f902090e",
    "msatoshi": 700000,
    "description": "Funny\r",
    "min_final_cltv_expiry": 144,
    "fallback": {
    "type": "P2SH",
    "addr": "2NENXARsztTVBv1ZyJMMVF1YPGfgS5eejgC",
    "hex": "a914e7bbe3dd9222d49c6d6c8c31e89c9afe8d2cd08b87"
    },
    "fallbacks": [
        {
        "type": "P2SH",
        "addr": "2NENXARsztTVBv1ZyJMMVF1YPGfgS5eejgC",
        "hex": "a914e7bbe3dd9222d49c6d6c8c31e89c9afe8d2cd08b87"
        }
    ],
    "routes": [
        [
            {
            "pubkey": "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
            "short_channel_id": "66051:263430:1800",
            "fee_base_msat": 1,
            "fee_proportional_millionths": 20,
            "cltv_expiry_delta": 3
            },
            {
            "pubkey": "039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
            "short_channel_id": "197637:395016:2314",
            "fee_base_msat": 2,
            "fee_proportional_millionths": 30,
            "cltv_expiry_delta": 4
            }
        ],
        [
            {
            "pubkey": "03a901b85534f431f7ce72046060fcf7a95c37e17vdbfd",
            "short_channel_id": "66051:263430:1800",
            "fee_base_msat": 1,
            "fee_proportional_millionths": 20,
            "cltv_expiry_delta": 3
            },
            {
            "pubkey": "5534ff1e92c43c74431f7ce720460695c37e148f78c7",
            "short_channel_id": "197637:395016:2314",
            "fee_base_msat": 2,
            "fee_proportional_millionths": 30,
            "cltv_expiry_delta": 4
            }
        ]
    ],
    "payment_hash": "b6fac49eac5b36bb6699e716645ddf4d823746ea522c3d3ebde2f04f9a652ec0",
    "signature": "3045022100f5540c34548000e1cdd4182fb495ea72a99478055cd16e37cd8c6f58f4bf5e1502202daeb0ed00b252f8580e58080d21e1af6237eb69442ebd2b34724dafc6aa021e"
}


DECODEPAY_HASH = {
    "currency": "tb",
    "timestamp": 1496314658,
    "created_at": 1496314658,
    "expiry": 3600,
    "payee": "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
    "msatoshi": 150000,
    "description_hash": "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1",
    "min_final_cltv_expiry": 9,
    "fallback": {
        "type": "P2PKH",
        "addr": "mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP",
        "hex": "76a9143172b5654f6683c8fb146959d347ce303cae4ca788ac"
    },
    "fallbacks": [
        {
        "type": "P2PKH",
        "addr": "mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP",
        "hex": "76a9143172b5654f6683c8fb146959d347ce303cae4ca788ac"
        }
    ],
    "payment_hash": "0001020304050607080900010203040506070809000102030405060708090102",
    "signature": "3045022100b6c42b8a61e0dc5823ea63e76ff148ab5f6c86f45f9722af0069c7934daff70d02205e315893300774c897995e3a7476c8193693d144a36e2645a0851e6ebafc9d0a"
}

FUNDCHANNEL = {
    "tx": "02000000010101fe262d44dd800ac48ae705cfb9bd1fe530b65a943cmc3a485b45n45d9c78897a0100000000ffffffff028813000000000000220020a7e840446feec8abbd6fd46ab00f6bb9e4d31e3ef9a4a838baa49f2dc285be32455f1b0000000000160014d94011695c18dc960f623e1a3d4d5d9addee736a02473044022036dcbac2e037d008b43817a4c0042483d9b5d8c0b69f5994b5ab7aa4a227684702201c315db296ae3477f5e0d0a55b06fc003bd9ffbb1cadc0ab00a9d9e70125a26e0121038f216727e40648c1b1fcc740d8b98883ae120d66ea607abdd75f9f05d5058cb000000000",
    "txid": "87b91526fea6ca52fe3cb8b569d4406a2d62alyd5cb9ceb63d2a96p11573040f",
    "channel_id": "0f047315e1962a3db6mib95cbdae622d6a40d488b5b83cfe5k8aa6fe2615b987"
}


GETINFO = {
   "id" : "022d558f74f2ab2a78d29ebf",
   "alias" : "pie",
   "color" : "dcdcdc",
   "num_peers" : 4,
   "num_pending_channels" : 1,
   "num_active_channels" : 3,
   "num_inactive_channels" : 0,
   "address" : [
      {
         "type" : "ipv4",
         "address" : "30.107.77.66",
         "port" : 9735
      }
   ],
   "binding" : [
      {
         "type" : "ipv4",
         "address" : "0.0.0.0",
         "port" : 9735
      }
   ],
   "version" : "v0.7.0-331-g12f703e",
   "blockheight" : 1519674,
   "network" : "bitcoin",
   "msatoshi_fees_collected" : 4,
   "fees_collected_msat" : "4msat"
}


INVOICE = {
    "payment_hash": "0a0d9938df88a1c54bfdf254df8eee4b89952f88c5a8321769887f4a4a187997",
    "expiry_time": 1533236108,
    "expires_at": 1533236108,
    "bolt11": "lntb7770p1pdkx3tupp5pgxejwxl3zsu2jla7f2dlrhwfwye2tugck5ry9mf3pl55jsc0xtsdqgv3jkgetycqp2fppjxz8lt4k8dht5kwv7juk2php3rrjp46tmung4gj8f3vf644tcf0u6quazcnntv4whw7ez9hg7su9shqg5vcr958ue8klxmaepqsa6ca78m84p8pcdakk6ws8r2ftscp4uxs6pktcqv24m2w"
}


LISTFUNDS =  {
    "outputs": [
        {
        "txid": "f1279a0ab804d5cd1da4fc49eaf76d66931a07fe59e40793a6920ec116fca544",
         "output": 0,
         "value": 7,
         "address": "2NBMywMRM6pgH1TQHM1sSnGFPcVYNi6cuFJ",
         "status": "confirmed"
        },
        {
        "txid": "6e801bb303d594feb1cc3794bb89fb391e38405753ac68b3cdcee793c51ee369",
         "output": 0,
         "value": 7,
         "address": "2NBMywMRM6pgH1TQHM1sSnGFPcVYNi6cuFJ",
         "status": "confirmed"
        }
    ],
    "channels": [
        {
        "peer_id": "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
        "short_channel_id": "1323814:55:0",
        "channel_sat": 700,
        "channel_total_sat": 5000000,
        "funding_txid": "b8df6b4fa5cffa8a91cce9916857732aaad8c1777212273149654dde5724d3bd"
        },
        {
        "peer_id": "02212d3ec887188b284dbb7b2e6eb40629a6e14fb049673f22d2a0aa05f902090e",
        "short_channel_id": "1326418:102:0",
        "channel_sat": 300,
        "channel_total_sat": 1000000,
        "funding_txid": "8f2050464b358706fdf334ca0c585296391792ee292300e4fb45dd4f602716e0"
        }
    ]
}


LISTFUNDS_EMPTY =  {
    "outputs": [],
    "channels": []
}


LISTINVOICES = {
    "invoices": [
        {
        "label": "1530107849998017",
        "bolt11": "lntb95u1pdn8972pp50qdfxxv7ta4j6ysmdhccxfpk4l2zwa6j7mtr4rvrnl9t3fsk4umqdq4f4sku6fqv9kzqsmfv4kx7cqp20g9zn3ql77gsy7hrztmxk5c46ds9fxpgg044u6rgnhfls8hp5r6qr58lvysxhqh6fc0nwq4fl98xdaqqqf2wj9k",
        "payment_hash": "781a93199e5f6b2d121b6df1832436afd4277752f6d63a8d839fcab8a616af36",
        "msatoshi": 9500000,
        "expires_at": 1530111450
        },
        {
        "label": "1530109997580457",
        "bolt11": "lntb229u1pdn8gpdpp5xqkdd0yd6gzrw9e0frvxj0rsn875edks3clc2xd5q6ep3qr80v5qdq4f4sku6fqv9kzqsmfv4kx7cqp273znjcccuf05uhzqzudwajttvqnpv7n6m59d5w3vnf52dzmmp6e8jafcuswxescfzyhr739l4y87q08q5e3grj4s708qc",
        "payment_hash": "302cd6bc8dd20437172f48d8693c7099fd4cb6d08e3f8519b406b21880677b28",
        "msatoshi": 22900000,
        "status": "paid",
        "pay_index": 1,
        "msatoshi_received": 22900000,
        "paid_timestamp": 1530110044,
        "paid_at": 1530110044,
        "expires_at": 1530113597
        },
        {
        "label": "1532635410687064",
        "bolt11": "lntb77u1pd452gjpp5yg5mynrjsvnw9tdjcctx6wayxta63pnk0rrd909q3vzv5zfz02tsdq8vdsku6gxqrpcgcqp2fppjl4ur87pe08uc97cady9j5w9la8ler3k2wyl37ye6h5rwaqhvd7794q753d9lpywr8q7pt7radexsu338pm08asyx4upchktuk",
        "payment_hash": "2229b24c728326e2adb2c6166d3ba432fba8867678c6d2bca08b04ca09227a97",
        "msatoshi": 7700000,
        "status": "expired",
        "expires_at": 1532637210
        },
        {
        "label": "153245487712131",
        "bolt11": "lntb70p1pdkpz47pp5d3jxdeg5cfkmzjwcsqdezr3zqyuse7n3z2l57skwqxyhkhlcxpvqdqzvscqp2qnpqts0tr2zgnndsw2mnrllsd8509cfham5cajhz7z6xvfvugsdq6nu8t2yk8qauauy08u6s3jp50llu52xyd5kz44ra2wsxjccu8fqpxv8qwn",
        "payment_hash": "6c6466e514c26db149d8801b910e2201390cfa7112bf4f42ce01897b5ff83058",
        "msatoshi": 7,
        "amount_msat": "7msat",
        "status": "unpaid",
        "description": "d",
        "expires_at": 1533057230
        }
    ]
}


LISTNODES = {
    "nodes": [
        {
            "nodeid": "02fbjkld9119979caedvvmkf0ada883ff614c6dfnv97382e25d73ec5fnhjbd62df2",
            "alias": "lighter",
            "color": "3399ff",
            "last_timestamp": 1561363407,
            "globalfeatures": "",
            "global_features": "",
            "addresses": [
                {
                    "type": "ipv4",
                    "address": "77.86.231.1",
                    "port": 9735
                }
            ]
        }
    ]
}


LISTPEERS = {
   "peers" : [
      {
         "id" : "0260fcb43c67a014600b2aa5c3847185cf35eb8d862b902693289205884525bb1e",
         "connected" : False,
         "channels" : [
            {
               "state" : "CHANNELD_NORMAL",
               "scratch_txid" : "3359e521f63527847c739071a129afe0a4705bb1b805ea20cf5b2dbe36409f77",
               "short_channel_id" : "1412943x2973x0",
               "direction" : 1,
               "channel_id" : "70ddc5fdf8115c9610bc81b793f7716bb2551c83380d6187c0172b4bc9c4eb1f",
               "funding_txid" : "1febc4c94b2b17c087610d38831c55b26b71f793b781bc10965c11f8fdc5dd70",
               "private" : False,
               "funding_allocation_msat" : {
                  "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : 0,
                  "0260fcb43c67a014600b2aa5c3847185cf35eb8d862b902693289205884525bb1e" : 670000000
               },
               "funding_msat" : {
                  "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : "0msat",
                  "0260fcb43c67a014600b2aa5c3847185cf35eb8d862b902693289205884525bb1e" : "670000000msat"
               },
               "msatoshi_to_us" : 0,
               "to_us_msat" : "0msat",
               "msatoshi_to_us_min" : 0,
               "min_to_us_msat" : "0msat",
               "msatoshi_to_us_max" : 0,
               "max_to_us_msat" : "0msat",
               "msatoshi_total" : 670000000,
               "total_msat" : "670000000msat",
               "dust_limit_satoshis" : 546,
               "dust_limit_msat" : "546000msat",
               "max_htlc_value_in_flight_msat" : 18446744073709551615,
               "max_total_htlc_in_msat" : "18446744073709551615msat",
               "their_channel_reserve_satoshis" : 0,
               "their_reserve_msat" : "0msat",
               "our_channel_reserve_satoshis" : 6700,
               "our_reserve_msat" : "6700000msat",
               "spendable_msatoshi" : 0,
               "spendable_msat" : "0msat",
               "htlc_minimum_msat" : 0,
               "minimum_htlc_in_msat" : "0msat",
               "their_to_self_delay" : 6,
               "our_to_self_delay" : 144,
               "max_accepted_htlcs" : 483,
               "status" : [
                  "CHANNELD_NORMAL:Attempting to reconnect"
               ],
               "in_payments_offered" : 0,
               "in_msatoshi_offered" : 0,
               "in_offered_msat" : "0msat",
               "in_payments_fulfilled" : 0,
               "in_msatoshi_fulfilled" : 0,
               "in_fulfilled_msat" : "0msat",
               "out_payments_offered" : 0,
               "out_msatoshi_offered" : 0,
               "out_offered_msat" : "0msat",
               "out_payments_fulfilled" : 0,
               "out_msatoshi_fulfilled" : 0,
               "out_fulfilled_msat" : "0msat",
               "htlcs" : []
            }
         ]
      },
      {
         "id" : "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
         "connected" : True,
         "netaddr" : [
            "54.236.55.50:9735"
         ],
         "globalfeatures" : "",
         "localfeatures" : "81",
         "channels" : [
            CHANNEL_NORMAL
         ]
      },
      {
         "id" : "024286158184e3ad3601289f0900c1d4af5c72d97f01e9aafa3b97d2c9ab13ede5",
         "connected" : False,
         "channels" : [
            CHANNEL_AWAITING_LOCKIN
         ]
      },
      {
         "id" : "0225f906558f702a826a5a14eefee483d6ea03ea4f2abd62d34114dd9a78d29ebf",
         "connected" : False,
         "channels" : [
            {
               "state" : "CHANNELD_NORMAL",
               "scratch_txid" : "f795c33e59f69dc9150d831e6824b63dfc2f49e8c5c0c09129c3f6fc1ba8f23f",
               "short_channel_id" : "1455914x53x0",
               "direction" : 1,
               "channel_id" : "0f047315e1962a3db6ceb95cbdae622d6a40d488b5b83cfe52caa6fe2615b987",
               "funding_txid" : "87b91526fea6ca52fe3cb8b588d4406a2d62aebd5cb9ceb63d2a96e11573040f",
               "private" : False,
               "funding_allocation_msat" : {
                  "0225f906558f702a826a5a14eefee483d6ea03ea4f2abd62d34114dd9a78d29ebf" : 0,
                  "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : 5000000
               },
               "funding_msat" : {
                  "0225f906558f702a826a5a14eefee483d6ea03ea4f2abd62d34114dd9a78d29ebf" : "0msat",
                  "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : "5000000msat"
               },
               "msatoshi_to_us" : 5000000,
               "to_us_msat" : "5000000msat",
               "msatoshi_to_us_min" : 5000000,
               "min_to_us_msat" : "5000000msat",
               "msatoshi_to_us_max" : 5000000,
               "max_to_us_msat" : "5000000msat",
               "msatoshi_total" : 5000000,
               "total_msat" : "5000000msat",
               "dust_limit_satoshis" : 546,
               "dust_limit_msat" : "546000msat",
               "max_htlc_value_in_flight_msat" : 18446744073709551615,
               "max_total_htlc_in_msat" : "18446744073709551615msat",
               "their_channel_reserve_satoshis" : 546,
               "their_reserve_msat" : "546000msat",
               "our_channel_reserve_satoshis" : 546,
               "our_reserve_msat" : "546000msat",
               "spendable_msatoshi" : 4228000,
               "spendable_msat" : "4228000msat",
               "htlc_minimum_msat" : 0,
               "minimum_htlc_in_msat" : "0msat",
               "their_to_self_delay" : 6,
               "our_to_self_delay" : 6,
               "max_accepted_htlcs" : 483,
               "status" : [
                  "CHANNELD_NORMAL:Attempting to reconnect"
               ],
               "in_payments_offered" : 0,
               "in_msatoshi_offered" : 0,
               "in_offered_msat" : "0msat",
               "in_payments_fulfilled" : 0,
               "in_msatoshi_fulfilled" : 0,
               "in_fulfilled_msat" : "0msat",
               "out_payments_offered" : 0,
               "out_msatoshi_offered" : 0,
               "out_offered_msat" : "0msat",
               "out_payments_fulfilled" : 0,
               "out_msatoshi_fulfilled" : 0,
               "out_fulfilled_msat" : "0msat",
               "htlcs" : []
            }
         ]
      },
      {
         "id" : "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
         "connected" : False,
         "channels" : [
            {
               "state" : "CHANNELD_NORMAL",
               "scratch_txid" : "785c3e98e33d7f300ce1fe95aa67be0067190be5677f6d9772adbc835236208e",
               "short_channel_id" : "1544100x19x0",
               "direction" : 0,
               "channel_id" : "33515ae8c87deea23fe37f80c44918d4d260e44a78d5a5ff0d222df77897c309",
               "funding_txid" : "09c39778f72d220dffa5d5784ae460d2d41849c4807fe33fa2ee7dc8e85a5133",
               "private" : True,
               "funding_allocation_msat" : {
                  "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : 0,
                  "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1" : 500000000
               },
               "funding_msat" : {
                  "030f933df635a4b7ce68cd36f8f25521babe015d1f611775de997d5b35618030ae" : "0msat",
                  "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1" : "500000000msat"
               },
               "msatoshi_to_us" : 0,
               "to_us_msat" : "0msat",
               "msatoshi_to_us_min" : 0,
               "min_to_us_msat" : "0msat",
               "msatoshi_to_us_max" : 0,
               "max_to_us_msat" : "0msat",
               "msatoshi_total" : 500000000,
               "total_msat" : "500000000msat",
               "dust_limit_satoshis" : 546,
               "dust_limit_msat" : "546000msat",
               "max_htlc_value_in_flight_msat" : 18446744073709551615,
               "max_total_htlc_in_msat" : "18446744073709551615msat",
               "their_channel_reserve_satoshis" : 5000,
               "their_reserve_msat" : "5000000msat",
               "our_channel_reserve_satoshis" : 5000,
               "our_reserve_msat" : "5000000msat",
               "spendable_msatoshi" : 0,
               "spendable_msat" : "0msat",
               "htlc_minimum_msat" : 0,
               "minimum_htlc_in_msat" : "0msat",
               "their_to_self_delay" : 6,
               "our_to_self_delay" : 2016,
               "max_accepted_htlcs" : 483,
               "status" : [
                  "CHANNELD_NORMAL:Reconnected, and reestablished."
               ],
               "in_payments_offered" : 0,
               "in_msatoshi_offered" : 0,
               "in_offered_msat" : "0msat",
               "in_payments_fulfilled" : 0,
               "in_msatoshi_fulfilled" : 0,
               "in_fulfilled_msat" : "0msat",
               "out_payments_offered" : 0,
               "out_msatoshi_offered" : 0,
               "out_offered_msat" : "0msat",
               "out_payments_fulfilled" : 0,
               "out_msatoshi_fulfilled" : 0,
               "out_fulfilled_msat" : "0msat",
               "htlcs" : []
            },
         ]
      },
   ]
}


LISTPEERS_EMPTY = {
    "peers": []
}


NEWADDRESS_P2SH_SEGWIT = {
    "p2sh-segwit": "2N875sa6BA9LwVTUviFisQZk"
}


NEWADDRESS_BECH32 = {
    "bech32": "tb1q9v8gmtkhs0qtknj3g3cz"
}


PAY = {
    "id": 6,
    "payment_hash": "90cf883e6c00a5e9071765dde5ffa19ce2746532b8ef3b6c939ac83ff038372f",
    "destination": "02212d3ec887188b284dbb7b2e6eb40629a6e14fb049673f22d2a0aa05f902090e",
    "msatoshi": 150000,
    "msatoshi_sent": 150100,
    "timestamp": 1533122166,
    "created_at": 1533122166,
    "status": "complete",
    "payment_preimage": "d628d988a3a33fde1db8c1b800d16a1135ee030e21866ae24ae9269d7cd41632",
    "getroute_tries": 1,
    "sendpay_tries": 1,
    "route": [
        {
        "id": "02212d3ec887188b284dbb7b2e6eb40629a6e14fb049673f22d2a0aa05f902090e",
        "channel": "1326418:102:0",
        "msatoshi": 150100,
        "delay": 144
        }
    ],
    "failures": []
}

PAYMENTS = {
    "payments": [
        {
            "id": 1,
            "payment_hash": "f7ce87ebee5e5n20641ef17db847224220a8d446c1cf6491a35cde7b27503f3fe",
            "destination": "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
            "msatoshi": 77000,
            "msatoshi_sent": 77033,
            "created_at": 1548680924,
            "status": "complete",
            "payment_preimage": "e333b05b94aaecdadd03aa65b47df296f6a312aaaa7b334aeb5abe0e6a40e19a",
            "description": "pizza"
        },
        {
            "id": 2,
            "payment_hash": "4a8e28d38fcc9f572807df876249715g31f962aaeb76741658db6c0e5d700a92",
            "destination": "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
            "msatoshi": 100000,
            "msatoshi_sent": 100048,
            "created_at": 1548680969,
            "status": "complete",
            "payment_preimage": "cb791daf001a8f180d5964b2bd7e79e1a7bd8940g071775855f1015cdb8385ae",
            "description": "lightning fast"
        },
        {
            "id": 3,
            "payment_hash": "b97349je9ed477e45btbd773725e1c3f64bkj0153667y85f06da4d3dd1b18910",
            "destination": "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
            "msatoshi": 1000000,
            "msatoshi_sent": 1002354,
            "created_at": 1548681049,
            "status": "complete",
            "payment_preimage": "6438421aaba463ada45jb6168ccbd07da68e0f87je5771cb5c1bd71f8c569c0c",
            "description": "lighter"
        },
        {
            "id": 4,
            "payment_hash": "cb3cb39de742ced7b553445902c89c2f085c1dbd68de68a8d98edb6aad45956e",
            "destination": "03035ba026129c629e0f11d8fd655e3acc360062bddd646c1935dd9232c5ed564c",                                                                                                                                                           "msatoshi": 700000,
            "amount_msat": "700000msat",                                                                                                                                                                                                                   "msatoshi_sent": 702086,                                                                                                                                                                                                                       "amount_sent_msat": "702086msat",
            "created_at": 1559664432,
            "status": "failed",
            "bolt11": "lntb7u1pw0d95ppp5ev7t8808gt8d0d2ng3vs9jyu9uy9c8dadr0x32xe3mdk4t29j4hqdqdv4ex2cm9d9mx2xqruyqrzjqgvtjtgem6fhaa6qz4xjp5ax7d7yfe3crjnjh9tcj22swdnyelwnv9c625qqqxsqqqqqqqlgqqqqqeqqjqrzjqwfn3p9278ttzzpe0e00uhyxhned3j5d9acqak5emwfpflp8z2cng95n6sqqqpsqqqqqqqlgqqqqqeqqjqrzjq2rrsp2pfed6mhr09nx3wnxp3amxk96f8yrsaktnkju55j5klccls944eqqqp9gqqqqqqqlgqqqqqeqqjqqdyvw4ftg9y7hskqz86zaaln4xqqttehg0ksp7ltgc5d7rgupk996yndv2vrjjxmu4xflafru8r9s3gla4znrjlvqnuy3tqd4dtfsjcqddlsw7"
    }
    ]
}

WITHDRAW = {
  "tx": "020000000001019eebc4c33036914b54fdc8a12e5443e4141208b84ecf456a29dba5c3736937f80100000000ffffffff0270110100000000001600140abe948e5b8c01a952c516969d52976157bb670c54628b01000000001600140d4dbfbf6377ff675dbc0a3354507965dede613a02483045022100a2939e98697c608fdc0607087a9bf4d8132374a0f63f07dc74ede9f808daf8020220529b25ed9a19a1cfdc8c8e7c80ddbf84fa11f7862a0800e47030dd8d4e1e6d9f0121021f86a5179c1309b091d8c6d6a4793de3ce764823f10f32747a0697f55c11a49200000000",
  "txid": "c6c5c15ba4e701e18c7e9d9eae9f87befab9a2d2bc126cd493fe7f9160e49947"
}
