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
        "status": "paid",
        "pay_index": 1,
        "msatoshi_received": 9500000,
        "paid_timestamp": 1530107870,
        "paid_at": 1530107870,
        "expiry_time": 1530111450,
        "expires_at": 1530111450
        },
        {
        "label": "1530109997580457",
        "bolt11": "lntb229u1pdn8gpdpp5xqkdd0yd6gzrw9e0frvxj0rsn875edks3clc2xd5q6ep3qr80v5qdq4f4sku6fqv9kzqsmfv4kx7cqp273znjcccuf05uhzqzudwajttvqnpv7n6m59d5w3vnf52dzmmp6e8jafcuswxescfzyhr739l4y87q08q5e3grj4s708qc",
        "payment_hash": "302cd6bc8dd20437172f48d8693c7099fd4cb6d08e3f8519b406b21880677b28",
        "msatoshi": 22900000,
        "status": "paid",
        "pay_index": 2,
        "msatoshi_received": 22900000,
        "paid_timestamp": 1530110044,
        "paid_at": 1530110044,
        "expiry_time": 1530113597,
        "expires_at": 1530113597
        },
        {
        "label": "1532635410687064",
        "bolt11": "lntb77u1pd452gjpp5yg5mynrjsvnw9tdjcctx6wayxta63pnk0rrd909q3vzv5zfz02tsdq8vdsku6gxqrpcgcqp2fppjl4ur87pe08uc97cady9j5w9la8ler3k2wyl37ye6h5rwaqhvd7794q753d9lpywr8q7pt7radexsu338pm08asyx4upchktuk",
        "payment_hash": "2229b24c728326e2adb2c6166d3ba432fba8867678c6d2bca08b04ca09227a97",
        "msatoshi": 7700000,
        "status": "expired",
        "expiry_time": 1532637210,
        "expires_at": 1532637210
        },
        {
        "label": "153245487712131",
        "bolt11": "lntb70p1pdkpz47pp5d3jxdeg5cfkmzjwcsqdezr3zqyuse7n3z2l57skwqxyhkhlcxpvqdqzvscqp2qnpqts0tr2zgnndsw2mnrllsd8509cfham5cajhz7z6xvfvugsdq6nu8t2yk8qauauy08u6s3jp50llu52xyd5kz44ra2wsxjccu8fqpxv8qwn",
        "payment_hash": "6c6466e514c26db149d8801b910e2201390cfa7112bf4f42ce01897b5ff83058",
        "msatoshi": 7,
        "expiry_time": 1533057230,
        "expires_at": 1533057230
        }
    ]
}


LISTPEERS = {
    "peers": [
        {
        "id": "0322deb288d430d3165af3d7456432111ff6cff3f431c9ae1",
        "connected": False,
        "channels": [
            {
            "state": "CHANNELD_NORMAL",
            "short_channel_id": "1323814:55:0",
            "channel_id": "d32457de4d654931271272c1d8aa2a73576891e9cc918afacfa54f6bdfb8",
            "funding_txid": "b8df6b4fa5ffa8a91cce9916857aaad8c1777212273149654dde5724d3bd",
            "msatoshi_to_us": 4800000,
            "msatoshi_to_us_min": 0,
            "msatoshi_to_us_max": 4800000,
            "msatoshi_total": 5000000000,
            "dust_limit_satoshis": 546,
            "max_htlc_value_in_flight_msat": 18446744073709551615,
            "their_channel_reserve_satoshis": 0,
            "our_channel_reserve_satoshis": 50000,
            "channel_reserve_satoshis": 0,
            "spendable_msatoshi": 0,
            "htlc_minimum_msat": 0,
            "their_to_self_delay": 6,
            "our_to_self_delay": 144,
            "to_self_delay": 6,
            "max_accepted_htlcs": 483,
            "status": ["CHANNELD_NORMAL:Reconnected, and reestablished."],
            "in_payments_offered": 0,
            "in_msatoshi_offered": 0,
            "in_payments_fulfilled": 0,
            "in_msatoshi_fulfilled": 0,
            "out_payments_offered": 0,
            "out_msatoshi_offered": 0,
            "out_payments_fulfilled": 0,
            "out_msatoshi_fulfilled": 0
            }
        ]
        },
        {
        "id": "02212d3ec887188b284dbb7b222d2e",
        "connected": True,
        "netaddr": ["54.236.55.50:9735"],
        "alias": "yalls.org",
        "color": "f8e71c",
        "channels": [
            {
            "state": "CHANNELD_NORMAL",
            "owner": "lightning_channeld",
            "short_channel_id": "1326418:102:0",
            "channel_id": "e01627604fdd45fbe4002329ee9217399652580cca34f3fd0687354b4650208f",
            "funding_txid": "8f2050464b358706fdf334ca0c585296391792ee292300e4fb45dd4f602716e0",
            "msatoshi_to_us": 998389918,
            "msatoshi_to_us_min": 998389918,
            "msatoshi_to_us_max": 1000000000,
            "msatoshi_total": 1000000000,
            "dust_limit_satoshis": 546,
            "max_htlc_value_in_flight_msat": 18446744073709551615,
            "their_channel_reserve_satoshis": 0,
            "our_channel_reserve_satoshis": 10000,
            "channel_reserve_satoshis": 0,
            "spendable_msatoshi": 988389918,
            "htlc_minimum_msat": 0,
            "their_to_self_delay": 6,
            "our_to_self_delay": 144,
            "to_self_delay": 6,
            "max_accepted_htlcs": 483,
            "status": [
                "CHANNELD_NORMAL:Reconnected, and reestablished.",
                "CHANNELD_NORMAL:Funding transaction locked. Waiting for their announcement signatures."
             ],
            "in_payments_offered": 0,
            "in_msatoshi_offered": 0,
            "in_payments_fulfilled": 0,
            "in_msatoshi_fulfilled": 0,
            "out_payments_offered": 0,
            "out_msatoshi_offered": 0,
            "out_payments_fulfilled": 0,
            "out_msatoshi_fulfilled": 0}
        ]
        },
        {
        "state": "GOSSIPING",
        "id": "02a528df8bc32794f95001b0e4bc39f1209b3c7a0dc6ee48148275477b62569177",
        "netaddr": [
            "35.185.82.104:39366"
        ],
        "connected": True,
        "owner": "lightning_gossipd"
        },
        {
        "state": "GOSSIPING",
        "id": "02bdae14ba7092995dd09a5bcd8de0ea1100e4253ece6e3d8388a9d83c4b4ad8c4",
        "alias": "LightningCoffee",
        "color": "ff0000",
        "netaddr": [
            "109.235.70.143:9736"
        ],
        "connected": True,
        "owner": "lightning_gossipd"
        }
    ]
}


LISTPEERS_EMPTY = {
    "peers": []
}


NEWADDRESS = [
    {
    "address": "2N875sa6BA9LwVTUviFisQZk"
    },
    {
    "address": "tb1q9v8gmtkhs0qtknj3g3cz"
    }
]


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
        }
    ]
}

WITHDRAW = {
  "tx": "020000000001019eebc4c33036914b54fdc8a12e5443e4141208b84ecf456a29dba5c3736937f80100000000ffffffff0270110100000000001600140abe948e5b8c01a952c516969d52976157bb670c54628b01000000001600140d4dbfbf6377ff675dbc0a3354507965dede613a02483045022100a2939e98697c608fdc0607087a9bf4d8132374a0f63f07dc74ede9f808daf8020220529b25ed9a19a1cfdc8c8e7c80ddbf84fa11f7862a0800e47030dd8d4e1e6d9f0121021f86a5179c1309b091d8c6d6a4793de3ce764823f10f32747a0697f55c11a49200000000",
  "txid": "c6c5c15ba4e701e18c7e9d9eae9f87befab9a2d2bc126cd493fe7f9160e49947"
}
