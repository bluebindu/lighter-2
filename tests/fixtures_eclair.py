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

""" Fixtures for test_light_eclair module """


ALLNODES = [
  {
    "signature": "3044022072537adb1a10dab3a4630b578e678f0b5b7f2916af65b5e2a1f71e751b8dddc802200903b8a33fc154b4542acee481446dd674238256d354249d7d10408c413201f201",
    "features": "",
    "timestamp": 1553000829,
    "nodeId": "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "rgbColor": "#33cccc",
    "alias": "cosmicApotheosis",
    "addresses": [
      "138.229.205.237:9735"
    ]
  },
  {
    "signature": "304502210080e1836a98f69133873a35bea4b9b9d5f5abdad376d526fb2f6ee46aaa77f62b022026ba53b630d76ae9d6c1beec134244a79669a31eb5e6a7cc2038aaefff84382b01",
    "features": "",
    "timestamp": 1553008703,
    "nodeId": "03ad4870c7a9dd0b429958cf9659b1330afbe33df8207cd1c882798cdad1dfb039",
    "rgbColor": "#1d236b",
    "alias": "capacity.network",
    "addresses": [
      "95.216.16.21:9735",
      "[2a01:4f9:2a:106a:0:0:0:2]:9736"
    ]
  }
]


BADRESPONSE = {
    "failures": [
        {
            "t": "unmapped error"
        },
        {
            "t": "extra error"
        }
    ]
}


CHANNEL_CLOSED = {
    "nodeId": "02863805414e5baddc6f2ccd174cc18f766b174939070ed973b4b94a4a96fe31f8",
    "channelId": "4315857d58ec84f44ba6a0b2531c8324ac7dd2fe691af94e7a9324c26c46a252",
    "state": "CLOSED",
    "data": {}
}


CHANNEL_OFFLINE = {
    "nodeId": "02863805414e5baddc6f2ccd174cc18f766b174939070ed973b4b94a4a96fe31f8",
    "channelId": "4315857d58ec84f44ba6a0b2531c8324ac7dd2fe691af94e7a9324c26c46a252",
    "state": "OFFLINE",
    "data": {}
}


CHANNEL_MUTUAL = {
    "nodeId": "0214cdb3d4ee57bce1cdbe66b7447f66eea13d9d49e35c02eb7ed22ce1ff374dcd",
    "channelId": "fc4c4474705a924b1408b858be04162bac0441d5e980074a0640fc41548dbebf",
    "state": "CLOSING",
    "data": {
          "commitments": {
                "localParams": {
                  "nodeId": "037d48d7883ade43b3df14c48d252e9050615efd123b6ccab9fce50a6984c63810",
                  "channelKeyPath": {
                    "path": [
                      1725782503,
                      3926238122,
                      3719241493,
                      1890273404
                    ]
                  },
                  "dustLimitSatoshis": 546,
                  "maxHtlcValueInFlightMsat": 5000000000,
                  "channelReserveSatoshis": 3400,
                  "htlcMinimumMsat": 1,
                  "toSelfDelay": 720,
                  "maxAcceptedHtlcs": 30,
                  "isFunder": True,
                  "defaultFinalScriptPubKey": "a914d670943941caccff9feed2648f034f56573a655c87",
                  "globalFeatures": "",
                  "localFeatures": "8a"
                },
                "remoteParams": {
                  "nodeId": "0214cdb3d4ee57bce1cdbe66b7447f66eea13d9d49e35c02eb7ed22ce1ff374dcd",
                  "dustLimitSatoshis": 546,
                  "maxHtlcValueInFlightMsat": 5000000000,
                  "channelReserveSatoshis": 3400,
                  "htlcMinimumMsat": 1,
                  "toSelfDelay": 720,
                  "maxAcceptedHtlcs": 30,
                  "fundingPubKey": "027c97331987c5dbd9a41c0047cdbdb595213e314b6301960789c085be5e0f414d",
                  "revocationBasepoint": "03dc9c480f80d213b411486b2664fe2c68926f4538c83e3b67c04fa709a5ac4b1a",
                  "paymentBasepoint": "0244a4a89812464dad98e25fcda11542bf873a0cd39bb8327f3b3ba894bb669b8a",
                  "delayedPaymentBasepoint": "02d523f51e5dbe7651f44cd16f6cbb96061bf0bbfe0cb6002d70e428846bf62ebc",
                  "htlcBasepoint": "02a99e2f7a371dbd92a1e6cf18e4dae0a2a5e49b1eda41785bd3b0f825098850e7",
                  "globalFeatures": "",
                  "localFeatures": "8a"
                },
                "channelFlags": 1,
                "localCommit": {
                  "index": 0,
                  "spec": {
                    "htlcs": [],
                    "feeratePerKw": 45000,
                    "toLocalMsat": 340000000,
                    "toRemoteMsat": 0
                  },
                  "publishableTxs": {
                    "commitTx": {
                      "txid": "0953d0bfd822c34729c0e5c5f94416490753d8e6a4cd63b211f20e3d01347f61",
                      "tx": "02000000000101fc4c4474705a924b1408b858be04162bac0441d5e980074a0640fc41548dbebe0100000000404d018001dcb00400000000002200209b93789667b51bd82834016cb4f6daacb9b9b868eec0cb8e854552568f767566040047304402204eb011a5707064656ddf8120bc2d92d19a87b0f764148d393b2aaf440309a22c02204aa76d68ceccd471318062290eb64ed9661779d235001e3f813b65c8efde3ba201483045022100aca4d9c04607f079862d35e4016d100de5d922a26c57e4afbdb97e80487ccf3e02206a319c913e2670c09c5ecfb455434e7d9f67ca319c9ce65fc64bea04033c542201475221027c97331987c5dbd9a41c0047cdbdb595213e314b6301960789c085be5e0f414d2103bca9c36cec797992a4aec1f26154acf7e196049d0cc54856905dc615ff58729452aea153b220"
                    },
                    "htlcTxsAndSigs": []
                  }
                },
                "remoteCommit": {
                  "index": 0,
                  "spec": {
                    "htlcs": [],
                    "feeratePerKw": 45000,
                    "toLocalMsat": 0,
                    "toRemoteMsat": 340000000
                  },
                  "txid": "5b1090081f25dbd2b43f4f116cdb910caf772fcc8a0bd5a8dff04f6bd9f24383",
                  "remotePerCommitmentPoint": "035d86c8a9d4e03766df7113b7801d40eb2f7c9ca2cf999c968ce6ddbc6bd721ff"
                },
                "localChanges": {
                  "proposed": [],
                  "signed": [],
                  "acked": []
                },
                "remoteChanges": {
                  "proposed": [],
                  "acked": [],
                  "signed": []
                },
                "localNextHtlcId": 0,
                "remoteNextHtlcId": 0,
                "originChannels": {},
                "remoteNextCommitInfo": "020b742ad8bf87f0628e692b506994604ad6bb5d523183bde162098c3f02f407da",
                "commitInput": {
                  "outPoint": "bebe8d5441fc40064a0780e9d54104ac2b1604be58b808144b925a7074444cfc:1",
                  "amountSatoshis": 340000
                },
                "remotePerCommitmentSecrets": None,
                "channelId": "fc4c4474705a924b1408b858be04162bac0441d5e980074a0640fc41548dbebf"
            },
            "waitingSince": 1562782259,
            "mutualCloseProposed": [
            {
              "txid": "4fb6a1de77c103fb6d03ca1d2f263cb0c7ab7838a94d24dc05ecd5b5a1e2fe73",
              "tx": "0200000001fc4c4474705a924b1408b858be04162bac0441d5e980074a0640fc41548dbebe0100000000ffffffff0139cc04000000000017a914d670943941caccff9feed2648f034f56573a655c8700000000"
            },
            {
              "txid": "40fb674d1c3ac6943137ffeb1dc18750689a12d2600fa99a4b43b5f564804dfe",
              "tx": "0200000001fc4c4474705a924b1408b858be04162bac0441d5e980074a0640fc41548dbebe0100000000ffffffff013acc04000000000017a914d670943941caccff9feed2648f034f56573a655c8700000000"
            }
            ],
            "mutualClosePublished": [
            {
              "txid": "40fb674d1c3ac6943137ffeb1dc18750689a12d2600fa99a4b43b5f564804dfe",
              "tx": "02000000000101fc4c4474705a924b1408b858be04162bac0441d5e980074a0640fc41548dbebe0100000000ffffffff013acc04000000000017a914d670943941caccff9feed2648f034f56573a655c870400483045022100a18af3918a18a0532b4223b6f06026c9fc860174f$7feeae0be990db9f48dfc80220706fce8adc356023c8653709c4d5f1f4b3d2defeefeeabc1d347b803e50a531401473044022007ca998347fd4ec12ea26afc1fe44ec7d4cf576560d2c508f3056ee9a020653b022071c9d78faad51c545ad5ffad0181531b5270c4df1a30a6680b6ba8cbec25112401$75221027c97331987c5dbd9a41c0047cdbdb595213e314b6301960789c085be5e0f414d2103bca9c36cec797992a4aec1f26154acf7e196049d0cc54856905dc615ff58729452ae00000000"
            }
            ],
            "revokedCommitPublished": []
        }
}


CHANNEL_NORMAL = {
    "nodeId": "02863805414e5baddc6f2ccd174cc18f766b174939070ed973b4b94a4a96fe31f8",
    "channelId": "4315857d58ec84f44ba6a0b2531c8324ac7dd2fe691af94e7a9324c26c46a252",
    "state": "NORMAL",
    "data": {
      "commitments": {
        "localParams": {
          "nodeId": "02f96a28d05560ddbd70ce655e1e0c52fe300b41889ebe4fc2b1321322039296fe",
          "channelKeyPath": {
            "path": [
              573467763,
              1626995395,
              334466227,
              2805826895
            ]
          },
          "dustLimitSatoshis": 546,
          "maxHtlcValueInFlightMsat": 5000000000,
          "channelReserveSatoshis": 2000,
          "htlcMinimumMsat": 1,
          "toSelfDelay": 720,
          "maxAcceptedHtlcs": 30,
          "isFunder": False,
          "defaultFinalScriptPubKey": "a91498fbca2ebc60897b6e21083f23e7bcd7d432361887",
          "globalFeatures": "",
          "localFeatures": "8a"
        },
        "remoteParams": {
          "nodeId": "02863805414e5baddc6f2ccd174cc18f766b174939070ed973b4b94a4a96fe31f8",
          "dustLimitSatoshis": 573,
          "maxHtlcValueInFlightMsat": 198000000,
          "channelReserveSatoshis": 2000,
          "htlcMinimumMsat": 1000,
          "toSelfDelay": 144,
          "maxAcceptedHtlcs": 483,
          "fundingPubKey": "0344202ff1a7f595b425f3a10e5b57698f1905651f068aefd0378917066dcd7fe2",
          "revocationBasepoint": "02333073744b193defff254422fe534f7f0f141809c81d548c7f1ee8c2460e8327",
          "paymentBasepoint": "0226dd82c2adb3584acfcbc55fa07ca3ae2eb40ed85d0a7a261f1f39f56d714d0e",
          "delayedPaymentBasepoint": "022829cefc491df808886de503b157d6340c424befc9c803bf2efea296f1473990",
          "htlcBasepoint": "03aa6f026558a8052dd0dbe2c36737397b303aa2339df69dcf02823187b4b08559",
          "globalFeatures": "",
          "localFeatures": "81"
        },
        "channelFlags": 0,
        "localCommit": {
          "index": 0,
          "spec": {
            "htlcs": [],
            "feeratePerKw": 253,
            "toLocalMsat": 50000000,
            "toRemoteMsat": 150000000
          },
          "publishableTxs": {
            "commitTx": "020000000001014315857d58ec84f44ba6a0b2531c8324ac7dd2fe691af94e7a9324c26c46a2530100000000d04e56800250c30000000000002200204148d0610bb8a9e0a63d7689b1205a07da4f5c4e1cc672b6523120fc3bbfd035394902000000000016001424dd951156abf4066e6f2ea7365703ca3e305d1d0400473044022071ffe796e0316193e308c1de8661f4f57cfffb97bcc23d7fb94137a9b91907800220106ed0c7c6e8ff9c353b5aafe28cf3ad0cd379c3a555a9d600adeb4eee1e8d0b01483045022100f0a95481fb3a465b091fb1433e45dc7a0f876fc132907de307fb309b7075024c02206e9bf7f234d15522c44e60e98eb153e1ce88aa392d2bacaf2a6d875558bcade001475221032547ebd34572f922f1d82f8233bd6f037848219bef93b6a50a2c10842cea0708210344202ff1a7f595b425f3a10e5b57698f1905651f068aefd0378917066dcd7fe252aef4c06a20",
            "htlcTxsAndSigs": []
          }
        },
        "remoteCommit": {
          "index": 0,
          "spec": {
            "htlcs": [],
            "feeratePerKw": 253,
            "toLocalMsat": 150000000,
            "toRemoteMsat": 50000000
          },
          "txid": "1ee64847bb0b067887e4ef1b794b307485153c07f8ae993f656caabf8646c1b0",
          "remotePerCommitmentPoint": "03e81bc3fc9a3c8101b8708662a743e971c0018216b0accf6a9f74189a5edb4994"
        },
        "localChanges": {
          "proposed": [],
          "signed": [],
          "acked": []
        },
        "remoteChanges": {
          "proposed": [],
          "acked": [],
          "signed": []
        },
        "localNextHtlcId": 0,
        "remoteNextHtlcId": 0,
        "originChannels": {},
        "remoteNextCommitInfo": "038013796b5d8d2bfd562b35db09f3d17649b8f47e64399e64510ab60f3ae5a435",
        "commitInput": {
          "outPoint": "53a2466cc224937a4ef91a69fed27dac24831c53b2a0a64bf484ec587d851543:1",
          "amountSatoshis": 200000
        },
        "remotePerCommitmentSecrets": None,
        "channelId": "4315857d58ec84f44ba6a0b2531c8324ac7dd2fe691af94e7a9324c26c46a252"
      },
      "shortChannelId": "1515559x114x1",
      "buried": True,
      "channelAnnouncement": {
        "nodeSignature1": "30440220108229951e5a78293418f94689fdabdca60d48514c1ca6eca774b867064b2680022027539d49efd189312d963919c31497eef3b68c8418e2e7b38593d188cc60008e01",
        "nodeSignature2": "304402200f53c1f281f1ae3cca3ff158f08c9fb586811866d7d8acdc9b9da1214819631d02202acc97b0c569ce8362533709b403823c2758e13fa62fdfb7e79c8d6b59833b8101",
        "bitcoinSignature1": "3045022100f66aa4f46792c7acaa0cb1ffaa3f0080260448e789f140bb15c0d2ff6467a118022017517835887a772e7f6e10c977e68e2da5ff858b784fa4bd20ac16314509f34101",
        "bitcoinSignature2": "304402201f0ce6892644a72e280cb1d912b8f5b237f356b6cbef8a6e17e3848291856327022005173ddbcd9b9ac1cd8c148b63ccc6a3a1f3d83d5866dba12cd6437f035be69801",
        "features": "",
        "chainHash": "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
        "shortChannelId": "1515559x114x1",
        "nodeId1": "02863805414e5baddc6f2ccd174cc18f766b174939070ed973b4b94a4a96fe31f8",
        "nodeId2": "02f96a28d05560ddbd70ce655e1e0c52fe300b41889ebe4fc2b1321322039296fe",
        "bitcoinKey1": "0344202ff1a7f595b425f3a10e5b57698f1905651f068aefd0378917066dcd7fe2",
        "bitcoinKey2": "032547ebd34572f922f1d82f8233bd6f037848219bef93b6a50a2c10842cea0708"
      },
      "channelUpdate": {
        "signature": "3044022043714b773ae7ed7b4162a667300914564a84e5a2797b8fb79d58383fc8df569d0220765623feba30fbc6fcb45bfacacde312cc2fcedb3683504b4a1e6de373480b2301",
        "chainHash": "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
        "shortChannelId": "1515559x114x1",
        "timestamp": 1557752335,
        "messageFlags": 1,
        "channelFlags": 1,
        "cltvExpiryDelta": 144,
        "htlcMinimumMsat": 1000,
        "feeBaseMsat": 1000,
        "feeProportionalMillionths": 100,
        "htlcMaximumMsat": 200000000
      }
    }
}


CHANNEL_WAITING_FUNDING = {
    "nodeId": "02a68237add204623021d09b0334c4992c132eb3c9dcfcb8f3cf8a57386775538e",
    "channelId": "aa03b917bf32f7393b0b08b9b31a34a88b5bbcb68858857955dd3239d7b3cde0",
    "state": "WAIT_FOR_FUNDING_CONFIRMED",
    "data": {
      "commitments": {
        "localParams": {
          "nodeId": "02f96a28d05560ddbd70ce655e1e0c52fe300b41889ebe4fc2b1321322039296fe",
          "channelKeyPath": {
            "path": [
              2923991324,
              1303752214,
              2994754672,
              595219576
            ]
          },
          "dustLimitSatoshis": 546,
          "maxHtlcValueInFlightMsat": 5000000000,
          "channelReserveSatoshis": 100000,
          "htlcMinimumMsat": 1,
          "toSelfDelay": 720,
          "maxAcceptedHtlcs": 30,
          "isFunder": True,
          "defaultFinalScriptPubKey": "a9140290da4f49579cc3bcb1498579977dfb8c95990087",
          "globalFeatures": "",
          "localFeatures": "8a"
        },
        "remoteParams": {
          "nodeId": "02a68237add204623021d09b0334c4992c132eb3c9dcfcb8f3cf8a57386775538e",
          "dustLimitSatoshis": 573,
          "maxHtlcValueInFlightMsat": 9900000000,
          "channelReserveSatoshis": 100000,
          "htlcMinimumMsat": 1000,
          "toSelfDelay": 1201,
          "maxAcceptedHtlcs": 483,
          "fundingPubKey": "030362289cb0b20a48fb169534d9a0b7f609be3524683c9c72dea9c293faa3d738",
          "revocationBasepoint": "038dc803e3b95139fa2290c88ea6e21553d901ae6a8711b772bfe508d2c4b70a9b",
          "paymentBasepoint": "02232613c31ae35221c3f59a00444f6acfa100e0b960aa41ddf0b768e1b7da5120",
          "delayedPaymentBasepoint": "038b8eb2bcac4721755cc917bd24550a50c82d0a2f295557df83cdf53518ab0412",
          "htlcBasepoint": "0363cda68d2cfdf59d4008565f070221e755bafe63f1978c36b8b75be65e92d8e1",
          "globalFeatures": "",
          "localFeatures": "81"
        },
        "channelFlags": 1,
        "localCommit": {
          "index": 0,
          "spec": {
            "htlcs": [],
            "feeratePerKw": 750,
            "toLocalMsat": 10000000000,
            "toRemoteMsat": 0
          },
          "publishableTxs": {
            "commitTx": "02000000000101aa03b917bf32f7393b0b08b9b31a34a88b5bbcb68858857955dd3239d7b3cde000000000006553e580016194980000000000220020f25fd0bc73a9a374f31e7b4e16bd40a50beea9d11de87ac08307e305888575cf040047304402204a9b90a2c3c3c6d4ca4cf9ecdb373cc14e6ebddb1ca960e42559df4d1fc43d170220480fa27e0e144951defa82ba12fb51c81dd969bb71aedf689a6ab37cbde5c9250147304402203d2d346ecf4c8ef58b784f367ab1ab470201a3727c92717c0dca61756b333c0d02205af622efb6b3263899cbb1f043fa4571a8c75d756f53abb47788a1d4daa9b1f501475221030362289cb0b20a48fb169534d9a0b7f609be3524683c9c72dea9c293faa3d738210337ab18506d37aebc93a00bbe38a14bf2219c60670786c1793a81b8f0bce1ea8d52aedc743020",
            "htlcTxsAndSigs": []
          }
        },
        "remoteCommit": {
          "index": 0,
          "spec": {
            "htlcs": [],
            "feeratePerKw": 750,
            "toLocalMsat": 0,
            "toRemoteMsat": 10000000000
          },
          "txid": "3f2f78e4073fbd2579ea0c516ec446aa2f709f697025f73e70f6b10cf245d3c8",
          "remotePerCommitmentPoint": "03a69a2cb30c540f0f34dadaee86dd19ed6a008164d9bfcf0f8f48edcc54793b89"
        },
        "localChanges": {
          "proposed": [],
          "signed": [],
          "acked": []
        },
        "remoteChanges": {
          "proposed": [],
          "acked": [],
          "signed": []
        },
        "localNextHtlcId": 0,
        "remoteNextHtlcId": 0,
        "originChannels": {},
        "remoteNextCommitInfo": "028b55275d4f4548b5dfdd59057875e7c96e78d0ec51cdb36139fb05eb2ea0b08f",
        "commitInput": {
          "outPoint": "e0cdb3d73932dd5579855888b6bc5b8ba8341ab3b9080b3b39f732bf17b903aa:0",
          "amountSatoshis": 10000000
        },
        "remotePerCommitmentSecrets": None,
        "channelId": "aa03b917bf32f7393b0b08b9b31a34a88b5bbcb68858857955dd3239d7b3cde0"
      },
      "fundingTx": "02000000000101250614c59acb0209fff55f25202cda1f2ade21e09a0a656ad3ef0d13aca7b22600000000171600143c69424402f027ffece4b3dbceec215164cf0b08feffffff028096980000000000220020e4faa117e1da4aa871c136bbdf5a75d91bbdd3a54427afe0d8569cefe8a0a97af02a31010000000016001455b35152c384a1c4d4ae6b8d075e7a14c85d7ae90247304402207c04b52f01931726edbb4f7eb24568a2d345d314b51ebb63db7dafddc0559c5a0220337805787a804395cb9dc64c0fb9dece4c3f8b6f2b73f86ede8364fe2cf873ee012102d9c9fc80902395574e03b4ec2a559c6b52748e7688eeda8f81f653385191cc0700000000",
      "waitingSince": 1557778397,
      "lastSent": {
        "temporaryChannelId": "8f7eb5d6b69de012b5deaf6cb3d3e83c258b682ad7897748d2bc8746515f5a4a",
        "fundingTxid": "aa03b917bf32f7393b0b08b9b31a34a88b5bbcb68858857955dd3239d7b3cde0",
        "fundingOutputIndex": 0,
        "signature": "3045022100dd04a9dfec68149c347d343b4d78586cabd49ac42ef87cbdf84a989dfb046db302204e892dccb5a41dc1d7a576ca7061104dbd7b7b74408c5068642c0ec8d4e95d1601"
      }
    }
}


CHANNEL_UNILATERAL = {
    "nodeId": "02a68237add204623021d09b0334c4992c132eb3c9dcfcb8f3cf8a57386775538e",
    "channelId": "aa03b917bf32f7393b0b08b9b31a34a88b5bbcb68858857955dd3239d7b3cde0",
    "state": "CLOSING",
    "data": {
        "mutualCloseProposed": [],
        "mutualClosePublished": [],
        "localCommitPublished": {
            "commitTx": {
                "txid": "16cad5cf0b46996057b1faa6cc6a6c0403e3412057cb04e9a26106cad2eb4a55",
                "tx": "02000000000101e91ba02ea6063783fc91e882824a7f6aa19c8287949bc27b19757cd95345342801000000006e17238002be0a0000000000001600141c730655350c39a6d63703cc8fd6c8fb499552da9efc0000000000002200208308eb66b2aa1b1daf88cd83e6ec6154a96f085fd8376fe06991bdccb7dfdbdd0400473044022031d34f1d94eb1ef888210df088378f750de40e29aafa9277b3d9116073e5b05e02204b9b3a90e1038a40f719728ef199a5f32c27f53140ed24a7d3b42a7dc663393201473044022069978412464c1fbde2263b1af6a5ec01b059cde9a0397b31a196aa1434ce5e4c0220245c05cf4e437963efcad6e64064f51869f37007df73c9b093a75753d40b03050147522102a7466b041a85874dbec391a0b2b6a498bf18f230431a26c6136ebd26ccadb28f2103716fa0003d80df57dc418918f1095f6c4c86e2ea4c45878c682e4404451389eb52aeeea4ec20"
            },
            "claimMainDelayedOutputTx": {
                "txid": "023b41616b101d3de05f00800260124a6ae172ee9105cf811d30215070093296",
                "tx": "02000000000101554aebd2ca0661a2e904cb572041e303046c6acca6fab1576099460bcfd5ca160100000000d00200000148b500000000000017a9146159bd608030c19d8851f6bf579dc9fc34d996ed8703483045022100d7d0f151ee4a72df43f533f6b1a88d55eb920a2d554c9456fe3b77597dae16d6022008123317065b77b5770255a7543bbe27c3f1d3db7eb3f5e32c76b5493d9fb4d201004d6321034be04c5b4285728e974b9fc6253f6bd50a52d3794895d487d89acba6130bf9486702d002b27521023304a373ed48d454162cf5b83ba871dbfd0deca494ea24905e1cdf36785e1bcf68ac00000000"
            },
            "htlcSuccessTxs": [],
            "htlcTimeoutTxs": [],
            "claimHtlcDelayedTxs": [],
            "irrevocablySpent": {
                "28344553d97c75197bc29b9487829ca16a7f4a8282e891fc833706a62ea01be9:1": "16cad5cf0b46996057b1faa6cc6a6c0403e3412057cb04e9a26106cad2eb4a55"
            }
        },
        "revokedCommitPublished": []
   }
}


CHANNEL_UNKNOWN = {
    "nodeId": "02863805414e5baddc6f2ccd174cc18f766b174939070ed973b4b94a4a96fe31f8",
    "channelId": "4315857d58ec84f44ba6a0b2531c8324ac7dd2fe691af94e7a9324c26c46a252",
    "state": "UNKNOWN",
    "data": {}
}


CHANNELS = [CHANNEL_NORMAL, CHANNEL_WAITING_FUNDING]


CREATEINVOICE = {
  "prefix": "lntb",
  "timestamp": 1557768667,
  "nodeId": "02f96a28d05560ddbd70ce655e1e0c52fe300b41889ebe4fc2b1321322039296fe",
  "serialized": "lntb70p1pwdn2wmpp5883kc30jcxdz6xd6q7zmhlrpkyldy8enxn72p2gncas8h7ycfprqdqvd35kw6r5v4eqfppjq2p6f5f2dxrm524xtdqrtpx597dcwd5rxqrzac4gmjxnuu06jk6qvkqq04qaay5p7ezcg4jlxh5vf4ugzl40mmdntk5lxzfptxusku0ay4m633a0pgl40npxqvja22ysphjq05cdr56lsqsqu5kt",
  "description": "lighter",
  "paymentHash": "39e36c45f2c19a2d19ba0785bbfc61b13ed21f3334fca0a913c7607bf8984846",
  "expiry": 3000,
  "amount": 7
}


GETINFO_TESTNET = {
  "nodeId": "0399454946097e6d6a8bfb9f4483ed752a8dcfac71925b91b7120126b898efc502",
  "alias": "pie",
  "chainHash": "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
  "blockHeight": 1515554,
  "publicAddresses": [
    "7.58.73.71:9735",
    "of7husrflx7sforh3fw6yqlpwstee3wg5imvvmkp4bz6rbjxtg5nljad.onion:9735"
  ]
}


GETINFO_MAINNET = {
  "nodeId": "0399454946097e6d6a8bfb9f4483ed752a8dcfac71925b91b7120126b898efc502",
  "alias": "pie",
  "chainHash": "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
  "blockHeight": 1515554,
  "publicAddresses": [
    "7.58.73.71:9735"
  ]
}


GETINFO_UNKNOWN = {
  "nodeId": "0399454946097e6d6a8bfb9f4483ed752a8dcfac71925b91b7120126b898efc502",
  "alias": "pie",
  "chainHash": "hdiahdsihdncsjnc",
  "blockHeight": 1515554,
  "publicAddresses": [
    "7.58.73.71:9735"
  ]
}


GETRECEIVEDINFO = {
  "paymentHash": "4d69a3cd69cb659e544722d6de4ecfffe9be27b239924e4112698b01347e5b8b",
  "amountMsat": 300000,
  "receivedAt": 1557756284358
}


GETSENTINFO_FAIL = [
  {
    "id": "84680319-1923-4495-adf7-03eb457a8180",
    "paymentHash": "a068da12e4fea8a1d0cbc45ccf5bdf41a2e9d15784644afec2c3fdea99af2f2f",
    "amountMsat": 700000,
    "createdAt": 1557761062137,
    "completedAt": 1557761062219,
    "status": "FAILED"
  }
]


GETSENTINFO_PENDING = [
  {
    "id": "84680319-1923-4495-adf7-03eb457a8180",
    "paymentHash": "a068da12e4fea8a1d0cbc45ccf5bdf41a2e9d15784644afec2c3fdea99af2f2f",
    "amountMsat": 700000,
    "createdAt": 1557761062137,
    "completedAt": 1557761062219,
    "status": "PENDING"
  }
]


GETSENTINFO_SUCCESS = [
  {
    "id": "92d01a04-5a2e-4ea8-a113-f0c972e19939",
    "paymentHash": "6c5392e5425ba698e4bca4ccfb737832d10ad81198d509d7d0ae5f9a6827e2d0",
    "preimage": "cdbfaec189f7bce9ee0ed1396286e2a69eb815d329468f10e96abe5e3118f157",
    "amountMsat": 700000,
    "createdAt": 1557757208226,
    "completedAt": 1557757209962,
    "status": "SUCCEEDED"
  }
]

ERROR = "error"


PARSEINVOICE = {
  "prefix": "lntb",
  "timestamp": 1557759146,
  "nodeId": "02a68237add204623021d09b0334c4992c132eb3c9dcfcb8f3cf8a57386775538e",
  "serialized": "lntb1500n1pwdnp92pp5ja6xldtskmu9g2zzxdl9wknzfmv8a5lamya8yrw4xzkvv5d2hvvsdpa2fjkzep6ypzxjepqfysx5atnwssxvmm4dejzqmteypzkxmrpd9ezqmt0vf5kccqzpgxqr23s7dkecquhxlxux95atd0n5lcu6kssnc7fzyy6gsla4jrfjnex9k4swxrfeht8zwgskgq3pvd3fqjpyr7hsa7x5kvzn3774dgefm3ha8cpcnh0pd",
  "description": "Read: Did I just found my Eclair mobil",
  "paymentHash": "97746fb570b6f8542842337e575a624ed87ed3fdd93a720dd530acc651aabb19",
  "expiry": 10800,
  "minFinalCltvExpiry": 40,
  "amount": 150000
}


PARSEINVOICE_D_HASH = {
  "prefix": "lnbc",
  "timestamp": 1496314658,
  "nodeId": "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
  "serialized": "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7",
  "description": "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1",
  "paymentHash": "0001020304050607080900010203040506070809000102030405060708090102",
  "amount": 2000000000
}


PEERS = [
    {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "state": "CONNECTED",
    "channels": 2
    },
    {
    "nodeId":
        "03ad4870c7a9dd0b429958cf9659b1330afbe33df8207cd1c882798cdad1dfb039",
    "state": "DISCONNECTED",
    "address": "172.19.0.3:9735",
    "channels": 1
    },
    {
    "nodeId":
        "0354d21c34f65c3429eedcef9e871a7286013ad5b27722a02752e29a4a888b0e62",
    "state": "CONNECTED",
    "address": "88.99.209.230:9735",
    "channels": 1
    },
    {
    "nodeId":
        "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
    "state": "CONNECTED",
    "channels": 1
    }
]


PAYINVOICE = '92d01a04-5a2e-4ea8-a113-f0c972e19939'


PAYINVOICE_ERROR = ("The form field 'invoice' was malformed:\n"
    "requirement failed: invalid checksum for lntb7u1pwdnrqjpp55p5d5yhyl652r5x"
    "tc3wv7k7lgx3wn52hs3jy4lkzc0774xd09uhsdqqcqzpg4k98y0aaavnnn3gtu0z2cjksfeax"
    "c2wh2mrw9t2a2ttjy88chckn0gh5t5l7ehc7twsm63tqa67asfzh4n7a2d64fwddmfxgm9m9y"
    "yspv30")


STRANGERESPONSE = 'i\'m a strange and never expected response'
