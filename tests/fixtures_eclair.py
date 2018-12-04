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


badresponse = {
    "failures": [
        {
            "t": "unmapped error"
        },
        {
            "t": "extra error"
        }
    ]
}


channels_empty = []

channels_one = [{
    "nodeId":
        "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
    "channelId":
        "69778693fac6cc79e7517107fbc78de25e311c3f4bd4ac3ae4d5b1fa13fa86de",
    "state": "WAIT_FOR_ACCEPT_CHANNEL"
}]

channels = [
    {
    "nodeId":
        "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
    "channelId":
        "69778693fac6cc79e7517107fbc78de25e311c3f4bd4ac3ae4d5b1fa13fa86de",
    "state": "WAIT_FOR_ACCEPT_CHANNEL"
    },
    {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
        "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
    "state": "OFFLINE"
    },
    {
    "nodeId":
        "0354d21c34f65c3429eedcef9e871a7286013ad5b27722a02752e29a4a888b0e62",
    "channelId":
        "d6c3abc4d9295cdd8a8d53e14a5727104db9280ec5d6432d2f14b2ce60207ec8",
    "state": "CLOSING"
    },
    {
    "nodeId":
        "03ad4870c7a9dd0b429958cf9659b1330afbe33df8207cd1c882798cdad1dfb039",
    "channelId":
        "b89af140bfe6898a781546e26c1c2a38eab5482748c7b6688b1475567d9ffc3f",
    "state": "CLOSING"
    },
    {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
        "81ece85edb41e20ea23611b15fbbddd3ca1a60fa021ec391bd8c7cedc1473ec6",
    "state":"CLOSING"
    },
    {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
        "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
    "state": "WAIT_FOR_FUNDING_CONFIRMED"
    },
    {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
        "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
    "state": "NORMAL"
    },
    {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
        "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
    "state": "ERR_INFORMATION_LEAK"
    }
]

channel_closing = {
    "nodeId":
        "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
    "channelId":
        "c46cf46127f630f6bbea14815a6d112e526b53a836e334b8597c2737eb8eeac3",
    "state": "CLOSING",
    "data": {
        "commitments": {
            "localParams": {
                "nodeId": "022237417f8aeb2c8d5c36150bd9b4fcf4b6525c99bfc0575af4d2800eb330e48c",
                "channelKeyPath": {"path": [3561297602, 523116577, 2219449922, 1318076182]},
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "isFunder": False,
                "defaultFinalScriptPubKey": "a91466133c1e7f138b0c8fe3f6155792ff932aeb3f6587",
                "globalFeatures": "",
                "localFeatures": "0a"
            },
            "remoteParams": {
                "nodeId":
                    "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
                "dustLimitSatoshis": 573,
                "maxHtlcValueInFlightMsat": 1980000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1000,
                "toSelfDelay": 240,
                "maxAcceptedHtlcs": 483,
                "fundingPubKey":
                    "03a1ee29ef3af37f3072df2bd6391021fab53019a037e9093ed793898ddc4183c7",
                "revocationBasepoint":
                    "02e43d3ad3accabb95b14e4e70e0e68a5acf639ee3dd2b4c59e48a02960cd5d3dc",
                "paymentBasepoint":
                    "020f0e41710177e0a7c0be5684257ea16ca147e35f099d34e799b1d20779d7ba34",
                "delayedPaymentBasepoint":
                    "02b1a7898058fdc6bf932308da07bdae130bc0d7bf2db709d4f4bfc0ddfe58b8cb",
                "htlcBasepoint":
                    "038ea5fcca83436d79dd944e94451f7c0b20c5661bd480a7789c55de95b7224305",
                "globalFeatures": "",
                "localFeatures": "82"
            },
            "channelFlags": 1,
            "localCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 32000,
                    "toLocalMsat": 0,
                    "toRemoteMsat": 2000000000
                },
                "publishableTxs": {
                    "commitTx":
                        "00000000000101c46cf46127f630f6bbea14815a6d112e526b53a836e334b8597c2737eb8eeac3000000000004a7048001002a1e0000000000160014f2533138510acb8042a552ef7bde2c0f7dc857ce040047304402204cdbb057560e7e \
5930dc60ed30ccb0f929b05df7d07fb7a96cbe6d55cbb09a76022063912f22af08060d2f517c32bd4bb52f08ed45f9e5cef6012e532c08c1c4d17b014730440220188ae2a2d31a17b772b0706efdd56cb4192eb06c4731281c45de608a5e2d8c2402203ac075f7c6f9b \
6dfbaa70e20e0ba8c9a55b97a4c31b889167c471204ef95ac630147522102109051e36ef9a776d603ed96b9b8488a0bdd9c1b69390e0232be4e570c3e51762103a1ee29ef3af37f3072df2bd6391021fab53019a037e9093ed793898ddc4183c752ae00000000",
                    "htlcTxsAndSigs": []
                }
            },
            "remoteCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 32000,
                    "toLocalMsat": 2000000000,
                    "toRemoteMsat": 0
                },
                "txid":
                    "063e66222b1ccf4e63bb02c7304309dca4b3592b8ee2af4dd88deb27b8633417",
                "remotePerCommitmentPoint":
                    "03792fac7b5a58cecb9a249ff51366eb8a9a8125a2cdd4e0e2bb1a4b72f1ed3a42"
            },
            "localChanges": {
                "proposed": [],
                "signed": [],
                "acked": []
            },
            "remoteChanges": {
                "proposed": [{
                    "channelId":
                        "c46cf46127f630f6bbea14815a6d112e526b53a836e334b8597c2737eb8eeac3",
                    "id": 0,
                    "amountMsat": 2000,
                    "paymentHash": "babad62243a0338671f08da12b4961cbe331109dd8a85b926f55f77c95287104",
                    "expiry": 1356618,
                    "onionRoutingPacket":
                        "0002b7aef6caf2b6e6457fdb42d5758de6712789a6b75bae46210a515ab62879ca05abf5bf61d2d7dc7be81e2ef517bd55c58a9a8567645041daff9c8e2915fa7f09886fd1869da69d2ccfac8d95fa1a8e96bbdb182d0883 \
2bc57159f8d787f14eca9dc7507d7eda0a9e44947313c37e86623346f02c9889e0690c4e87383703924a610c7bfb508c3e0d9ffb0d9a79d97f60a27a3cb0347afdeba7fdc5627e19ccc1a7307c13ac58c11701fa62f9b9c44e340a83c8237145dd049e951d45d847d1f \
492e07ba7b724dc7f91545048cbcb0ac820e074d6269baccd5d3291989fa69fbcc4298a6dda51e393f311e0c8e0a39e0e39996d42e79c8b835027ab777f9b46ac3929148bb2e943322616df37ae2f96a127325c1c1e27d280eb365af882d095902f0e82b1ccb7004e55 \
6f02398a6f0f68ce1c2c7b93e151ab9b17afb9dfcc6734332c0c18c4f2b7effb6058b86fa3ca72e4c57670d9bc9d087d1443bb3d85364cbf001a303e4ce778c68cb7f67ceda4f28e9a14ac0c416811a8f5ad3b31be8f0a24eb7e6a7eb32c8117d6eb3a11285196dcbc0 \
a05966169631f465b7decf18cb37bc7d157f297dd68587933c3d6f6acd187b9c3381c8538d1766888055be0afdd6b328be0ae6428d7d415ebbf37f76103561e7dbe31ff96b0a4b917d944109496eaa3b4c8df1539cf8297adb6853550a2b7294008ffd798240577fa43 \
38a8e4738f880d905ff4c83073949cafc399bcda2e832cbfdd3fa879b0ed58bf974dae5b27567ea077e1c9981b0bdfb4b74ae073dcd295b4e45cb60dadcffbbf98c6075fb2770468054ce097947cad87173e89b08404d3a8064e1c1db6448d097f78082eb362b678055 \
10916ffc100307470bfc579a3e5ed6bcf7e0e5f5ba5b1e53e2ed61fb9a3a035ac6888950bee622dbf654611f8f6aa9569ce540e6b6381a774115946090da89494ff249b64a99556acbf89f5875c7899b9a5c9812e4ebd4ab224a8b215568b583d0d2627243651f5a287 \
800a7165fa3428367fcddc281b63861f1d943f7ba637aadf27dfe4bc61ae55838de5cf07643af4198ab76611c9e6f29e0975d28c5fb8e79e6e910b9271a46e7867af380781e29b6621659de8d014ccac0aeb326af7cd1686d442eb6396407037295821bd503a2c7f49f \
bfaaf3715123dd84ede6884b7c1ebed153e1c2f2563184cdbf28def07d677a7f25e2a824adb84e807b26b160a4b2a5293ae5f0ecfd69f25e5c2b457ce45e54514161fc488b142784cdc3a51f96e7c1fac1d93208705444f82e3774d501835be717ccb67effe3723f578 \
0091f566d9c878e9dcc61d41297bd3f65ca1d50c2f0d7e1b4187135cc8b60f7dde7c71f381c6692d5aa8626933c2e5a8e111a8c9317749cef03644abdb702381622f785ec2fe05485f198b57014422fb4efbcf9486d66c83c8ba53a8d691d76af1dec80b532e983702d \
2b30cad00904a22c5ea494a28caeb8f0130aa6b7d43067cb677c11a6fd2001a61c067e10ae8eebbaa0859f13be5ced6210fa6b3bf0eb2b15c9166608010b11d697cdb551c346c5bd5413a21e0c60f2f6ead79430cf0e5f1d96298aedc28c0fb3d9e07eed5438a3e81b8 \
3c8a1e44be36bbbe0f00fde3ac40609dc74ce4a53ce3cc59b463323f981d178bec19e62fc045a0b66c339b6e6595bd1bf186f7eea2813687ce7f37b0e8369ecc47c6617c30699fa0ff45a527eb534c6f0d2fcb87ebd2b9a50c26c20084666130b07493b8b7772431f3b \
a9b3b6f3070fc9aacd8e51da1be7fa936b38501bc94c64eeec4d9bb3e83452b49c93d970ad09019b0e34acf138ddec240047afd709e6a86489e6bd468fb10d376edfec5ee9a9048229773434cf17b060c1010489b324541c1cf0d86c96be2e7e4940c458567a64f236c \
489ef04e7d8592e089791e44"
                }],
                "acked": [],
                "signed": []
            },
            "localNextHtlcId": 0,
            "remoteNextHtlcId": 1,
            "originChannels": {},
            "remoteNextCommitInfo":
                "0293b7b7aeeae31455453426e8c6dc356cdbc572ba0e0f908286a007a3bf58b2ae",
            "commitInput": {
                "outPoint":
                    "c3ea8eeb37277c59b834e336a8536b522e116d5a8114eabbf630f62761f46cc4:0",
                "amountSatoshis": 2000000
            },
            "remotePerCommitmentSecrets": None,
            "channelId":
                "c46cf46127f630f6bbea14815a6d112e526b53a836e334b8597c2737eb8eeac3"
        },
        "mutualCloseProposed": [],
        "mutualClosePublished": [],
        "localCommitPublished": {
            "commitTx":
                "00000000000101c46cf46127f630f6bbea14815a6d112e526b53a836e334b8597c2737eb8eeac3000000000004a7048001002a1e0000000000160014f2533138510acb8042a552ef7bde2c0f7dc857ce040047304402204cdbb057560e7e5930 \
dc60ed30ccb0f929b05df7d07fb7a96cbe6d55cbb09a76022063912f22af08060d2f517c32bd4bb52f08ed45f9e5cef6012e532c08c1c4d17b014730440220188ae2a2d31a17b772b0706efdd56cb4192eb06c4731281c45de608a5e2d8c2402203ac075f7c6f9b6dfb \
aa70e20e0ba8c9a55b97a4c31b889167c471204ef95ac630147522102109051e36ef9a776d603ed96b9b8488a0bdd9c1b69390e0232be4e570c3e51762103a1ee29ef3af37f3072df2bd6391021fab53019a037e9093ed793898ddc4183c752ae00000000",
            "htlcSuccessTxs": [],
            "htlcTimeoutTxs": [],
            "claimHtlcDelayedTxs": [],
            "irrevocablySpent": {}
        },
        "revokedCommitPublished": []
    }
}

channel_error = 'command failed: channel 14be56f323eb36e3d295e5fe040db45a01e7213f5a0f88763752c00a0fd6132d not found'


channel_funding = {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
        "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
    "state": "WAIT_FOR_FUNDING_CONFIRMED",
    "data": {
        "commitments": {
            "localParams": {
                "nodeId":
                    "02c6a2fdf0ad76c1388b34273f09a97c1d4ebf3d2cae00a7171630a98ab9ced9ab",
                "channelKeyPath": {
                    "path": [2307247080, 1950049505, 2938673724, 1830280272]
                },
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "isFunder": False,
                "defaultFinalScriptPubKey":
                    "a914c0cc34aabf566a750fcb67324b397f23ab782d5e87",
                "globalFeatures": "",
                "localFeatures": "0a"
            },
            "remoteParams": {
                "nodeId":
                    "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "fundingPubKey":
                    "03a7b13bef5c3c9f4bdf8094951f1cbfe40720f44ec41ba7f64f5501746a31e845",
                "revocationBasepoint":
                    "02ed886baf1d9667896703ab1a2426f3c2684fd1e2eb5438d056bb8e29aa1b4106",
                "paymentBasepoint":
                    "02bbe0c4963d7c2a37a2b998b944388b357d97fce6f926b099164e1cef80819206",
                "delayedPaymentBasepoint":
                    "026b8c07abd41fd2e5d5aa239423639ed7be3b5a1112962af99927ff65ba4c4767",
                "htlcBasepoint":
                    "032cc12090f6d00358aa19785051d17cab2a43b407e1a3bbcb990f19025e2b7065",
                "globalFeatures": "",
                "localFeatures": "8a"
            },
            "channelFlags": 0,
            "localCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 31922,
                    "toLocalMsat": 0,
                    "toRemoteMsat": 2000000000
                },
                "publishableTxs": {
                    "commitTx":
                        "020000000001017a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2000000000092cc488001392a1e0000000000160 \
014a24ddf4ed36e5ae1b490d4422cb9d3e939af5435040047304402201e1b70010631b2228462c162b6cf3ff4fa761025395c11b72e7372ef45bee3fc02206e31bb3109c0974 \
2c8a0025872f732e929ad7f0f6124c1db5b5ad34036f351070147304402202cef1862fbf8d4c4e00b2ae53e2546af868091f2cac9fe42626adb1e8fa68155022028c8782903b \
9d958cc9199e922da631e7598642a47f3ef079f61cdef6ce4c3860147522102fdfb74cea2f643c6f4c48bfb94a5e784ac88491efae01147b57b4c30b3a5d8f72103a7b13bef5 \
c3c9f4bdf8094951f1cbfe40720f44ec41ba7f64f5501746a31e84552ae7b923320",
                    "htlcTxsAndSigs": []
                }
            },
            "remoteCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 31922,
                    "toLocalMsat": 2000000000,
                    "toRemoteMsat": 0
                },
                "txid":
                    "c8438059ea0e9d9907a02a9475ed624c41462f4f175df12c0e5ae54863c9f225",
                "remotePerCommitmentPoint":
                    "02984374c6304aafb0e59d491a045cddd45921702028a244c03cc0881f0e64bd8b"
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
            "remoteNextCommitInfo":
                "020ed63750e2bfc017dcb7c025250c14e7e503dd7ddd7f6c2f58de785cbaed22f4",
            "commitInput": {
                "outPoint":
                    "f2adf0175360ffaba072ca15a85d4c4bbf9c6ab1bbda0c1c3ac65594d4d8047a:0",
                "amountSatoshis": 2000000
            },
            "remotePerCommitmentSecrets": None,
            "channelId":
                "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2"
        },
        "lastSent": {
            "channelId":
                "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
            "signature":
                "3045022100f8018a103a73e06ab9a3ade488cfcdca8bfe8ed030f3f78b770d35ed81de9982022054f135d70bfd8724c972c65f0a7ca4f8c61656625d \
e8d8df198e7ca2c5c68b2c01"
        }
    }
}


channel_waiting = {
    "nodeId":
        "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
        "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
    "state": "WAIT_FOR_FUNDING_CONFIRMED",
    "data": {
        "commitments": {
            "localParams": {
                "nodeId":
                    "02c6a2fdf0ad76c1388b34273f09a97c1d4ebf3d2cae00a7171630a98ab9ced9ab",
                "channelKeyPath": {
                    "path": [2307247080, 1950049505, 2938673724, 1830280272]
                },
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "isFunder": False,
                "defaultFinalScriptPubKey":
                    "a914c0cc34aabf566a750fcb67324b397f23ab782d5e87",
                "globalFeatures": "",
                "localFeatures": "0a"
            },
            "remoteParams": {
                "nodeId":
                    "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "fundingPubKey":
                    "03a7b13bef5c3c9f4bdf8094951f1cbfe40720f44ec41ba7f64f5501746a31e845",
                "revocationBasepoint":
                    "02ed886baf1d9667896703ab1a2426f3c2684fd1e2eb5438d056bb8e29aa1b4106",
                "paymentBasepoint":
                    "02bbe0c4963d7c2a37a2b998b944388b357d97fce6f926b099164e1cef80819206",
                "delayedPaymentBasepoint":
                    "026b8c07abd41fd2e5d5aa239423639ed7be3b5a1112962af99927ff65ba4c4767",
                "htlcBasepoint":
                    "032cc12090f6d00358aa19785051d17cab2a43b407e1a3bbcb990f19025e2b7065",
                "globalFeatures": "",
                "localFeatures": "8a"
            },
            "channelFlags": 0,
            "localCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 31922,
                    "toLocalMsat": 0,
                    "toRemoteMsat": 2000000000
                },
                "publishableTxs": {
                    "commitTx":
                        "020000000001017a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2000000000092cc488001392a1e0000000000160014a24ddf4ed36e5ae1b490d4422cb9d3e939af5435040047304402201e1b70010631b2 \
228462c162b6cf3ff4fa761025395c11b72e7372ef45bee3fc02206e31bb3109c09742c8a0025872f732e929ad7f0f6124c1db5b5ad34036f351070147304402202cef1862fbf8d4c4e00b2ae53e2546af868091f2cac9fe42626adb1e8fa68155022028c8782903b9d \
958cc9199e922da631e7598642a47f3ef079f61cdef6ce4c3860147522102fdfb74cea2f643c6f4c48bfb94a5e784ac88491efae01147b57b4c30b3a5d8f72103a7b13bef5c3c9f4bdf8094951f1cbfe40720f44ec41ba7f64f5501746a31e84552ae7b923320",
                    "htlcTxsAndSigs": []
                }
            },
            "remoteCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 31922,
                    "toLocalMsat": 2000000000,
                    "toRemoteMsat": 0
                },
                "txid":
                    "c8438059ea0e9d9907a02a9475ed624c41462f4f175df12c0e5ae54863c9f225",
                "remotePerCommitmentPoint":
                    "02984374c6304aafb0e59d491a045cddd45921702028a244c03cc0881f0e64bd8b"
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
            "remoteNextCommitInfo":
                "020ed63750e2bfc017dcb7c025250c14e7e503dd7ddd7f6c2f58de785cbaed22f4",
            "commitInput": {
                "outPoint":
                    "f2adf0175360ffaba072ca15a85d4c4bbf9c6ab1bbda0c1c3ac65594d4d8047a:0",
                "amountSatoshis": 2000000
            },
            "remotePerCommitmentSecrets": None,
            "channelId":
                "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2"
        },
        "lastSent": {
            "channelId":
                "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
            "signature":
                "3045022100f8018a103a73e06ab9a3ade488cfcdca8bfe8ed030f3f78b770d35ed81de9982022054f135d70bfd8724c972c65f0a7ca4f8c61656625de8d8df198e7ca2c5c68b2c01"
        }
    }
}


channel_waiting_for_accept = {
    "nodeId":
        "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
    "channelId":
        "14be56f323eb36e3d295e5fe040db45a01e7213f5a0f88763752c00a0fd6132d",
    "state": "WAIT_FOR_ACCEPT_CHANNEL",
    "data": {
        "initFunder": {
            "temporaryChannelId":
                "14be56f323eb36e3d295e5fe040db45a01e7213f5a0f88763752c00a0fd6132d",
            "fundingSatoshis": 3200000,
            "pushMsat": 0,
            "initialFeeratePerKw": 31214,
            "fundingTxFeeratePerKw": 500,
            "localParams": {
                "nodeId":
                    "02c6a2fdf0ad76c1388b34273f09a97c1d4ebf3d2cae00a7171630a98ab9ced9ab",
                "channelKeyPath": {"path": [1938153712, 231676982, 1783817806, 4044805978]},
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 32000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "isFunder": True,
                "defaultFinalScriptPubKey":
                    "a9145761798e2d2a9c1af0da0a74a34c0deedb94958687",
                "globalFeatures": "",
                "localFeatures": "0a"
            },
            "remote": {
                "path": {
                    "parent": {
                        "parent": {
                            "parent": {
                                "parent": {
                                    "address": {
                                        "protocol": "akka",
                                        "system": "default"
                                    },
                                    "name": "/"
                                },
                                "name": "user",
                                "uid": 0
                            },
                            "name": "$g",
                            "uid": 301717002
                        },
                        "name": "authenticator",
                        "uid": 1857081162
                    },
                    "name": "$w",
                    "uid": -2028861491
                }
            },
            "remoteInit": {
                "globalFeatures": "",
                "localFeatures": "82"
            },
            "channelFlags": 1
        },
        "lastSent": {
            "chainHash":
                "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
            "temporaryChannelId":
                "14be56f323eb36e3d295e5fe040db45a01e7213f5a0f88763752c00a0fd6132d",
            "fundingSatoshis": 3200000,
            "pushMsat": 0,
            "dustLimitSatoshis": 546,
            "maxHtlcValueInFlightMsat": 1000000000,
            "channelReserveSatoshis": 32000,
            "htlcMinimumMsat": 1,
            "feeratePerKw": 31214,
            "toSelfDelay": 144,
            "maxAcceptedHtlcs":30,
            "fundingPubkey":
                "03c5a7310e9f38556c20833c91fe01229decb8b032abe693ab6186190dc9169c01",
            "revocationBasepoint":
                "03d6388c40d16100240665974a331ecd33998e2b5977b4fab4ad4d9d3c399c5546",
            "paymentBasepoint":
                "023ff18443c2d47ab97c99d4011e385913ebd4ea8dd6a7df2e108500ee6cc0b674",
            "delayedPaymentBasepoint":
                "0285b4169ccf7eb7f0a22cc858a21580ab579810d62c93d206b661aa132e65b874",
            "htlcBasepoint":
                "021282e05902d4822f2663dc5294082de0cacd63dd7500860faad15fd1ba097438",
            "firstPerCommitmentPoint":
                "022ce956e6339721b7e7f4fe7ffd0f155134ab715c21ac3b42a1308e8d4f47b6bf",
            "channelFlags": 1
        }
    }
}

channel_normal = {
    "nodeId":
    "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
    "channelId":
    "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2",
    "state":
    "NORMAL",
    "data": {
        "commitments": {
            "localParams": {
                "nodeId":
                "02c6a2fdf0ad76c1388b34273f09a97c1d4ebf3d2cae00a7171630a98ab9ced9ab",
                "channelKeyPath": {
                    "path": [2307247080, 1950049505, 2938673724, 1830280272]
                },
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "isFunder": False,
                "defaultFinalScriptPubKey":
                    "a914c0cc34aabf566a750fcb67324b397f23ab782d5e87",
                "globalFeatures": "",
                "localFeatures": "0a"
            },
            "remoteParams": {
                "nodeId":
                    "0322deb288d430d3165a261d1e1bb11833a36f3d7456432111ff6cff3f431c9ae1",
                "dustLimitSatoshis": 546,
                "maxHtlcValueInFlightMsat": 1000000000,
                "channelReserveSatoshis": 20000,
                "htlcMinimumMsat": 1,
                "toSelfDelay": 144,
                "maxAcceptedHtlcs": 30,
                "fundingPubKey":
                    "03a7b13bef5c3c9f4bdf8094951f1cbfe40720f44ec41ba7f64f5501746a31e845",
                "revocationBasepoint":
                    "02ed886baf1d9667896703ab1a2426f3c2684fd1e2eb5438d056bb8e29aa1b4106",
                "paymentBasepoint":
                    "02bbe0c4963d7c2a37a2b998b944388b357d97fce6f926b099164e1cef80819206",
                "delayedPaymentBasepoint":
                    "026b8c07abd41fd2e5d5aa239423639ed7be3b5a1112962af99927ff65ba4c4767",
                "htlcBasepoint":
                    "032cc12090f6d00358aa19785051d17cab2a43b407e1a3bbcb990f19025e2b7065",
                "globalFeatures": "",
                "localFeatures": "8a"
            },
            "channelFlags": 0,
            "localCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 31922,
                    "toLocalMsat": 0,
                    "toRemoteMsat": 2000000000
                },
                "publishableTxs": {
                    "commitTx":
                        "020000000001017a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2000000000092cc488001392a1e0000000000160 \
                    014a24ddf4ed36e5ae1b490d4422cb9d3e939af5435040047304402201e1b70010631b2228462c162b6cf3ff4fa761025395c11b72e7372ef45bee3fc02206e31bb3109c0974 \
                    2c8a0025872f732e929ad7f0f6124c1db5b5ad34036f351070147304402202cef1862fbf8d4c4e00b2ae53e2546af868091f2cac9fe42626adb1e8fa68155022028c8782903b \
                    9d958cc9199e922da631e7598642a47f3ef079f61cdef6ce4c3860147522102fdfb74cea2f643c6f4c48bfb94a5e784ac88491efae01147b57b4c30b3a5d8f72103a7b13bef5 \
                    c3c9f4bdf8094951f1cbfe40720f44ec41ba7f64f5501746a31e84552ae7b923320",
                    "htlcTxsAndSigs": []
                }
            },
            "remoteCommit": {
                "index": 0,
                "spec": {
                    "htlcs": [],
                    "feeratePerKw": 31922,
                    "toLocalMsat": 2000000000,
                    "toRemoteMsat": 0
                },
                "txid":
                    "c8438059ea0e9d9907a02a9475ed624c41462f4f175df12c0e5ae54863c9f225",
                "remotePerCommitmentPoint":
                    "02984374c6304aafb0e59d491a045cddd45921702028a244c03cc0881f0e64bd8b"
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
            "remoteNextCommitInfo":
                "022d74f2ad9551246e0db566b032ffa6844768aa69b8bf87f243182c55ddeea307",
            "commitInput": {
                "outPoint":
                    "f2adf0175360ffaba072ca15a85d4c4bbf9c6ab1bbda0c1c3ac65594d4d8047a:0",
                "amountSatoshis": 2000000
            },
            "remotePerCommitmentSecrets": None,
            "channelId":
                "7a04d8d49455c63a1c0cdabbb16a9cbf4b4c5da815ca72a0abff605317f0adf2"
        },
        "shortChannelId": "14b3490008b30000",
        "buried": False,
        "channelUpdate": {
            "signature":
                "3045022100a1fc2fa92efa78cc5824366db78208b98770ea3800c5d97b1abf41da19c55c2302200f29464fc066b25eff543a21deafdd809030314da5 \
            fd9ac040d2a684aeca486e01",
            "chainHash":
                "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
            "shortChannelId": "14b3490008b30000",
            "timestamp": 1533214957,
            "flags": "0000",
            "cltvExpiryDelta": 144,
            "htlcMinimumMsat": 1,
            "feeBaseMsat": 1000,
            "feeProportionalMillionths": 100
        }
    }
}


checkinvoice_desc = {
    "prefix": "lntb",
    "amount": 777000,
    "timestamp": 1542813782,
    "nodeId": "031aa03c3f6681a3773ec7a6933bc72baf6d75014feea24341b81a04f5c543521a",
    "tags": [
    {
      "hash": "32d3a1ac5d206c4861ebafd0214033a36f169bb622ab2f9ac0136b2188581836"
    },
    {
      "description": "lighter is cool"
    },
    {
      "blocks": 144
    },
    {
      "seconds": 60
    }
    ],
    "signature": "3b1b519a11040ca9c30f5ad1dc350817ac8bf7c48bc801f72003a962cab96eb57d601b1a71336db6cf70925961f77fadd350e1b8f5200284e5ed4a714614cb7500"
}


# invoice: lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr$yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn$q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj
checkinvoice_hash = {
    "prefix": "lnbc",
    "amount": 2000000000,
    "timestamp": 1496314658,
    "nodeId": "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
    "tags": [
    {
      "hash": "0001020304050607080900010203040506070809000102030405060708090102"
    },
    {
      "hash": "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1"
    },
    {
      "version": 17,
      "hash": "04b61f7dc1ea0dc99424464cc4064dc564d91e89"
    },
    {
      "path": [
        {
          "nodeId": "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
          "shortChannelId": "102030405060708",
          "feeBaseMsat": 1,
          "feeProportionalMillionths": 20,
          "cltvExpiryDelta": 3
        },
        {
          "nodeId": "039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
          "shortChannelId": "30405060708090a",
          "feeBaseMsat": 2,
          "feeProportionalMillionths": 30,
          "cltvExpiryDelta": 4
        }
      ]
    }
    ],
    "signature": "91675cb3fad8e9d915343883a49242e074474e26d42c7ed914655689a8074553733e8e4ea5ce9b85f69e40d755a55014536b12323f8b220600c94ef2b9c5142800"
}



details = {
    "prefix": "lntb",
    "timestamp": 1533041362,
    "nodeId": "022237417f8a9b4fcf4b6525c575af2800eb330e48c",
    "tags": [
        {
        "hash": "a3af1a3caef9370b3d75a49f35425c"
        },
        {
        "description": "dog"
        },
        {
        "seconds": 3600
        }
    ],
    "signature": "bcf9b1864ed0f12f3d64511896eab0"
}


getinfo = {
    "chainHash":
        "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
    "nodeId": "id",
    "alias": "pie",
    "blockHeight": 7777
}


getinfo_mainnet = {
    "chainHash":
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
}


getinfo_testnet = {
    "chainHash":
        "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000"
}


getinfo_unknown = {
    "chainHash": "aaazzz"
}


peers = [
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
    "state": "DISCONNECTED",
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


peers2 = [
    {
    "nodeId": "pubkey_1",
    "state": "DISCONNECTED"
    },
    {
    "nodeId": "pubkey_2",
    "state": "CONNECTED",
    "address": "",
    "channels": 0
    }
]


send = {
    "amountMsat": 345000,
    "paymentHash":
        "8cfa048e6fc9ac961e60f3f779e4f0e0a082c8f74a0fcb523fa04bbb7af16fbd",
    "paymentPreimage":
        "c38555f240425583f9a8339d30f4729774ebe06f70b751fba9e55756e8102bbf",
    "route": [{
        "nodeId":
            "02c6a2fdf0ad76c1388b34273f09a97c1d4ebf3d2cae00a7171630a98ab9ced9ab",
        "nextNodeId":
            "0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7",
        "lastUpdate": {
            "signature":
                "304402203b982b4205c0d78641f149dff649d665af6cdc6d5e3499a9161b4534c8ce5bdc02207e4c665839207633d433579a7af6a7d421dbab8e0439e5a0bb07fb66e6aedd3101",
            "chainHash":
                "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
            "shortChannelId": "14a2e30000530000",
            "timestamp": 1531144683,
            "flags": "0001",
            "cltvExpiryDelta": 144,
            "htlcMinimumMsat": 1000,
            "feeBaseMsat": 1000,
            "feeProportionalMillionths": 100
        }
    }]
}


send_error = 'payment request is not valid'


send_error_funds = {
    "paymentHash":
        "18d102a78b124d4a2155b0bf955b7096215be3fb4b99698c6f95fdf66d1d64a3",
    "failures": [
        {
        "t":
        "insufficient funds: missingSatoshis=20007 reserveSatoshis=20000 fees=0"
        }
    ]
}


send_route = {
    "paymentHash":
        "a6b644b674184a8a9d5e5d9fc310bc80b2da72e6caf9d6a211cc472135b2a0f7",
    "failures": [
        {
        "t": "route not found"
        }
    ]
}


send_slow = 'request timed out'


strangeresponse = 'i\'m a strange and never expected response'
