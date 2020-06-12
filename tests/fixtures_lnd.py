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

""" Fixtures for test_light_lnd module """

from importlib import import_module

from . import proj_root

ln = import_module(proj_root + '.rpc_pb2')


GETINFO_MAINNET = ln.GetInfoResponse(
    identity_pubkey='asd', chains=[ln.Chain(network="mainnet")])

GETINFO_TESTNET = ln.GetInfoResponse(
    identity_pubkey='asd', chains=[ln.Chain(network="testnet")],
    uris=['uri'], color='#DCDCDC', alias='lighter')

TXID = "fd7f6077b3d76aa6c17b0cd66b2736142fda2662c5e782be724316e365400768"
TXID_BYTES = b"h\x07@e\xe3\x16Cr\xbe\x82\xe7\xc5b&\xda/\x146'k\xd6\x0c{\xc1\xa6j\xd7\xb3w`\x7f\xfd"
ADDRESS = "n1ER93kV9ox9ccrA4fxGZa9JXEGnhLDGnF"

NODE_ID = "021f7b8bbfbca12b6520683fe39aa80316b729b49db6735a164ad019f81485a684"
HOST = "snoopy"
PORT = 9735
NODE_URI = '{}@{}:{}'.format(NODE_ID, HOST, PORT)

NOW = 1549296034

HOP_HINT0 = ln.HopHint(node_id=NODE_ID, fee_base_msat=66)
HOP_HINT1 = ln.HopHint(node_id=NODE_ID, fee_base_msat=77)
HOP_HINTS0 = [HOP_HINT0, HOP_HINT1]
ROUTE_HINT0 = ln.RouteHint(hop_hints=HOP_HINTS0)

HOP_HINT2 = ln.HopHint(node_id=NODE_ID, fee_base_msat=88)
HOP_HINT3 = ln.HopHint(node_id=NODE_ID, fee_base_msat=99)
HOP_HINTS1 = [HOP_HINT2, HOP_HINT3]
ROUTE_HINT1 = ln.RouteHint(hop_hints=HOP_HINTS1)

ROUTE_HINTS = [ROUTE_HINT0, ROUTE_HINT1]

INVOICE = ln.Invoice(memo="lighter", value=777, route_hints=ROUTE_HINTS,
                     amt_paid_msat=999000)

PAYMENT = ln.Payment(payment_hash="0abc", creation_date=1549277641, value_msat=777)

DEST_ADDRESSES = ["1", "2"]

TRANSACTION = ln.Transaction(tx_hash=TXID, amount=7, dest_addresses=DEST_ADDRESSES)

PAYMENT1 = ln.Payment(payment_hash="0abc", creation_date=NOW, value_msat=777)
PAYMENT2 = ln.Payment(payment_hash="0def", creation_date=(NOW - 10000), value_msat=888)
PAYMENT3 = ln.Payment(payment_hash="0ghi", creation_date=(NOW + 10000), value_msat=999)
PAYMENTS = [PAYMENT1, PAYMENT2, PAYMENT3]

EXPIRY = 3600
# paid invoice
INVOICE_PAID = ln.Invoice(creation_date=NOW - 100000, expiry=EXPIRY, state=1)
# pending invoice
INVOICE_PENDING = ln.Invoice(creation_date=NOW - 1, expiry=EXPIRY, state=0)
# expired invoice
INVOICE_EXPIRED = ln.Invoice(creation_date=NOW - 100000, expiry=EXPIRY, state=0)
# unkown invoice
INVOICE_UNKNOWN = ln.Invoice(state=7)

INVOICES = [INVOICE_PAID, INVOICE_PENDING, INVOICE_EXPIRED, INVOICE_UNKNOWN]

CHAN_ID = 881808325541888
REMOTE_NODE_PUB = '0392708c1e6fc4a98c9184c6bcb7cb5ffe4d88c756e36f47a97520a6d0df9fefcf'
CHAN_POINT = '063758d210cf244cf71ced5864a0a9a13f58c6e71735945fa6521e686cbbc5e6:0'
LOC_TXID = '1128dcde5432bec2a705929dd05a3470fa82026aa8ed1da6004fb3f57f3377ff'
REM_TXID = '19acd65ae4e3bdb598eea8989efdae276858815558147747aea258b95cf5db0a'
CAPACITY_BITS = 77854.54
LOC_BAL_BITS = 66666.66
REM_BAL_BITS = 11111.11
COMMIT_FEE_BITS = 76.77
CAPACITY_SAT = int(CAPACITY_BITS * 100)
LOC_BAL_SAT = int(LOC_BAL_BITS * 100)
REM_BAL_SAT = int(REM_BAL_BITS * 100)
COMMIT_FEE_SAT = int(COMMIT_FEE_BITS * 100)
CHAN_RESERVE = 1000

COMMITMENTS = ln.PendingChannelsResponse.Commitments(
    local_txid=LOC_TXID, remote_txid=REM_TXID,
    local_commit_fee_sat=COMMIT_FEE_SAT, remote_commit_fee_sat=COMMIT_FEE_SAT)

OPEN_CHAN = ln.Channel(
    chan_id=CHAN_ID, capacity=CAPACITY_SAT, local_balance=LOC_BAL_SAT,
    remote_balance=REM_BAL_SAT, commit_fee=COMMIT_FEE_SAT, initiator=False)

OPEN_CHAN_INACTIVE = ln.Channel(
    chan_id=CHAN_ID, capacity=CAPACITY_SAT, local_balance=LOC_BAL_SAT,
    remote_balance=REM_BAL_SAT, active=False)

OPEN_CHAN_INITIATOR = lnd_chan = ln.Channel(
    chan_id=CHAN_ID, capacity=CAPACITY_SAT, local_balance=LOC_BAL_SAT,
    remote_balance=REM_BAL_SAT, commit_fee=COMMIT_FEE_SAT, initiator=True)

PENDING_CHAN = ln.PendingChannelsResponse.PendingChannel(
    remote_node_pub=REMOTE_NODE_PUB, capacity=CAPACITY_SAT,
    local_balance=LOC_BAL_SAT, remote_balance=REM_BAL_SAT,
    channel_point=CHAN_POINT, local_chan_reserve_sat=CHAN_RESERVE,
    remote_chan_reserve_sat=CHAN_RESERVE, initiator=ln.INITIATOR_REMOTE,
    commitment_type=ln.STATIC_REMOTE_KEY)

PENDING_CHAN_INITIATOR = ln.PendingChannelsResponse.PendingChannel(
    remote_node_pub=REMOTE_NODE_PUB, capacity=CAPACITY_SAT,
    local_balance=LOC_BAL_SAT, remote_balance=REM_BAL_SAT,
    channel_point=CHAN_POINT, local_chan_reserve_sat=CHAN_RESERVE,
    remote_chan_reserve_sat=CHAN_RESERVE, initiator=ln.INITIATOR_LOCAL,
    commitment_type=ln.STATIC_REMOTE_KEY)

PENDING_OPEN_CHAN = ln.PendingChannelsResponse.PendingOpenChannel(
    channel=PENDING_CHAN_INITIATOR, commit_fee=COMMIT_FEE_SAT,
    commit_weight=552, fee_per_kw=253)

WAITING_CLOSE_CHAN = ln.PendingChannelsResponse.WaitingCloseChannel(
    channel=PENDING_CHAN, limbo_balance=1000, commitments=COMMITMENTS)

def get_listpayments_response():
    response = ln.ListPaymentsResponse()
    # for payment in payments_list:
    response.payments.extend(PAYMENTS)
    return response

def get_invoices_response(request):
    response = ln.ListInvoiceResponse(first_index_offset=1 , last_index_offset=len(INVOICES))
    response.invoices.extend(INVOICES)
    return response

def get_transactions_response():
    transaction2 = ln.Transaction(tx_hash="1abc")
    transactions_list = [TRANSACTION, transaction2]
    response = ln.TransactionDetails()
    response.transactions.extend(transactions_list)
    return response
