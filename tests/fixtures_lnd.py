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
