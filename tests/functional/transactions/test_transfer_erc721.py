import pytest
import time
from ape import accounts


def test_transfer_erc721(bob, w3, proxy, base, nft, base_sign_message, new_account):

    # authorise fist
    proxy.authorise_module(base.address, sender=bob)

    new_account_address = new_account
    
    nft.mint(new_account_address, 1, sender=bob)

    zero_address = "0x0000000000000000000000000000000000000000"

    # encode transfer token data
    data = nft.transferFrom.encode_input(new_account_address, accounts[0], 1)

    owner = bob.address
    account = new_account_address
    transaction_to = nft.address
    transaction_calldata = data
    transaction_value = 0
    nonce = 1
    gas_price = 10000
    gas_limit = 10000
    deadline = int(time.time()) + 1800
    refund_token = zero_address
    refund_addres = accounts[0].address

    signature = base_sign_message(
        owner, 
        account, 
        transaction_to, 
        transaction_value, 
        nonce, 
        gas_price, 
        gas_limit, 
        deadline, 
        refund_token, 
        refund_addres, 
        base.address, 
        w3
    )

    param = {
        "owner": owner,
        'account': account,
        'transaction_to': transaction_to,
        'transaction_calldata': transaction_calldata,
        'transaction_value': transaction_value,
        'nonce': nonce,
        'gas_price': gas_price,
        'gas_limit': gas_limit,
        'deadline': deadline,
        'refund_token': refund_token,
        'refund_address': refund_addres,
        'signature': signature
    }

    base.execute(param, sender=bob)

    assert nft.ownerOf(1) == accounts[0]

