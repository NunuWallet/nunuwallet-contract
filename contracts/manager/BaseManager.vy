# @version 0.3.7


interface NunuAccount:
    def isValidSignature(_hash: bytes32, _signature: Bytes[65]) -> bytes4: view

interface OracleManager:
    def in_token(_token: address, _eth_amount: uint256) -> uint256: view
    def in_eth(_token: address, _token_amount: uint256) -> uint256: view


event AddAuthoriseRelayer:
    relayer: indexed(address)
    exists: bool

event RemoveAuthoriseRelayer:
    relayer: indexed(address)
    exists: bool

event AddedToWhitelist:
    wallet: indexed(address)
    target: indexed(address)
    period: uint256

event RemovedForWhitelist:
    wallet: indexed(address)
    target: indexed(address)

event TranscationExecuted:
     wallet: indexed(address)
     success: bool
     return_data: Bytes[max_value(uint16)]

event Refund:
     wallet: indexed(address)
     refund_address: indexed(address)
     refund_token: address
     refund_amount: uint256

event ChangeOwner:
    old_owner: indexed(address)
    new_owner: indexed(address)

event ChangeProxy:
    old_proxy: indexed(address)
    new_proxy: indexed(address)

event ChangeOracle:
    old_oracle: indexed(address)
    new_oracle: indexed(address)


struct MultiCall:
    target: address
    allow_failure: bool
    value: uint256
    call_data: Bytes[max_value(uint16)]

struct Result:
    success: bool
    return_data: Bytes[max_value(uint8)]

struct ExecuteParameters:
    owner: address
    account: address
    transaction_to: address
    transaction_calldata: Bytes[max_value(uint16)]
    transaction_value: uint256
    nonce: uint256
    gas_price: uint256
    gas_limit: uint256
    deadline: uint256
    refund_token: address
    refund_address: address
    signature: Bytes[65]

NATIVE_TOKEN: constant(address) = empty(address)
EMPTY_BYTES: constant(bytes32) = empty(bytes32)
IERC1271_ISVALIDSIGNATURE_SELECTOR: public(constant(bytes4)) = 0x1626BA7E

EXECUTE_PARAMETERS_TYPEHASH: constant(bytes32) = keccak256(
    "ExecuteParameters(address owner,address account,address transaction_to,uint256 transaction_value,uint256 nonce,uint256 gas_price,uint256 gas_limit,uint256 deadline,address refund_token,address refund_address)"
)
EIP712_TYPEHASH: constant(bytes32) = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

DOMAIN_SEPARATOR: immutable(bytes32)
NAME: immutable(String[64])
VERSION: constant(String[8]) = "v1.0.0"

owner: public(address)
authorise_relayer: HashMap[address, bool]

whitelist_period: public(uint256)
whitelist: HashMap[address, HashMap[address, uint256]]

proxy: public(address)
oracle: public(address)
security: public(address)
expired_hash: public(HashMap[bytes32, bool])


@external
def __init__(_relayer: address, _whitelist_period: uint256, _proxy: address, _oracle: address, _security: address):
    self.owner = msg.sender
    self.authorise_relayer[_relayer] = True
    self.whitelist_period = _whitelist_period

    self.proxy = _proxy
    self.oracle = _oracle
    self.security = _security

    name: String[64] = concat("Nunu Wallet Base Manager", " v1")
    NAME = name

    DOMAIN_SEPARATOR = keccak256(
        _abi_encode(EIP712_TYPEHASH, keccak256(name), keccak256(VERSION), chain.id, self)
    )


@view
@external
def is_authorise_relayer(_relayer: address) -> bool:
    return self._is_authorise_relayer(_relayer)


@view
@external
def is_whitelist(_wallet: address, _target: address) -> bool:
    return self._is_whitelist(_wallet, _target)
    

@view
@internal
def _is_authorise_relayer(_relayer: address) -> bool:
    return self.authorise_relayer[_relayer]


@view
@internal
def _is_whitelist(_wallet: address, _target: address) -> bool:
    assert _wallet != _target, "Nunu: Cannot whitelist wallet"

    _iw: bool = False
    if self.whitelist[_wallet][_target] != 0:
        _iw = True
    return _iw


@pure
@internal
def _execute_parameters_hash(_param: ExecuteParameters) -> bytes32:

    param_hash: bytes32 = keccak256(
        _abi_encode(
            EXECUTE_PARAMETERS_TYPEHASH,
            _param.owner,
            _param.account,
            _param.transaction_to,
            _param.transaction_value,
            _param.nonce,
            _param.gas_price,
            _param.gas_limit,
            _param.deadline,
            _param.refund_token,
            _param.refund_address
        )
    )

    digest: bytes32 = keccak256(
        concat(
            b"\x19\x01",
            DOMAIN_SEPARATOR,
            param_hash
        )
    )

    return digest


@internal
def _refund(
    _account: address,
    _calldata: Bytes[max_value(uint16)],
    _start_gas: uint256,
    _gas_price: uint256,
    _gas_limit: uint256,
    _refund_token: address,
    _refund_address: address
) -> bool:
    
    if _gas_price > 0:
        assert _refund_address != empty(address), "Nunu: empty refund address"

        refund_amount: uint256 = 0

        # empty(address) is ETH
        if _refund_token == empty(address):

            gas_consumed: uint256 = _start_gas - msg.gas + 23000
            refund_amount = min(gas_consumed, _gas_limit) * min(_gas_price, tx.gasprice)
            
            raw_call(
                self.proxy,
                _abi_encode(
                    _account,
                    _refund_address,
                    refund_amount,
                    _calldata,
                    method_id=method_id("execute(address,address,uint256,bytes)")
                )
            )

        else:
            gas_consumed: uint256 = _start_gas - msg.gas + 37500
            
            # Here it is also necessary to calculate how many tokens the gas price can be exchanged for
            # Then the final gas fee to be paid is obtained by gaslimit * token price
            token_gas_price: uint256 = OracleManager(self.oracle).in_token(_refund_token, tx.gasprice)
            # token_gas_price: uint256 = tx.gasprice
            refund_amount = min(gas_consumed, _gas_limit) + min(_gas_price, token_gas_price)

            success: bool = False
            response: Bytes[32] = b""

            success, response = raw_call(
                self.proxy,
                _abi_encode(
                    _account,
                    _refund_token,
                    empty(uint256),
                    _abi_encode(
                        _refund_address,
                        refund_amount,
                        method_id=method_id("transfer(address,uint256)")
                    ),
                    method_id=method_id("execute(address,address,uint256,bytes)")
                ),
                max_outsize=32,
                revert_on_failure=False
            )

            if len(response) != 0:
                assert convert(response, bool), "Nunu: call fail"

            assert success, "Nunu: refund transfer fail"

        log Refund(_account, _refund_address, _refund_token, refund_amount)

    return True


@external
def add_authorise_relayer(_relayer: address):
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Nunu: sender not authorized"
    
    self.authorise_relayer[_relayer] = True
    log AddAuthoriseRelayer(_relayer, True)


@external
def remove_authorise_relayer(_relayer: address):
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Nunu: sender not authorized"

    self.authorise_relayer[_relayer] = False
    log RemoveAuthoriseRelayer(_relayer, False)


@external
def add_whitelist(_wallet: address, _target: address):
    assert _wallet != _target, "Nunu: cannot whitelist wallet"
    assert not self._is_whitelist(_wallet, _target), "Nunu: target already whitelisted"
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Nunu: sender not authorized"

    whitelistAfter: uint256 = block.timestamp + self.whitelist_period
    self.whitelist[_wallet][_target] = whitelistAfter

    log AddedToWhitelist(_wallet, _target, whitelistAfter)


@external
def remove_whitelist(_wallet: address, _target: address):
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Nunu: sender not authorized"

    self.whitelist[_wallet][_target] = 0
    
    log RemovedForWhitelist(_wallet, _target)


@external
def change_owner(_new_owner: address):
    assert msg.sender == self.owner, "Nunu: only owner"
    
    old_owner: address = self.owner
    self.owner = _new_owner
    log ChangeOwner(old_owner, _new_owner)


@external
def change_proxy(_new_proxy: address):
    assert msg.sender == self.owner, "Nunu: only owner"
    
    old_proxy: address = self.proxy
    self.proxy = _new_proxy
    log ChangeProxy(old_proxy, _new_proxy)
    

@external
def change_oracle(_new_oracle: address):
    assert msg.sender == self.owner, "Nunu: only owner"
    
    old_oracle: address = self.oracle
    self.oracle = _new_oracle
    log ChangeOracle(old_oracle, _new_oracle)


@external
def withdraw(_token: address, _amount: uint256) -> bool:
    assert msg.sender == self.owner, "NUNU: only owner"

    raw_call(
        _token,
        _abi_encode(
            msg.sender,
            _amount,
            method_id=method_id("transfer(address,uint256)")
        )
    )

    return True


@external
def multi_call(_transactions: DynArray[MultiCall, 30]) -> DynArray[Result, 30]:
    assert self._is_authorise_relayer(msg.sender), "Nunu: sender not be authorise"
    assert len(_transactions) != 0, "empty call"

    results: DynArray[Result, 30] = []
    return_data: Bytes[max_value(uint8)] = b""
    success: bool = empty(bool)

    for i in range(30):
        if i >= len(_transactions):
            break

        if _transactions[i].allow_failure == False:
            return_data = raw_call(
                self,
                _transactions[i].call_data,
                max_outsize=255,
                is_delegate_call=True
            )
            success = True

            results.append(Result({success: success, return_data: return_data}))

        else:
            success, return_data = raw_call(
                _transactions[i].target,
                _transactions[i].call_data,
                max_outsize=255,
                is_delegate_call=True,
                revert_on_failure=False
            )

            results.append(Result({success: success, return_data: return_data}))

    return results


@external
def execute(_param: ExecuteParameters) -> bool:
    assert self._is_authorise_relayer(msg.sender), "Nunu: sender not be authorise"
    assert block.timestamp <= _param.deadline, "expired deadline"

    # gas = 21k + non zero byte * 16 + zero byte * 4
    #     ~= 21k + len(msg.data) * [1/3 * 16 + 2/3 * 4]
    start_gas: uint256 = msg.gas + 21000 + len(msg.data) * 8
    assert start_gas >= _param.gas_limit, "not enough gas provided"

    digest: bytes32 = self._execute_parameters_hash(_param)

    assert not self.expired_hash[digest], "Nunu: expired hash"
    assert IERC1271_ISVALIDSIGNATURE_SELECTOR == NunuAccount(_param.account).isValidSignature(digest, _param.signature), "signature fail"

    refund_success: bool = self._refund(
        _param.account,
        b"",
        start_gas,
        _param.gas_price,
        _param.gas_limit,
        _param.refund_token,
        _param.refund_address
    )

    assert refund_success, "Nunu: refund fail"

    success: bool = False
    return_data: Bytes[32] = b""

    success, return_data = raw_call(
        self.proxy,
        _abi_encode(
            _param.account,
            _param.transaction_to,
            _param.transaction_value,
            _param.transaction_calldata,
            method_id=method_id("execute(address,address,uint256,bytes)")
        ),
        max_outsize=32,
        revert_on_failure=False
    )
    assert success, "Nunu: call fail"

    log TranscationExecuted(_param.account, success, return_data)
    return True

