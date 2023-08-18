# @version 0.3.7


a: public(uint256)
b: public(uint256)

owner: public(address)

@external
def __init__():
    self.owner = msg.sender


@external
def compute_add(_x: uint256, _y: uint256):
    self.a = _x + _y


@external
def compute_add_owner(_x: uint256, _y: uint256):
    assert msg.sender == self.owner, "only owner"
    self.a = _x + _y


@external
def compute_add_mul_owner(_x: uint256, _y: uint256):
    assert msg.sender == self.owner, "only owner"
    self.a = _x * _y


@external
def compute_add_mul(_x: uint256, _y: uint256):
    self.a = _x * _y


