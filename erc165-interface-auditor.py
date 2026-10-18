#!/usr/bin/env python3
"""Audit ERC-165 interface claims using read-only JSON-RPC calls."""

import argparse
import json
import re
import sys
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

_MASK64 = (1 << 64) - 1


def _rotation_offsets() -> List[int]:
    offsets = [0] * 25
    x, y = 1, 0
    for t in range(24):
        offsets[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


def _lfsr_bit(t: int) -> int:
    if t % 255 == 0:
        return 1
    register = 0x01
    for _ in range(t % 255):
        register = (((register << 1) ^ 0x71) if register & 0x80 else (register << 1)) & 0xFF
    return register & 1


def _round_constants() -> List[int]:
    constants: List[int] = []
    for round_index in range(24):
        value = 0
        for j in range(7):
            if _lfsr_bit(j + 7 * round_index):
                value ^= 1 << ((1 << j) - 1)
        constants.append(value)
    return constants


_ROTATIONS = _rotation_offsets()
_ROUND_CONSTANTS = _round_constants()


def _rotl(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state: List[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        parity = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        delta = [parity[(x - 1) % 5] ^ _rotl(parity[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= delta[x]

        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(
                    state[x + 5 * y], _ROTATIONS[x + 5 * y]
                )
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ (
                    (~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]
                )
        state[0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Keccak-256, with the original 0x01 padding rather than SHA3 padding."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _keccak_f(state)
    output = bytearray()
    while len(output) < 32:
        for lane in range(rate // 8):
            output.extend(state[lane].to_bytes(8, "little"))
        if len(output) < 32:
            _keccak_f(state)
    return bytes(output[:32])


def function_selector(signature: str) -> str:
    return keccak256(signature.encode("ascii"))[:4].hex()


def is_address(value: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))


def normalize_address(value: str) -> str:
    if not is_address(value):
        raise ValueError(f"invalid address: {value}")
    return value.lower()


class RpcError(Exception):
    def __init__(self, message: str, data: Any = None):
        super().__init__(message)
        self.message = message
        self.data = data


class JsonRpcClient:
    """Small JSON-RPC client. A transport can be injected by tests."""

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        transport: Optional[Callable[[str, List[Any]], Dict[str, Any]]] = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.transport = transport
        self._next_id = 1

    def call(self, method: str, params: List[Any]) -> Any:
        if self.transport is not None:
            response = self.transport(method, params)
        else:
            body = json.dumps(
                {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
            ).encode("utf-8")
            self._next_id += 1
            request = urllib.request.Request(
                self.url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "erc165-interface-auditor/1.0",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    result = json.loads(response.read().decode("utf-8"))
            except Exception as exc:
                raise RpcError(f"RPC request failed: {exc}") from exc
            response = result
        if "error" in response:
            error = response["error"]
            if isinstance(error, dict):
                raise RpcError(str(error.get("message", "JSON-RPC error")), error.get("data"))
            raise RpcError(str(error))
        if "result" not in response:
            raise RpcError("JSON-RPC response has neither result nor error")
        return response["result"]


def encode_supports_interface(interface_id: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{8}", interface_id):
        raise ValueError("interface ID must contain exactly 8 hexadecimal characters")
    # bytes4 is left-aligned in its 32-byte ABI slot.
    return "0x" + function_selector("supportsInterface(bytes4)") + interface_id.lower() + "0" * 56


def decode_support_result(result: Any) -> Dict[str, Any]:
    if not isinstance(result, str) or not result.startswith("0x"):
        return {"status": "invalid_return", "return_data": result}
    payload = result[2:]
    if payload == "":
        return {"status": "empty_return", "return_data": result}
    if len(payload) < 64:
        return {"status": "invalid_return", "return_data": result}
    value = int(payload[:64], 16)
    if value == 0:
        return {"status": "not_supported", "return_value": False, "return_data": result}
    if value == 1:
        return {"status": "supported", "return_value": True, "return_data": result}
    return {"status": "invalid_return", "return_value": value, "return_data": result}


def _error_data_hex(data: Any) -> Optional[str]:
    if isinstance(data, str) and data.startswith("0x"):
        return data
    if isinstance(data, dict):
        for key in ("data", "return", "result"):
            found = _error_data_hex(data.get(key))
            if found:
                return found
    return None


def describe_rpc_error(exc: RpcError) -> str:
    raw = _error_data_hex(exc.data)
    if raw:
        return f"{exc.message} ({raw[:18]}...)" if len(raw) > 18 else f"{exc.message} ({raw})"
    return exc.message


def _parse_interfaces(items: Optional[Iterable[str]]) -> List[Tuple[str, str]]:
    if not items:
        return [
            ("erc165", "01ffc9a7"),
            ("invalid", "ffffffff"),
            ("erc721", "80ac58cd"),
            ("erc1155", "d9b67a26"),
            ("erc2981", "2a55205a"),
        ]
    parsed: List[Tuple[str, str]] = []
    names = set()
    for item in items:
        if "=" not in item:
            raise ValueError(f"interface must be NAME=8_HEX_DIGITS: {item}")
        name, interface_id = item.split("=", 1)
        name = name.strip().lower()
        if not name or name in names:
            raise ValueError(f"duplicate or empty interface name: {name}")
        encode_supports_interface(interface_id)
        names.add(name)
        parsed.append((name, interface_id.lower()))
    return parsed


def audit_interfaces(
    client: JsonRpcClient,
    address: str,
    interfaces: Optional[Iterable[Tuple[str, str]]] = None,
    block_tag: str = "latest",
) -> Dict[str, Any]:
    address = normalize_address(address)
    selected = list(interfaces) if interfaces is not None else _parse_interfaces(None)
    chain_id = client.call("eth_chainId", [])
    block_number = client.call("eth_blockNumber", [])
    code = client.call("eth_getCode", [address, block_tag])
    results: Dict[str, Dict[str, Any]] = {}
    for name, interface_id in selected:
        try:
            result = client.call(
                "eth_call",
                [{"to": address, "data": encode_supports_interface(interface_id)}, block_tag],
            )
            results[name] = {"interface_id": "0x" + interface_id, **decode_support_result(result)}
        except RpcError as exc:
            results[name] = {
                "interface_id": "0x" + interface_id,
                "status": "reverted",
                "error": describe_rpc_error(exc),
            }

    erc165 = results.get("erc165", {}).get("status")
    invalid = results.get("invalid", {}).get("status")
    if erc165 == "supported" and invalid == "not_supported":
        conclusion = "valid_erc165_behavior"
    elif erc165 == "supported" and invalid == "supported":
        conclusion = "invalid_erc165_behavior"
    else:
        conclusion = "no_confirmed_erc165_behavior"
    supported = [name for name, result in results.items() if result.get("status") == "supported"]
    return {
        "chain_id": chain_id,
        "block_number": block_number,
        "block_tag": block_tag,
        "address": address,
        "code_present": isinstance(code, str) and code not in ("0x", "0x0"),
        "interfaces": results,
        "supported_interfaces": supported,
        "conclusion": conclusion,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit ERC-165 interface claims with read-only eth_call requests."
    )
    parser.add_argument("--rpc-url", required=True, help="JSON-RPC endpoint")
    parser.add_argument("--address", required=True, help="contract address")
    parser.add_argument("--block", default="latest", dest="block_tag", help="block tag or hex block number")
    parser.add_argument(
        "--interface",
        action="append",
        dest="interfaces",
        help="optional NAME=8_HEX_DIGITS; repeat to replace the default matrix",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        selected = _parse_interfaces(args.interfaces)
        report = audit_interfaces(JsonRpcClient(args.rpc_url), args.address, selected, args.block_tag)
    except (ValueError, RpcError) as exc:
        parser.error(str(exc))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
