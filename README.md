# erc165-interface-auditor

`erc165-interface-auditor` checks a contract's ERC-165 claims for ERC-721, ERC-1155, and ERC-2981, while also testing the ERC-165 and 0xffffffff control IDs. It is useful for deciding whether a token contract can be safely routed through an integration without trusting an indexer or a source repository.

## Example

These are real read-only runs made on 2026-10-11 UTC. Ethereum mainnet Azuki reported valid ERC-165 behavior and ERC-721 support. Optimism WETH returned empty data for the same probes, so the tool did not mistake an empty response for a reliable false value. The excerpts below show selected fields from the actual output.

```text
$ python erc165-interface-auditor.py --rpc-url https://ethereum-rpc.publicnode.com --address 0xed5af388653567af2f388e6224dc7c4b3241c544
{
  "address": "0xed5af388653567af2f388e6224dc7c4b3241c544",
  "chain_id": "0x1",
  "block_number": "0x18f4340",
  "code_present": true,
  "conclusion": "valid_erc165_behavior",
  "supported_interfaces": ["erc165", "erc721"]
}

$ python erc165-interface-auditor.py --rpc-url https://mainnet.optimism.io --address 0x4200000000000000000000000000000000000006
{
  "address": "0x4200000000000000000000000000000000000006",
  "chain_id": "0xa",
  "block_number": "0x96b8a00",
  "code_present": true,
  "conclusion": "no_confirmed_erc165_behavior",
  "supported_interfaces": []
}
```

## Usage

```text
python erc165-interface-auditor.py --rpc-url RPC_URL --address CONTRACT [--block BLOCK_TAG] [--interface NAME=8_HEX_DIGITS]
```

The default matrix tests `erc165=01ffc9a7`, `invalid=ffffffff`, `erc721=80ac58cd`, `erc1155=d9b67a26`, and `erc2981=2a55205a`. Repeat `--interface` to replace that matrix with custom IDs.

## How it works

The tool reads bytecode presence and calls `supportsInterface(bytes4)` with ABI-correct left-aligned `bytes4` values. It classifies true, false, empty, malformed, and reverted responses separately. A contract is called valid ERC-165 only when it returns true for ERC-165 and false for 0xffffffff. The bundled Keccak-256 implementation derives its tables from the Keccak formulas rather than copying long constants.

## Tests

`python -m unittest -v`
