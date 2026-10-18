import importlib.util
import json
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("erc165-interface-auditor.py")
SPEC = importlib.util.spec_from_file_location("interface_auditor", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


AZUKI = "0xed5af388653567af2f388e6224dc7c4b3241c544"
OP_WETH = "0x4200000000000000000000000000000000000006"


def response_key(method, params):
    return (method, json.dumps(params, sort_keys=True))


class FakeRpc:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
        key = (method, json.dumps(params, sort_keys=True))
        if key not in self.responses:
            raise AssertionError(f"unexpected RPC request: {method} {params}")
        response = self.responses[key]
        if isinstance(response, Exception):
            return {"error": {"message": response.message, "data": response.data}}
        return {"result": response}


class InterfaceAuditorTests(unittest.TestCase):
    def test_keccak_empty_and_supports_interface_selector(self):
        self.assertEqual(
            MODULE.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(MODULE.function_selector("supportsInterface(bytes4)"), "01ffc9a7")

    def test_bytes4_is_left_aligned(self):
        self.assertEqual(
            MODULE.encode_supports_interface("80ac58cd"),
            "0x01ffc9a780ac58cd00000000000000000000000000000000000000000000000000000000",
        )

    def test_fixed_ethereum_azuki_matrix(self):
        ids = {
            "erc165": "01ffc9a7",
            "invalid": "ffffffff",
            "erc721": "80ac58cd",
            "erc1155": "d9b67a26",
            "erc2981": "2a55205a",
        }
        responses = {
            response_key("eth_chainId", []): "0x1",
            response_key("eth_blockNumber", []): "0x18f4300",
            response_key("eth_getCode", [AZUKI, "latest"]): "0x60006000",
        }
        for name, interface_id in ids.items():
            data = MODULE.encode_supports_interface(interface_id)
            value = "0x" + "0" * 63 + ("1" if name in ("erc165", "erc721") else "0")
            responses[response_key("eth_call", [{"to": AZUKI, "data": data}, "latest"])] = value
        report = MODULE.audit_interfaces(
            MODULE.JsonRpcClient("mock:", transport=FakeRpc(responses)), AZUKI
        )
        self.assertTrue(report["code_present"])
        self.assertEqual(report["conclusion"], "valid_erc165_behavior")
        self.assertEqual(report["supported_interfaces"], ["erc165", "erc721"])
        self.assertEqual(report["interfaces"]["erc2981"]["status"], "not_supported")

    def test_fixed_optimism_weth_empty_return_is_not_false(self):
        ids = ["01ffc9a7", "ffffffff", "80ac58cd", "d9b67a26", "2a55205a"]
        responses = {
            response_key("eth_chainId", []): "0xa",
            response_key("eth_blockNumber", []): "0x96b8884",
            response_key("eth_getCode", [OP_WETH, "latest"]): "0x60006000",
        }
        for interface_id in ids:
            data = MODULE.encode_supports_interface(interface_id)
            responses[response_key("eth_call", [{"to": OP_WETH, "data": data}, "latest"])] = "0x"
        report = MODULE.audit_interfaces(
            MODULE.JsonRpcClient("mock:", transport=FakeRpc(responses)), OP_WETH
        )
        self.assertTrue(report["code_present"])
        self.assertEqual(report["conclusion"], "no_confirmed_erc165_behavior")
        self.assertEqual(report["interfaces"]["erc165"]["status"], "empty_return")
        self.assertEqual(report["supported_interfaces"], [])

    def test_reverted_call_is_reported(self):
        responses = {
            response_key("eth_chainId", []): "0x1",
            response_key("eth_blockNumber", []): "0x10",
            response_key("eth_getCode", [AZUKI, "latest"]): "0x6000",
            response_key(
                "eth_call", [{"to": AZUKI, "data": MODULE.encode_supports_interface("01ffc9a7")}, "latest"]
            ): MODULE.RpcError("execution reverted", {"data": "0x08c379a0"}),
            response_key(
                "eth_call", [{"to": AZUKI, "data": MODULE.encode_supports_interface("ffffffff")}, "latest"]
            ): "0x" + "0" * 63 + "0",
            response_key(
                "eth_call", [{"to": AZUKI, "data": MODULE.encode_supports_interface("80ac58cd")}, "latest"]
            ): "0x" + "0" * 63 + "0",
            response_key(
                "eth_call", [{"to": AZUKI, "data": MODULE.encode_supports_interface("d9b67a26")}, "latest"]
            ): "0x" + "0" * 63 + "0",
            response_key(
                "eth_call", [{"to": AZUKI, "data": MODULE.encode_supports_interface("2a55205a")}, "latest"]
            ): "0x" + "0" * 63 + "0",
        }
        report = MODULE.audit_interfaces(
            MODULE.JsonRpcClient("mock:", transport=FakeRpc(responses)), AZUKI
        )
        self.assertEqual(report["interfaces"]["erc165"]["status"], "reverted")
        self.assertEqual(report["conclusion"], "no_confirmed_erc165_behavior")

    def test_custom_interface_matrix_is_validated(self):
        selected = MODULE._parse_interfaces(["custom=12345678"])
        self.assertEqual(selected, [("custom", "12345678")])
        with self.assertRaises(ValueError):
            MODULE._parse_interfaces(["bad=1234"])
        with self.assertRaises(ValueError):
            MODULE._parse_interfaces(["x=12345678", "x=abcdef12"])


if __name__ == "__main__":
    unittest.main()
