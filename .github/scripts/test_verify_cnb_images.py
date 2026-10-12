import base64
import importlib.util
import io
import json
import pathlib
import unittest
import urllib.error
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location(
    "verify_cnb_images", pathlib.Path(__file__).with_name("verify-cnb-images.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NAME = "example/jeepay/jeepay-manager"
DIGEST = "sha256:" + "a" * 64
CONFIG = "sha256:" + "b" * 64
CHILD = "sha256:" + "c" * 64


class Response(io.BytesIO):
    def __init__(self, data, headers=None):
        super().__init__(json.dumps(data).encode())
        self.headers = headers or {}


class RegistryServer:
    """拒绝向 manifest 直接发送 Basic，要求按镜像 scope 交换 token。"""
    def __init__(self, private=False, os="linux", arch="amd64", realm=module.TOKEN_URL):
        self.calls = []
        self.private, self.os, self.arch, self.realm = private, os, arch, realm

    def __call__(self, request, timeout):
        self.calls.append(request)
        url = urllib.parse.urlsplit(request.full_url)
        authorization = request.get_header("Authorization")
        if url.path == "/service/token":
            query = urllib.parse.parse_qs(url.query)
            assert query == {"service": ["cnb-registry"], "scope": ["repository:" + NAME + ":pull"]}
            if authorization:
                expected = "Basic " + base64.b64encode(b"cnb:test-credential").decode()
                assert authorization == expected
                return Response({"access_token": "private-pull-token"})
            return Response({"token": "anonymous-pull-token"})
        expected = "Bearer " + ("private-pull-token" if self.private else "anonymous-pull-token")
        if authorization != expected:
            challenge = (f'Bearer realm="{self.realm}",service="cnb-registry",'
                         f'scope="repository:{NAME}:pull"')
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized",
                                         {"WWW-Authenticate": challenge}, None)
        if url.path.endswith("/manifests/v3.2.2"):
            return Response({"manifests": [
                {"digest": "attestation", "platform": {"os": "unknown", "architecture": "unknown"}},
                {"digest": CHILD, "platform": {"os": "linux", "architecture": self.arch}},
            ]}, {"Docker-Content-Digest": DIGEST})
        if url.path.endswith("/manifests/" + CHILD):
            return Response({"config": {"digest": CONFIG}})
        if url.path.endswith("/blobs/" + CONFIG):
            return Response({"os": self.os, "architecture": self.arch})
        raise AssertionError("非预期的 registry 请求")


class RegistryTests(unittest.TestCase):
    def test_anonymous_bearer_exchange_and_config(self):
        server = RegistryServer()
        result = module.verify_image(module.Registry("test-credential", server), NAME, "v3.2.2")
        self.assertEqual(result, (DIGEST, CONFIG))
        self.assertEqual(len(server.calls), 5)
        self.assertIsNone(server.calls[0].get_header("Authorization"))
        self.assertIsNone(server.calls[1].get_header("Authorization"))
        self.assertTrue(all(r.get_header("Authorization").startswith("Bearer ")
                            for r in server.calls[2:]))

    def test_private_pull_authenticates_only_to_token_service(self):
        server = RegistryServer(private=True)
        module.verify_image(module.Registry("test-credential", server), NAME, "v3.2.2")
        basic = [r for r in server.calls if (r.get_header("Authorization") or "").startswith("Basic ")]
        self.assertEqual(len(basic), 1)
        self.assertEqual(urllib.parse.urlsplit(basic[0].full_url).path, "/service/token")

    def test_different_token_realm_is_rejected_without_sending_credential(self):
        server = RegistryServer(realm="https://example.invalid/token")
        with self.assertRaisesRegex(ValueError, "非预期"):
            module.verify_image(module.Registry("test-credential", server), NAME, "v3.2.2")
        self.assertEqual(len(server.calls), 1)

    def test_wrong_architecture_fails(self):
        with self.assertRaisesRegex(ValueError, "没有 linux/amd64"):
            module.verify_image(module.Registry(open_url=RegistryServer(arch="arm64")), NAME, "v3.2.2")

    def test_index_linux_label_does_not_hide_windows_config(self):
        with self.assertRaisesRegex(ValueError, "config 不是 linux/amd64"):
            module.verify_image(module.Registry(open_url=RegistryServer(os="windows")), NAME, "v3.2.2")

    def test_private_image_without_credential_remains_failure(self):
        with self.assertRaises(urllib.error.HTTPError):
            module.verify_image(module.Registry(open_url=RegistryServer(private=True)), NAME, "v3.2.2")

    def test_cross_host_redirect_drops_authorization(self):
        request = urllib.request.Request(module.REGISTRY + "/v2/blob",
                                         headers={"Authorization": "Bearer test-token"})
        redirected = module.SafeRedirect().redirect_request(request, None, 302, "", {},
                                                           "https://example.invalid/blob")
        self.assertIsNone(redirected.get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
