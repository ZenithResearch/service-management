import importlib.util
import json
from pathlib import Path
import unittest

from vercel.headers import get_headers


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("service_management_vercel_entrypoint",
                                              ROOT / "api" / "provider.py")
ENTRYPOINT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ENTRYPOINT)


class VercelEntrypointTests(unittest.TestCase):
    def test_every_public_write_route_reaches_the_bounded_handler(self):
        rewrites = json.loads((ROOT / "vercel.json").read_text())["rewrites"]
        self.assertEqual(rewrites, [
            {"source": "/v1/provider",
             "destination": "/api/provider?route=catalog"},
            {"source": "/v1/request-credential",
             "destination": "/api/provider?route=credential"},
            {"source": "/v1/client/requests",
             "destination": "/api/provider?route=intake"},
            {"source": "/v1/client/reference-objects",
             "destination": "/api/provider?route=reference"},
        ])
        self.assertEqual(ENTRYPOINT._route_path("/api/provider?route=catalog"),
                         "/v1/provider")
        self.assertEqual(ENTRYPOINT._route_path("/api/provider?route=credential"),
                         "/v1/request-credential")
        self.assertEqual(ENTRYPOINT._route_path("/api/provider?route=intake"),
                         "/v1/client/requests")
        self.assertEqual(ENTRYPOINT._route_path("/api/provider?route=reference"),
                         "/v1/client/reference-objects")

    def test_unknown_or_ambiguous_route_fails_closed(self):
        for path in ("/api/provider", "/api/provider?route=status",
                     "/api/provider?route=intake&route=reference"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                ENTRYPOINT._route_path(path)

    def test_queue_publish_uses_only_one_platform_oidc_request_header(self):
        token = "header.payload.signature"
        self.assertIsNone(get_headers())
        with ENTRYPOINT._queue_oidc_context((("X-Vercel-Oidc-Token", token),
                                             ("Origin", "https://anima.example"))):
            self.assertEqual(get_headers(), {"x-vercel-oidc-token": token})
        self.assertIsNone(get_headers())
        for headers in ((),
                        (("X-Vercel-Oidc-Token", token),
                         ("x-vercel-oidc-token", token)),
                        (("X-Vercel-Oidc-Token", "not-a-jwt"),)):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                ENTRYPOINT._queue_oidc_context(headers)


if __name__ == "__main__":
    unittest.main()
