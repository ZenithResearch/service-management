import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackageMetadataTests(unittest.TestCase):
    def test_production_runtime_dependencies_are_required(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]

        self.assertEqual(
            project["dependencies"],
            [
                "cryptography==50.0.1",
                "jsonschema==4.26.0",
                "vercel-queue==0.9.2",
            ],
        )
        self.assertNotIn("optional-dependencies", project)
        self.assertEqual((ROOT / "requirements.txt").read_text(), ".\n")


if __name__ == "__main__":
    unittest.main()
