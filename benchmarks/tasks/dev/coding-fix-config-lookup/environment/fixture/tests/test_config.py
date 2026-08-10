from __future__ import annotations

import unittest

from config_lookup import resolve_config


class ResolveConfigTests(unittest.TestCase):
    def test_cli_wins(self) -> None:
        self.assertEqual(
            resolve_config(cli="cli", environment="env", config_file="file", default="default"),
            "cli",
        )

    def test_falls_back_in_order(self) -> None:
        self.assertEqual(
            resolve_config(cli=None, environment="env", config_file="file", default="default"),
            "env",
        )
        self.assertEqual(
            resolve_config(cli=None, environment=None, config_file="file", default="default"),
            "file",
        )

    def test_empty_string_is_explicit(self) -> None:
        self.assertEqual(
            resolve_config(cli="", environment="env", config_file="file", default="default"),
            "",
        )


if __name__ == "__main__":
    unittest.main()
