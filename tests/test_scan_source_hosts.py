"""Offline regression checks for the source-addition mirror boundary."""

import pathlib
import tempfile
import unittest
from unittest.mock import patch

from scan_source_hosts import LITERAL, added_lines, source_additions


class SourceAdditionTests(unittest.TestCase):
    def test_context_and_removed_literals_are_outside_the_scan(self):
        diff = '\n'.join([
            'diff --git a/src/example.rs b/src/example.rs',
            '--- a/src/example.rs',
            '+++ b/src/example.rs',
            '@@ -2,3 +2,3 @@',
            ' const OLD: &str = "https://old.invalid";',
            '-const REMOVED: &str = "https://removed.invalid";',
            '+const NEW: &str = "PUBLIC_URL_BASE";',
            ' // retained context',
        ])
        additions = list(added_lines(diff))
        self.assertEqual(additions, [('src/example.rs', 3, 'const NEW: &str = "PUBLIC_URL_BASE";')])
        self.assertFalse(any(LITERAL.search(line) for _, _, line in additions))

    def test_added_literals_are_found_with_destination_locations(self):
        diff = '\n'.join([
            'diff --git a/src/example.rs b/src/example.rs',
            '--- a/src/example.rs',
            '+++ b/src/example.rs',
            '@@ -0,0 +1,2 @@',
            '+// ' + '.'.join(['test', 'workers', 'dev']),
            '+// ' + '.'.join(['test', 'r2', 'dev']),
            '@@ -8 +10 @@',
            '-// removed',
            '+// ' + 'a' * 32,
        ])
        additions = list(added_lines(diff))
        self.assertEqual([number for _, number, _ in additions], [1, 2, 10])
        self.assertTrue(all(LITERAL.search(line) for _, _, line in additions))

    def test_untracked_source_is_included(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'src').mkdir()
            (root / 'src/new.rs').write_text('// https://new.invalid\n')
            with patch('scan_source_hosts.subprocess.check_output', side_effect=['', 'src/new.rs\0']):
                additions = list(source_additions(root, 'abcdef0'))
        self.assertEqual(len(additions), 1)
        self.assertEqual(additions[0][:2], ('src/new.rs', 1))
        self.assertIsNotNone(LITERAL.search(additions[0][2]))

    def test_account_shape_does_not_match_longer_public_identifiers(self):
        self.assertIsNotNone(LITERAL.search('account = "' + 'a' * 32 + '"'))
        self.assertIsNone(LITERAL.search('revision = "' + 'a' * 40 + '"'))
        self.assertIsNone(LITERAL.search('public_key = "02' + 'a' * 64 + '"'))


if __name__ == '__main__':
    unittest.main()
