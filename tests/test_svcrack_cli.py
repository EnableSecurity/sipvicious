import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from sipvicious import svcrack


class SvcrackCliTests(unittest.TestCase):
    def test_non_numeric_password_range_reports_dictionary_hint(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(sys, 'argv', ['sipvicious_svcrack', '-u', '1000', '-r', 'secret', '127.0.0.1']):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    svcrack.main()

        self.assertEqual(exc.exception.code, 10)
        self.assertIn("Invalid password range 'secret'", stderr.getvalue())
        self.assertIn('Use -r for numeric passwords and ranges, or -d for dictionary input.', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
