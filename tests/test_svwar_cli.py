import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from sipvicious import svwar


class SvwarCliTests(unittest.TestCase):
    def test_non_numeric_extension_range_reports_dictionary_hint(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(sys, 'argv', ['sipvicious_svwar', '-e', 'sipcaller1', '127.0.0.1']):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    svwar.main()

        self.assertEqual(exc.exception.code, 10)
        self.assertIn("Invalid extension range 'sipcaller1'", stderr.getvalue())
        self.assertIn('Use -e for numeric extensions and ranges, or -d for non-numeric/alphanumeric extension names.', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
