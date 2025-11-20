# SPDX-License-Identifier: MIT

import helpers
import pytest

@helpers.filtered_test
def test_falcon_keypair_from_seed():
    """Test Falcon keypair generation from seed for determinism"""
    output = helpers.run_subprocess(
        [helpers.path_to_executable('sig_keypair_from_seed')],
    )
    # Check that the test passed (exit code 0 means success)
    # The run_subprocess will raise an exception if it fails
    assert "ALL TESTS PASSED" in output

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)