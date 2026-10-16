"""injected violation"""
import pytest
from tests.conftest import SOCKETPAIR_OK

pytestmark = pytest.mark.skipif(not SOCKETPAIR_OK, reason="inject")


def test_dummy():
    assert True
