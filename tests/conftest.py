import pytest
import tempfile
import shutil
from pathlib import Path
from commit_reveal.core import CommitRevealScheme


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def scheme():
    """Basic commit-reveal scheme."""
    return CommitRevealScheme()


@pytest.fixture
def zkp_scheme():
    """Commit-reveal scheme with ZKP enabled."""
    return CommitRevealScheme(use_zkp=True)


@pytest.fixture
def sha512_scheme():
    """Commit-reveal scheme with SHA-512."""
    return CommitRevealScheme(hash_algorithm='sha512')


@pytest.fixture
def test_values():
    """Common test values for various data types."""
    return {
        'strings': [
            "simple",
            "",
            "with spaces",
            "with\nnewlines\tand\ttabs",
            "unicode: 🔐🚀💎",
            "very_long_" + "x" * 1000,
            "special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        ],
        'integers': [
            0, 1, -1, 42, 2**32, 2**64, 2**128
        ],
        'bytes': [
            b"",
            b"simple bytes",
            b"\x00\x01\x02\xff",
            bytes(range(256)),
            b"a" * 1000
        ]
    }


@pytest.fixture(autouse=True)
def isolate_filesystem():
    """Isolate each test to prevent interference."""
    # This fixture automatically runs for each test
    # It doesn't do much in this case, but can be extended
    pass


# Custom markers for test categorization
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security-focused"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance benchmarks"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )


# Test collection hooks
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Mark performance tests
        if "performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)

        # Mark slow tests
        if any(keyword in item.nodeid for keyword in ["performance", "large", "concurrent"]):
            item.add_marker(pytest.mark.slow)

        # Mark security tests
        if any(keyword in item.name.lower() for keyword in ["security", "timing", "collision"]):
            item.add_marker(pytest.mark.security)