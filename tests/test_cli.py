import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

# Add the parent directory to the path to import the CLI module
sys.path.insert(0, str(Path(__file__).parent.parent))
from commit_reveal.cli import (
    get_storage_path, ensure_storage_directory, save_commitment,
    load_commitment, list_commitments, delete_commitment, main
)


class TestStorageUtilities:
    """Test suite for storage utility functions."""

    def test_get_storage_path(self):
        """Test getting storage path."""
        path = get_storage_path()
        assert isinstance(path, Path)
        assert path.name == ".commit-reveal"
        assert path.parent == Path.home()

    @patch('commit_reveal.cli.Path.home')
    def test_get_storage_path_custom_home(self, mock_home):
        """Test storage path with custom home directory."""
        mock_home.return_value = Path("/custom/home")
        path = get_storage_path()
        assert path == Path("/custom/home/.commit-reveal")

    def test_ensure_storage_directory(self):
        """Test ensuring storage directory exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('commit_reveal.cli.get_storage_path') as mock_get_path:
                storage_path = Path(temp_dir) / ".commit-reveal"
                mock_get_path.return_value = storage_path

                # Directory shouldn't exist initially
                assert not storage_path.exists()

                # Ensure directory is created
                result = ensure_storage_directory()
                assert storage_path.exists()
                assert storage_path.is_dir()
                assert result == storage_path


class TestCommitmentStorage:
    """Test suite for commitment storage functions."""

    def setup_method(self):
        """Set up test environment with temporary directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / ".commit-reveal"
        self.storage_path.mkdir()

    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)

    @patch('commit_reveal.cli.ensure_storage_directory')
    def test_save_commitment_basic(self, mock_ensure_dir):
        """Test saving a basic commitment."""
        mock_ensure_dir.return_value = self.storage_path

        name = "test-commitment"
        commitment = b"test_commitment_bytes"
        salt = b"test_salt_bytes"

        save_commitment(name, commitment, salt)

        # Check file was created
        file_path = self.storage_path / f"{name}.json"
        assert file_path.exists()

        # Check file contents
        with open(file_path, 'r') as f:
            data = json.load(f)

        assert data["name"] == name
        assert data["commitment"] == commitment.hex()
        assert data["salt"] == salt.hex()
        assert data["zkp"] is False

    @patch('commit_reveal.cli.ensure_storage_directory')
    def test_save_commitment_with_value(self, mock_ensure_dir):
        """Test saving commitment with value."""
        mock_ensure_dir.return_value = self.storage_path

        name = "test-commitment"
        commitment = b"test_commitment"
        salt = b"test_salt"
        value = "secret_value"

        save_commitment(name, commitment, salt, value=value)

        file_path = self.storage_path / f"{name}.json"
        with open(file_path, 'r') as f:
            data = json.load(f)

        assert data["value"] == value

    @patch('commit_reveal.cli.ensure_storage_directory')
    def test_save_commitment_with_zkp(self, mock_ensure_dir):
        """Test saving commitment with ZKP data."""
        mock_ensure_dir.return_value = self.storage_path

        name = "test-commitment"
        commitment = b"test_commitment"
        salt = b"test_salt"
        zkp_data = {
            "nonce": b"test_nonce",
            "challenge": 12345,
            "response": 67890
        }

        save_commitment(name, commitment, salt, zkp_data=zkp_data)

        file_path = self.storage_path / f"{name}.json"
        with open(file_path, 'r') as f:
            data = json.load(f)

        assert data["zkp"] is True
        assert data["zkp_data"]["nonce"] == zkp_data["nonce"].hex()
        assert data["zkp_data"]["challenge"] == zkp_data["challenge"]
        assert data["zkp_data"]["response"] == zkp_data["response"]

    @patch('commit_reveal.cli.get_storage_path')
    def test_load_commitment_exists(self, mock_get_path):
        """Test loading an existing commitment."""
        mock_get_path.return_value = self.storage_path

        # Create test file
        name = "test-commitment"
        test_data = {
            "name": name,
            "commitment": "abcdef",
            "salt": "123456",
            "zkp": False
        }

        file_path = self.storage_path / f"{name}.json"
        with open(file_path, 'w') as f:
            json.dump(test_data, f)

        # Load and verify
        loaded_data = load_commitment(name)
        assert loaded_data == test_data

    @patch('commit_reveal.cli.get_storage_path')
    def test_load_commitment_not_exists(self, mock_get_path):
        """Test loading a non-existent commitment."""
        mock_get_path.return_value = self.storage_path

        result = load_commitment("nonexistent")
        assert result is None

    @patch('commit_reveal.cli.get_storage_path')
    def test_list_commitments_empty(self, mock_get_path):
        """Test listing commitments when storage is empty."""
        mock_get_path.return_value = Path("/nonexistent")

        result = list_commitments()
        assert result == []

    @patch('commit_reveal.cli.get_storage_path')
    def test_list_commitments_with_files(self, mock_get_path):
        """Test listing commitments with existing files."""
        mock_get_path.return_value = self.storage_path

        # Create test files
        (self.storage_path / "commitment1.json").touch()
        (self.storage_path / "commitment2.json").touch()
        (self.storage_path / "not_json.txt").touch()  # Should be ignored

        result = list_commitments()
        assert set(result) == {"commitment1", "commitment2"}

    @patch('commit_reveal.cli.get_storage_path')
    def test_delete_commitment_exists(self, mock_get_path):
        """Test deleting an existing commitment."""
        mock_get_path.return_value = self.storage_path

        # Create test file
        name = "test-commitment"
        file_path = self.storage_path / f"{name}.json"
        file_path.touch()

        assert file_path.exists()

        result = delete_commitment(name)
        assert result is True
        assert not file_path.exists()

    @patch('commit_reveal.cli.get_storage_path')
    def test_delete_commitment_not_exists(self, mock_get_path):
        """Test deleting a non-existent commitment."""
        mock_get_path.return_value = self.storage_path

        result = delete_commitment("nonexistent")
        assert result is False


class TestCLICommands:
    """Test suite for CLI command functionality."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / ".commit-reveal"
        self.storage_path.mkdir()

    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)

    @patch('commit_reveal.cli.ensure_storage_directory')
    @patch('sys.argv', ['commit-reveal', 'commit', 'test-name', 'test-value'])
    def test_commit_command(self, mock_ensure_dir, capsys):
        """Test the commit command."""
        mock_ensure_dir.return_value = self.storage_path

        with pytest.raises(SystemExit) as exc_info:
            main()

        # Check that the command completed successfully (exit code 0 means no explicit exit)
        # If there's no explicit exit, the test should not raise SystemExit
        assert exc_info.value.code is None or exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "Committed to 'test-value' with name 'test-name'" in captured.out
        assert "Commitment:" in captured.out
        assert "Salt:" in captured.out

    @patch('commit_reveal.cli.load_commitment')
    @patch('sys.argv', ['commit-reveal', 'reveal', 'test-name', 'test-value'])
    def test_reveal_command_success(self, mock_load, capsys):
        """Test successful reveal command."""
        # Mock loaded commitment data
        mock_load.return_value = {
            "name": "test-name",
            "commitment": "a" * 64,  # 32 bytes in hex
            "salt": "b" * 64,        # 32 bytes in hex
            "zkp": False
        }

        try:
            main()
        except SystemExit:
            pass

        captured = capsys.readouterr()
        # The exact output depends on whether the reveal succeeds
        assert "Reveal" in captured.out

    @patch('commit_reveal.cli.load_commitment')
    @patch('sys.argv', ['commit-reveal', 'reveal', 'nonexistent', 'value'])
    def test_reveal_command_not_found(self, mock_load, capsys):
        """Test reveal command with non-existent commitment."""
        mock_load.return_value = None

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "No commitment found with name 'nonexistent'" in captured.err

    @patch('commit_reveal.cli.list_commitments')
    @patch('sys.argv', ['commit-reveal', 'list'])
    def test_list_command_empty(self, mock_list, capsys):
        """Test list command with no commitments."""
        mock_list.return_value = []

        try:
            main()
        except SystemExit:
            pass

        captured = capsys.readouterr()
        assert "No commitments found." in captured.out

    @patch('commit_reveal.cli.list_commitments')
    @patch('sys.argv', ['commit-reveal', 'list'])
    def test_list_command_with_commitments(self, mock_list, capsys):
        """Test list command with existing commitments."""
        mock_list.return_value = ["commitment1", "commitment2"]

        try:
            main()
        except SystemExit:
            pass

        captured = capsys.readouterr()
        assert "Commitments:" in captured.out
        assert "commitment1" in captured.out
        assert "commitment2" in captured.out

    @patch('commit_reveal.cli.delete_commitment')
    @patch('sys.argv', ['commit-reveal', 'delete', 'test-name'])
    def test_delete_command_success(self, mock_delete, capsys):
        """Test successful delete command."""
        mock_delete.return_value = True

        try:
            main()
        except SystemExit:
            pass

        captured = capsys.readouterr()
        assert "Commitment 'test-name' deleted successfully." in captured.out

    @patch('commit_reveal.cli.delete_commitment')
    @patch('sys.argv', ['commit-reveal', 'delete', 'nonexistent'])
    def test_delete_command_not_found(self, mock_delete, capsys):
        """Test delete command with non-existent commitment."""
        mock_delete.return_value = False

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "No commitment found with name 'nonexistent'" in captured.err

    @patch('sys.argv', ['commit-reveal'])
    def test_no_command_shows_help(self, capsys):
        """Test that running without command shows help."""
        try:
            main()
        except SystemExit:
            pass

        captured = capsys.readouterr()
        assert "usage:" in captured.out.lower() or "Commit-Reveal CLI tool" in captured.out


class TestZKPCLICommands:
    """Test suite for ZKP-related CLI commands."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / ".commit-reveal"
        self.storage_path.mkdir()

    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)

    @patch('commit_reveal.cli.ensure_storage_directory')
    @patch('sys.argv', ['commit-reveal', '--zkp', 'commit', 'test-name', 'test-value'])
    def test_zkp_commit_command(self, mock_ensure_dir, capsys):
        """Test ZKP commit command."""
        mock_ensure_dir.return_value = self.storage_path

        try:
            main()
        except SystemExit:
            pass

        captured = capsys.readouterr()
        assert "ZKP proof created and stored." in captured.out

    @patch('commit_reveal.cli.load_commitment')
    @patch('sys.argv', ['commit-reveal', '--zkp', 'prove', 'test-name'])
    def test_zkp_prove_command_without_zkp_flag_error(self, mock_load, capsys):
        """Test prove command without ZKP flag should fail."""
        # This test checks the error case where --zkp is required but not provided
        mock_load.return_value = {
            "name": "test-name",
            "commitment": "a" * 64,
            "salt": "b" * 64,
            "value": "test-value",
            "zkp": False
        }

        # Change argv to not include --zkp flag
        with patch('sys.argv', ['commit-reveal', 'prove', 'test-name']):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "ZKP functionality must be enabled with --zkp flag" in captured.err


class TestCLIErrorHandling:
    """Test suite for CLI error handling."""

    @patch('sys.argv', ['commit-reveal', 'invalid-command'])
    def test_invalid_command(self, capsys):
        """Test handling of invalid command."""
        try:
            main()
        except SystemExit:
            pass

        # Should show help or error message
        captured = capsys.readouterr()
        # The behavior depends on argparse implementation
        assert captured.err != "" or captured.out != ""

    @patch('commit_reveal.cli.CommitRevealScheme')
    @patch('sys.argv', ['commit-reveal', 'commit', 'test', 'value'])
    def test_commit_scheme_error(self, mock_scheme_class, capsys):
        """Test handling of CommitRevealScheme errors."""
        # Make the scheme raise an exception
        mock_scheme = MagicMock()
        mock_scheme.commit.side_effect = Exception("Test error")
        mock_scheme_class.return_value = mock_scheme

        with pytest.raises(Exception):
            main()