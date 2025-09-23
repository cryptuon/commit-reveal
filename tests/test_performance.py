import pytest
import time
import statistics
from commit_reveal.core import CommitRevealScheme


class TestPerformanceBenchmarks:
    """Performance benchmarks for the commit-reveal scheme."""

    @pytest.fixture
    def scheme(self):
        return CommitRevealScheme()

    @pytest.fixture
    def zkp_scheme(self):
        return CommitRevealScheme(use_zkp=True)

    def test_commit_performance_strings(self, scheme):
        """Benchmark commit performance with string values."""
        values = [f"test_string_{i}" for i in range(1000)]
        times = []

        for value in values:
            start_time = time.perf_counter()
            scheme.commit(value)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        avg_time = statistics.mean(times)
        max_time = max(times)

        # Performance assertions (adjust thresholds based on requirements)
        assert avg_time < 0.001, f"Average commit time too slow: {avg_time:.6f}s"
        assert max_time < 0.01, f"Maximum commit time too slow: {max_time:.6f}s"

        print(f"String commit - Avg: {avg_time:.6f}s, Max: {max_time:.6f}s, Min: {min(times):.6f}s")

    def test_commit_performance_integers(self, scheme):
        """Benchmark commit performance with integer values."""
        values = list(range(1000, 2000))
        times = []

        for value in values:
            start_time = time.perf_counter()
            scheme.commit(value)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        avg_time = statistics.mean(times)
        max_time = max(times)

        assert avg_time < 0.001, f"Average commit time too slow: {avg_time:.6f}s"
        assert max_time < 0.01, f"Maximum commit time too slow: {max_time:.6f}s"

        print(f"Integer commit - Avg: {avg_time:.6f}s, Max: {max_time:.6f}s, Min: {min(times):.6f}s")

    def test_reveal_performance(self, scheme):
        """Benchmark reveal performance."""
        # Pre-generate commitments
        commitments = []
        for i in range(1000):
            value = f"test_{i}"
            commitment, salt = scheme.commit(value)
            commitments.append((value, salt, commitment))

        times = []
        for value, salt, commitment in commitments:
            start_time = time.perf_counter()
            scheme.reveal(value, salt, commitment)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        avg_time = statistics.mean(times)
        max_time = max(times)

        assert avg_time < 0.001, f"Average reveal time too slow: {avg_time:.6f}s"
        assert max_time < 0.01, f"Maximum reveal time too slow: {max_time:.6f}s"

        print(f"Reveal - Avg: {avg_time:.6f}s, Max: {max_time:.6f}s, Min: {min(times):.6f}s")

    def test_zkp_proof_performance(self, zkp_scheme):
        """Benchmark ZKP proof creation performance."""
        # Pre-generate commitments
        commitments = []
        for i in range(100):  # Fewer iterations for ZKP as it's more expensive
            value = f"test_{i}"
            commitment, salt = zkp_scheme.commit(value)
            commitments.append((value, salt, commitment))

        times = []
        for value, salt, commitment in commitments:
            start_time = time.perf_counter()
            zkp_scheme.create_zkp_proof(value, salt, commitment)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        avg_time = statistics.mean(times)
        max_time = max(times)

        # ZKP operations are expected to be slower
        assert avg_time < 0.01, f"Average ZKP proof time too slow: {avg_time:.6f}s"
        assert max_time < 0.1, f"Maximum ZKP proof time too slow: {max_time:.6f}s"

        print(f"ZKP Proof - Avg: {avg_time:.6f}s, Max: {max_time:.6f}s, Min: {min(times):.6f}s")

    def test_zkp_verification_performance(self, zkp_scheme):
        """Benchmark ZKP verification performance."""
        # Pre-generate proofs
        proofs = []
        for i in range(100):
            value = f"test_{i}"
            commitment, salt = zkp_scheme.commit(value)
            nonce, challenge, response = zkp_scheme.create_zkp_proof(value, salt, commitment)
            proofs.append((commitment, nonce, challenge, response))

        times = []
        for commitment, nonce, challenge, response in proofs:
            start_time = time.perf_counter()
            zkp_scheme.verify_zkp_proof(commitment, nonce, challenge, response)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        avg_time = statistics.mean(times)
        max_time = max(times)

        assert avg_time < 0.01, f"Average ZKP verification time too slow: {avg_time:.6f}s"
        assert max_time < 0.1, f"Maximum ZKP verification time too slow: {max_time:.6f}s"

        print(f"ZKP Verification - Avg: {avg_time:.6f}s, Max: {max_time:.6f}s, Min: {min(times):.6f}s")

    def test_large_value_performance(self, scheme):
        """Benchmark performance with large values."""
        # Test with increasingly large values
        sizes = [1024, 10240, 102400, 1024000]  # 1KB, 10KB, 100KB, 1MB

        for size in sizes:
            value = "x" * size

            start_time = time.perf_counter()
            commitment, salt = scheme.commit(value)
            commit_time = time.perf_counter() - start_time

            start_time = time.perf_counter()
            scheme.reveal(value, salt, commitment)
            reveal_time = time.perf_counter() - start_time

            # Performance should scale reasonably with input size
            assert commit_time < 0.1, f"Commit time for {size} bytes too slow: {commit_time:.6f}s"
            assert reveal_time < 0.1, f"Reveal time for {size} bytes too slow: {reveal_time:.6f}s"

            print(f"Size {size} bytes - Commit: {commit_time:.6f}s, Reveal: {reveal_time:.6f}s")

    def test_memory_usage_estimation(self, scheme):
        """Test memory usage estimation for commitments."""
        import sys

        # Measure memory usage for a single commitment
        value = "test_value"
        commitment, salt = scheme.commit(value)

        # Basic size checks
        commitment_size = sys.getsizeof(commitment)
        salt_size = sys.getsizeof(salt)

        # SHA-256 output should be 32 bytes
        assert len(commitment) == 32
        assert len(salt) == 32

        # Including Python object overhead, should still be reasonable
        assert commitment_size < 100, f"Commitment object too large: {commitment_size} bytes"
        assert salt_size < 100, f"Salt object too large: {salt_size} bytes"

        print(f"Memory usage - Commitment: {commitment_size} bytes, Salt: {salt_size} bytes")

    def test_concurrent_operations_simulation(self, scheme):
        """Simulate concurrent operations (single-threaded test)."""
        import threading
        import queue

        results = queue.Queue()
        errors = queue.Queue()

        def worker(worker_id, num_operations):
            try:
                for i in range(num_operations):
                    value = f"worker_{worker_id}_value_{i}"
                    commitment, salt = scheme.commit(value)
                    is_valid = scheme.reveal(value, salt, commitment)
                    if not is_valid:
                        errors.put(f"Worker {worker_id}: Invalid reveal for operation {i}")
                results.put(f"Worker {worker_id} completed {num_operations} operations")
            except Exception as e:
                errors.put(f"Worker {worker_id} error: {e}")

        # Simulate 5 concurrent workers with 100 operations each
        threads = []
        start_time = time.perf_counter()

        for worker_id in range(5):
            thread = threading.Thread(target=worker, args=(worker_id, 100))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.perf_counter()
        total_time = end_time - start_time

        # Check results
        assert errors.empty(), f"Errors occurred: {list(errors.queue)}"
        assert results.qsize() == 5, f"Expected 5 workers to complete, got {results.qsize()}"

        # 500 total operations should complete in reasonable time
        assert total_time < 5.0, f"Concurrent operations too slow: {total_time:.2f}s"

        print(f"Concurrent operations (5 workers, 100 ops each): {total_time:.2f}s")


class TestMemoryAndResourceUsage:
    """Test memory usage and resource consumption."""

    @pytest.fixture
    def scheme(self):
        return CommitRevealScheme()

    def test_no_memory_leaks_simple(self, scheme):
        """Simple test for obvious memory leaks."""
        import gc
        import sys

        # Force garbage collection
        gc.collect()
        initial_objects = len(gc.get_objects())

        # Perform many operations
        for i in range(1000):
            value = f"test_{i}"
            commitment, salt = scheme.commit(value)
            scheme.reveal(value, salt, commitment)

        # Force garbage collection again
        gc.collect()
        final_objects = len(gc.get_objects())

        # Allow for some growth, but not excessive
        object_growth = final_objects - initial_objects
        assert object_growth < 100, f"Possible memory leak: {object_growth} objects created"

        print(f"Object count change: {object_growth}")

    def test_resource_cleanup(self, scheme):
        """Test that resources are properly cleaned up."""
        # This is mainly relevant for ensuring no file handles or other resources leak
        # For this library, it's mostly about the hash function objects

        initial_scheme_state = scheme.__dict__.copy()

        # Perform operations
        for i in range(100):
            value = f"test_{i}"
            commitment, salt = scheme.commit(value)
            scheme.reveal(value, salt, commitment)

        final_scheme_state = scheme.__dict__.copy()

        # Scheme state should not have grown significantly
        assert initial_scheme_state.keys() == final_scheme_state.keys()

        # Hash function should still be the same object
        assert initial_scheme_state['_hash_func'] is final_scheme_state['_hash_func']


if __name__ == "__main__":
    # Allow running performance tests standalone
    pytest.main([__file__, "-v", "-s"])