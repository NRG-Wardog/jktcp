"""Source-owned Python checks only; does not compile or execute Rust/native code."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
module_spec = importlib.util.spec_from_file_location("source_parity", ROOT / ".ci/source-parity.py")
parity = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(parity)


def oid(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class SourceParityTests(unittest.TestCase):
    def setUp(self):
        self.old, self.prior, self.new, self.meta = b"upstream\n", b"previous\n", b"reviewed\n", b"metadata\n"
        self.blobs = {oid(data): data for data in (self.old, self.prior, self.new, self.meta)}
        self.actual = {"src.rs": ("100644", "blob", oid(self.new)),
                       ".ci/contract.json": ("100644", "blob", oid(self.meta))}
        self.original = {"src.rs": ("100644", "blob", oid(self.old))}
        self.previous = {"src.rs": ("100644", "blob", oid(self.prior))}
        self.spec = {"metadata_files": [".ci/contract.json"], "files": [{
            "path": "src.rs", "git_mode": "100644", "new_source_blob": oid(self.new),
            "new_source_sha256": parity.digest(self.new), "upstream_git_mode": "100644",
            "upstream_blob": oid(self.old), "upstream_sha256": parity.digest(self.old),
            "previous_owner_git_mode": "100644", "previous_owner_blob": oid(self.prior),
            "previous_owner_sha256": parity.digest(self.prior),
        }]}

    def verify(self):
        return parity.verify_committed(self.spec, self.actual, self.original, self.previous, self.blobs.__getitem__)

    def test_exact_reviewed_inventory_passes(self):
        self.assertEqual(self.verify(), 1)

    def test_changed_source_blob_rejected(self):
        self.actual["src.rs"] = ("100644", "blob", oid(self.prior))
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_source_digest_rejected(self):
        self.spec["files"][0]["new_source_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_upstream_rejected(self):
        self.original["src.rs"] = ("100644", "blob", oid(self.prior))
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_previous_owner_rejected(self):
        self.previous["src.rs"] = ("100644", "blob", oid(self.old))
        with self.assertRaises(ValueError):
            self.verify()

    def test_extra_product_rejected(self):
        self.actual["surprise.rs"] = self.actual["src.rs"]
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_mode_rejected(self):
        self.actual["src.rs"] = ("100755", "blob", oid(self.new))
        with self.assertRaises(ValueError):
            self.verify()

    def test_duplicate_product_rejected(self):
        self.spec["files"].append(copy.deepcopy(self.spec["files"][0]))
        with self.assertRaises(ValueError):
            self.verify()

    def test_metadata_symlink_rejected(self):
        self.actual[".ci/contract.json"] = ("120000", "blob", oid(self.meta))
        with self.assertRaises(ValueError):
            self.verify()

    def test_traversal_rejected(self):
        self.spec["metadata_files"] = ["../outside"]
        with self.assertRaises(ValueError):
            parity.entries(self.spec)

    def test_worktree_and_metadata_bytes_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ci").mkdir()
            (root / "src.rs").write_bytes(self.new)
            (root / ".ci/contract.json").write_bytes(self.meta)
            parity.verify_worktree(root, self.actual, self.blobs.__getitem__)
            (root / ".ci/contract.json").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                parity.verify_worktree(root, self.actual, self.blobs.__getitem__)

    def test_untracked_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".ci").mkdir()
            (root / "src.rs").write_bytes(self.new)
            (root / ".ci/contract.json").write_bytes(self.meta)
            (root / "extra").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                parity.verify_worktree(root, self.actual, self.blobs.__getitem__)


class TransportSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = (ROOT / "src/adapter.rs").read_text().split("#[cfg(test)]", 1)[0]
        cls.handle = (ROOT / "src/handle.rs").read_text()

    def test_transport_packets_have_one_write_owner(self):
        self.assertNotIn("self.peer.write_all", self.adapter)
        self.assertEqual(self.adapter.count("self.peer.write("), 1)
        pending = self.adapter.split("fn has_pending_work", 1)[1].split("pub(crate) async fn", 1)[0]
        self.assertIn("!self.outbox.is_empty()", pending)
        self.assertIn("self.outbox_needs_flush", pending)
        self.assertIn("ConnectionStatus::Error(_) => false", pending)

    def test_application_dequeue_precedes_cancellable_send(self):
        psh = self.adapter.split("async fn psh(", 1)[1].split("async fn read_ip_packet", 1)[0]
        first_await = psh.index(".await")
        for operation in ("state.write_buffer.drain(..len)", "state.unacked.push_back", "state.seq ="):
            self.assertLess(psh.index(operation), first_await)
        flushing = self.adapter.split("async fn write_buffer_flush", 1)[1].split("async fn check_zero_window_probes", 1)[0]
        self.assertNotIn("write_buffer.drain", flushing)

    def test_persist_state_and_queue_are_retained(self):
        probes = self.adapter.split("async fn check_zero_window_probes", 1)[1].split("async fn check_retransmissions", 1)[0]
        self.assertIn("INITIAL_PERSIST_MS << state.persist_retries.min(5)", probes)
        self.assertIn("self.send_packet(ip).await?", probes)
        self.assertIn("state.bytes_in_flight == 0", probes)
        self.assertIn("state.persist_retries.saturating_add(1)", probes)

    def test_pending_flush_survives_cancellation(self):
        flushing = self.adapter.split("async fn flush_outbox", 1)[1].split("fn has_pending_work", 1)[0]
        self.assertIn("self.outbox.is_empty() && !self.outbox_needs_flush", flushing)
        self.assertLess(flushing.index("self.outbox_needs_flush = true"), flushing.index("self.peer.flush().await?"))
        self.assertGreater(flushing.index("self.outbox_needs_flush = false"), flushing.index("self.peer.flush().await?"))

    def test_inbound_readers_wake_before_outgoing_flush(self):
        incoming = self.handle.split("r = adapter.process_tcp_packet()", 1)[1].split("_ = crate::time::sleep", 1)[0]
        self.assertLess(incoming.index("deliver(&mut adapter, &mut handles).await"), incoming.index("adapter.write_buffer_flush().await"))
        retransmit = self.adapter.split("async fn check_retransmissions", 1)[1].split("pub(crate) async fn process_tcp_packet", 1)[0]
        self.assertIn("Some(state) if matches!(state.status, ConnectionStatus::Connected)", retransmit)

    def test_reader_wakeup_and_fatal_timer_flush_are_retained(self):
        self.assertIn("deliver(&mut adapter, &mut handles).await;", self.handle)
        timer = self.handle.split("_ = crate::time::sleep", 1)[1].split("deliver(&mut adapter", 1)[0]
        self.assertIn("if has_pending_work", timer)
        self.assertIn("if let Err(e) = adapter.write_buffer_flush().await", timer)
        self.assertIn("handles.drain()", timer)
        self.assertIn("tx.send(Err(e.kind().into()))", timer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
