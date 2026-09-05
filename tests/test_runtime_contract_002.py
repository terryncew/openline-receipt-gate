from __future__ import annotations

import unittest

from olp_gate.ancestry import (
    AFFECTED_STATE,
    AncestryClosureError,
    ReceiverAncestryClosureView,
)
from olp_gate.standing import support_receipt_hash


def artifact(name: str):
    return {"schema": "test.artifact.v1", "id": name}


class ReceiverAncestryClosureTests(unittest.TestCase):
    def test_exact_transitive_closure_and_control(self):
        view = ReceiverAncestryClosureView()
        x = artifact("X")
        a = artifact("A")
        b = artifact("B")
        c_support = artifact("CONTROL-C")
        c = artifact("C")

        view.record_commit(
            decision_id="A",
            derived_receipt=a,
            accepted_supports=[x],
        )
        view.record_commit(
            decision_id="B",
            derived_receipt=b,
            accepted_supports=[a],
        )
        view.record_commit(
            decision_id="C",
            derived_receipt=c,
            accepted_supports=[c_support],
        )

        result = view.apply_standing_loss(
            support_hash=support_receipt_hash(x),
            standing_event_id="standing-loss-X-1",
            standing_event_sequence=2,
        )

        a_hash = support_receipt_hash(a)
        b_hash = support_receipt_hash(b)
        c_hash = support_receipt_hash(c)
        x_hash = support_receipt_hash(x)

        self.assertEqual(
            set(result["affected_receipt_hashes"]),
            {a_hash, b_hash},
        )
        self.assertEqual(
            result["causal_paths"][b_hash],
            [x_hash, a_hash, b_hash],
        )
        self.assertEqual(view.affected(a_hash)["state"], AFFECTED_STATE)
        self.assertEqual(view.affected(b_hash)["state"], AFFECTED_STATE)
        self.assertIsNone(view.affected(c_hash))

    def test_duplicate_edge_and_standing_replay_are_idempotent(self):
        view = ReceiverAncestryClosureView()
        x = artifact("X")
        a = artifact("A")

        first = view.record_commit(
            decision_id="A",
            derived_receipt=a,
            accepted_supports=[x],
        )
        second = view.record_commit(
            decision_id="A",
            derived_receipt=a,
            accepted_supports=[x],
        )
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(view.snapshot()["edge_sequence"], 1)

        first_loss = view.apply_standing_loss(
            support_hash=support_receipt_hash(x),
            standing_event_id="loss-1",
            standing_event_sequence=2,
        )
        sequence = view.snapshot()["closure_event_sequence"]
        replay = view.apply_standing_loss(
            support_hash=support_receipt_hash(x),
            standing_event_id="loss-1",
            standing_event_sequence=2,
        )
        self.assertFalse(first_loss["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(view.snapshot()["closure_event_sequence"], sequence)

    def test_cycle_and_multi_basis_are_rejected_without_mutation(self):
        view = ReceiverAncestryClosureView()
        x = artifact("X")
        a = artifact("A")
        b = artifact("B")
        other = artifact("OTHER")

        view.record_commit(
            decision_id="A",
            derived_receipt=a,
            accepted_supports=[x],
        )
        view.record_commit(
            decision_id="B",
            derived_receipt=b,
            accepted_supports=[a],
        )
        before = view.snapshot()

        with self.assertRaisesRegex(
            AncestryClosureError, "ancestry_cycle_forbidden"
        ):
            view.record_commit(
                decision_id="cycle",
                derived_receipt=x,
                accepted_supports=[b],
            )
        self.assertEqual(view.snapshot(), before)

        with self.assertRaisesRegex(
            AncestryClosureError, "ancestry_multi_basis_not_supported"
        ):
            view.record_commit(
                decision_id="multi",
                derived_receipt=other,
                accepted_supports=[x, a],
            )
        self.assertEqual(view.snapshot(), before)

    def test_untrusted_edge_assertion_never_mutates_receiver_state(self):
        view = ReceiverAncestryClosureView()
        before = view.snapshot()
        decision = view.assess_untrusted_edge(
            {
                "relationship": "BASIS_FOR",
                "support_hash": "0" * 64,
                "derived_receipt_hash": "1" * 64,
                "producer": "untrusted",
            }
        )
        self.assertFalse(decision["admitted"])
        self.assertEqual(
            decision["reason"],
            "ancestry_external_edge_forbidden",
        )
        self.assertEqual(view.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
