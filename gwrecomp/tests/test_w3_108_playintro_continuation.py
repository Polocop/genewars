import unittest

from tools.w3_108_playintro_continuation import (
    build_evidence,
    derive_screen_setup_return_chain,
    extract_closure_instructions,
)


class PlayIntroContinuationTests(unittest.TestCase):
    def test_synthetic_return_chain_extraction(self):
        synthetic = """
        x(); /* 0x0009FEAF: ret */
        x(); /* 0x000962F7: call 0x9fd40 */
        x(); /* 0x000962FC: add esp, 0x10 */
        x(); /* 0x000962FF: ret */
        x(); /* 0x00092A11: call 0x962f0 */
        x(); /* 0x00092A16: mov ebx, 1 */
        """
        instructions = extract_closure_instructions(synthetic)
        chain = derive_screen_setup_return_chain(instructions)
        self.assertEqual(
            [row["link_va"] for row in chain],
            ["0x0009FEAF", "0x000962F7", "0x000962FC", "0x000962FF", "0x00092A11", "0x00092A16"],
        )

    def test_rejects_inconsistent_synthetic_return(self):
        instructions = extract_closure_instructions(
            "x(); /* 0x0009FEAF: jmp 0x1234 */"
        )
        with self.assertRaisesRegex(ValueError, "return-chain mismatch"):
            derive_screen_setup_return_chain(instructions)

    def test_hash_bound_real_inputs_and_frontier(self):
        evidence = build_evidence()
        self.assertEqual(evidence["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(evidence["first_exact_capture_frontier"]["link_va"], "0x00092A16")
        self.assertEqual(evidence["first_exact_capture_frontier"]["status"], "STATIC_ONLY_NOT_DYNAMICALLY_OBSERVED")
        self.assertIn("0x00094347", [r["link_va"] for r in evidence["static_chain"]])
        self.assertIn("0x000929C8", [r["link_va"] for r in evidence["next_distinguishing_frontiers"]])
        self.assertNotIn("0x000929C4", [r["link_va"] for r in evidence["next_distinguishing_frontiers"]])
        self.assertIn("did not observe", evidence["interpretation"])


if __name__ == "__main__":
    unittest.main()
