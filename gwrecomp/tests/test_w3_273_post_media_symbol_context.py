import unittest
from tools.w3_273_post_media_symbol_context import parse_publics,nearest
class MapSymbolContextTests(unittest.TestCase):
 def test_exact_public_and_neighbor_are_returned_without_boundary_claim(self):
  p=parse_publics(' 0001:0005B880 W?ResetAllInputs$n()v\n 0001:000929D0 W?PlaySmacker$n(pnaucuc)v')
  self.assertEqual(nearest(p,0x5B880)['exact_symbol'],'W?ResetAllInputs$n()v')
  self.assertEqual(nearest(p,0x92996)['nearest_upper']['name'],'W?PlaySmacker$n(pnaucuc)v')
 def test_malformed_lines_are_ignored(self):
  self.assertEqual(parse_publics('bad row\n0001:nothex Symbol'),{})
 def test_missing_symbol_does_not_invent_a_name(self):
  self.assertIsNone(nearest({},0x92AE2)['exact_symbol'])
if __name__=='__main__':unittest.main()
