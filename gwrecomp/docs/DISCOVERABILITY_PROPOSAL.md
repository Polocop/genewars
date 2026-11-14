# Proposal: making GWRecomp discoverable from the repository front page

Status: **proposal only - nothing here has been applied to `main`.**

Constraints: keep mefistotelis' attribution and README intact, do not rewrite history, do not make `main` look like a finished product.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Banner at the top of `main`'s README linking to `gwrecomp/` | Visible to every visitor; no default-branch change; trivially reversible | Changes `main`; requires the merge blockers to be cleared first |
| B. Repository "About" description and topics (e.g. `gene-wars`, `static-recompilation`, `reverse-engineering`, `bullfrog`) | Helps search; no code change | Settings change; description must not imply a finished port |
| C. Make `gwrecomp-native-port` the default branch | Visitors land directly on the new work | Hides the inherited upstream layout; makes the fork diverge visibly; not reversible without confusing forks/PRs |
| D. Separate GWRecomp-only repository | Clean identity | Contradicts the decision to keep it in the fork; loses fork relationship |

## Recommended

1. Resolve the merge blockers in the draft PR (see `PROVENANCE.md`).
2. Merge the PR so `main` carries `gwrecomp/` and the docs.
3. In a *separate, small* follow-up PR, add a three-line banner (option A) above the upstream README text, leaving the upstream text unchanged, worded as: "Fork of mefistotelis/genewars. Contains GWRecomp, an experimental static-recompilation port (research prototype, requires your own game files)."
4. Apply option B with the same honest wording.
5. Keep `main` as the default branch (reject C and D).

Until step 2, the branch banner in the root `README.md` of `gwrecomp-native-port` already provides a link for anyone who follows the branch or PR.
