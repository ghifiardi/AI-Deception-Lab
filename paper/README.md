# Optional Traps — arXiv preprint source

LaTeX source for "Optional Traps: An Empirical Study of LLM Agents Against Credential Deception and Alert-Driven Revocation" (IEEEtran conference format, two columns, 6 pages).

| File | Purpose |
| --- | --- |
| `main.tex` | Paper source, with the bibliography inline (no BibTeX step) |
| `fig-architecture.tex` | Figure 1, drawn in TikZ (no image files needed) |
| `main.pdf` | Compiled preview |

## Build

```bash
pdflatex main.tex && pdflatex main.tex
```

Needs IEEEtran, TikZ, booktabs and tabularx. All of these are in TeX Live and on arXiv.

## Before submitting

1. Repository URL and Zenodo DOI (10.5281/zenodo.24217354) are already in Section IX.
2. Check the references against the original publications. In particular, check the second author of [1] on the USENIX page, and the page numbers in [5], [9] and [10].
3. Optionally add a contact e-mail under the author block.
4. On arXiv, choose primary category **cs.CR** and upload `main.tex` plus `fig-architecture.tex`. First-time submitters to cs.CR may need an endorsement.
