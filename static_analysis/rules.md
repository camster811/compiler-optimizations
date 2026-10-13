# Static baseline rules

`analyze.py` reads only analyzer-facing Ghidra records (`ghidra/record_schema.json`).
It never reads the oracle mapping, run metadata, source, ground truth, or anything
derived from file names or directories, and it ignores symbol names, the decompiler
text, and Ghidra's stack-variable names and sizes. Rules work from the instruction
listing and the call list.

## How the listing is read

One straight-line pass (no branches followed). It tracks:

- the result of a `malloc` call (`RAX` after the call) and its size, taken from the
  constant in `RDI` at the call;
- frame addresses made with `LEA` from `RBP` or `RSP`;
- both values copied between registers or spilled to and reloaded from a frame slot;
- every store (`MOV`-family with a memory destination) made through those values,
  as a half-open byte interval `[lo, hi)` measured from the pointer or the frame base.
  Overlapping or touching intervals are merged.

Compiler-expanded copies matter here: `strcpy` of a constant never survives as a call,
so the copy appears as one or two immediate or register stores. The rules therefore
look at store extents, not at a callee named `strcpy`. The disappearance of `strcpy`
is compiler builtin lowering seen at both optimization levels, not an O2 effect.

## Rules

| Rule id | Fires when | Classification | CWE |
|---|---|---|---|
| `heap_write_exceeds_allocation` | For a constant-size `malloc(n)` result, a merged written interval has `hi > n`. | `vulnerable` | CWE-122 |
| `unsupported_heap_underwrite` | A merged written interval has `lo < 0` and no `hi > n` finding fired. | `uncertain` | none |
| `stack_write_exceeds_frame_locals` | Stores through a frame address extend past the end of the local area: beyond `rbp+0` in an `RBP` frame (into the saved frame pointer), or beyond the `SUB RSP, n` area. | `vulnerable` | CWE-121 |
| `unresolved_copy_call` | The listing still calls a copy function (`strcpy`, `memcpy`, ...) and no rule above fired. | `uncertain` | none |
| `heap_write_within_allocation` | Every tracked `malloc` has a constant size, every written interval lies in `[0, n]`, nothing else is unresolved, and no rule above fired. | `not_vulnerable` | none |
| `insufficient_evidence` | None of the above, for example a buffer-like stack write that stays inside the frame, a `malloc` with a non-constant size or no visible write, or an unmatched call list. | `uncertain` | none |
| `no_function_recovered` | The record has `status` other than `ok`. | `uncertain` | none |

When several vulnerable findings exist, `predicted_cwe` comes from the lowest address.

CWE-122 is reported only when a heap write ends past the allocation (`hi > n`). A heap
write that starts before it (`lo < 0`) is an underwrite, which CWE files separately
(CWE-124). The project is scoped to CWE-121/122, so an underwrite is never classified
as CWE-122 and CWE-124 is not a prediction class: it yields `uncertain` with
`unsupported_heap_underwrite`. If a record has both an overflow and an underwrite, it is
`vulnerable` with CWE-122 for the overflow, and `unsupported_heap_underwrite` is listed
in `triggered_rules` with its own evidence line. No pilot record has an underwrite; the
rule was checked only on synthetic listings.

### Evidence wording

Intervals are half-open. For example, the O0 stack case reports
`11-byte write over [rbp-0xa, rbp+0x1) extends 1 byte(s) beyond the local area into the
saved frame pointer`. The write crosses the end of the local area and lands on one byte
of the saved frame pointer; it does not pass the whole saved frame pointer.

### Frozen pilot parameter

`MIN_BUFFER_LIKE_WRITE = 8` is a heuristic, not a derived value. A merged stack write of
at least 8 bytes that stays inside the frame is treated as buffer-like and adds
"capacity unknown" evidence (which yields `uncertain`). Shorter stack writes (scalar
spills and initializations) are ignored so that every ordinary local variable does not
force an uncertain result. It is fixed for the pilot and was not tuned.

## Deliberate limits

- **Stack buffer capacity is not recoverable from these records.** Ghidra's
  stack-variable sizes describe its reconstruction of the accesses (it reports 11 bytes
  for a 10-byte buffer and gives the fixed variant the same size), not the source
  object, so they are not used. A stack overflow is detected only when the write leaves
  the local area. A write that overflows the buffer but lands in padding (the optimized
  stack build) is `uncertain`, not safe.
- **Stack writes are never called safe.** Without a trustworthy capacity, staying
  inside the frame does not show staying inside the buffer.
- The baseline recovers heap allocation/write relationships but cannot generally
  reconstruct source-level stack-object bounds from these binary records. That is a
  limitation of the baseline and is itself evidence for the research question.
- No branch, loop, or interprocedural reasoning.
- The rules were written after the four pilot cases were inspected. Pilot results are
  development-set sanity checks, not evidence of generality.
- Retained and stripped predictions agree largely by construction, because the rules
  ignore function names, decompiler text, and inferred variable names and sizes. The
  pilot result is "the symbol-insensitive baseline produced identical retained and
  stripped predictions". It is not evidence that stripping has no effect on static
  analysis in general; the LLM condition is where neutral names are expected to matter.

## Output

`output/predictions.json`: one object per distinct input record, sorted by `sample_id`
then `record_sha256`.

```json
{
  "record_sha256": "…",
  "sample_id": "sample_0003",
  "classification": "vulnerable | not_vulnerable | uncertain",
  "predicted_cwe": "CWE-122",
  "evidence": ["malloc(10) is followed by a write of 11 bytes over [ptr+0, ptr+11) that ends 1 byte(s) past the allocation"],
  "triggered_rules": ["heap_write_exceeds_allocation"]
}
```

### `record_sha256` is a content identifier

It is the SHA-256 of the input record's raw bytes. It is derived only from analyzer-facing
input, reveals no optimization level or symbol condition, binds a prediction to the exact
bytes analyzed, and makes shuffled execution reproducible. The 16 records share four
`sample_id` values, so `sample_id` alone cannot identify a prediction.

It is not an observation id. Byte-identical records from different experimental
conditions would share a hash. The analyzer emits one prediction per distinct hash; the
private evaluator maps each hash to one or more observations and adds the condition only
at evaluation time. Because the hash covers raw bytes, reformatting a record changes it;
the 16 input records are therefore frozen as exact experimental inputs.

## Reporting `uncertain`

`uncertain` is an abstention. Never report only the cases the baseline decided; always
give coverage next to accuracy. `evaluation/check_static_predictions.py` prints two views.

**Three-way descriptive view.** Correct decisions, incorrect decisions, abstentions,
decision coverage (decided / total), abstention rate, and *selective accuracy*
(correct / decided). Selective accuracy is not ordinary accuracy. A decision is correct
when a vulnerable case is predicted `vulnerable` with the right CWE, or a fixed case is
predicted `not_vulnerable`.

**Binary security-detection view (primary).** `vulnerable` is an alert; `not_vulnerable`
and `uncertain` are no alert. Report TP, TN, FP, FN, accuracy, balanced accuracy,
precision, recall, F1, FPR and FNR. Abstentions on vulnerable cases are false negatives
and abstentions on fixed cases are true negatives; the checker prints both counts so a
reader can see how much of TN and FN is abstention.
