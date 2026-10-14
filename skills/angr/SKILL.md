---
name: angr
description: Symbolic/concolic execution with angr to solve for inputs that reach or avoid a program state — recover license/password/serial checks, prove reachability of a sink, and detect unconstrained (hijackable) states whose constraints feed straight into exploit development. Use when you need the input that satisfies a binary's checks rather than just running or reading it, or to locate control-flow hijack primitives.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# angr — symbolic execution for input recovery and hijack detection

angr lifts the binary to VEX IR and executes it over symbolic values; a constraint
solver (claripy/Z3) then produces concrete inputs for any reachable state. Use it to
answer "what input makes execution reach address X / print 'correct' / avoid 'wrong'",
and to find states where the program counter itself became attacker-controlled.

Install: `pip install angr` (in a venv — it pins specific claripy/cle/pyvex versions).
Deep reference: `references/angr.md`. Hooks/SimProcedures: `references/simprocedures.md`.
Output wiring: `references/rupu.md`. For *running* a binary (emulation, not solving),
use the sibling `qiling-unicorn` skill instead.

## 1. Project and initial state

```python
import angr, claripy

proj = angr.Project("./target", auto_load_libs=False)
# auto_load_libs=False: unresolved libc calls become SimProcedure stubs — almost
# always what you want. Loading real libc = massive state explosion.

print(hex(proj.entry), proj.arch.name, proj.loader.main_object.pic)
# PIE binaries load at base 0x400000 by default; angr addresses = base + file offset.
# Pin it explicitly if you want disassembler-matching addresses:
# proj = angr.Project("./target", main_opts={"base_addr": 0x400000}, auto_load_libs=False)

state = proj.factory.entry_state()                 # start at the entry point
state = proj.factory.full_init_state()             # also run ld.so init/ctors first
state = proj.factory.blank_state(addr=0x401230)    # start mid-binary, everything-symbolic
state = proj.factory.call_state(0x401560, arg1, arg2)  # call one function with args
```

`blank_state`/`call_state` skip all the setup that breaks (`full_init_state` hangs,
missing env) — start directly at the check function when you can.

## 2. Symbolic input — three placements

```python
flag = claripy.BVS("flag", 8 * 32)                     # 32 symbolic bytes

# (a) stdin — most common for crackmes
stdin = angr.SimFileStream(name="stdin", content=flag, has_end=True)
state = proj.factory.entry_state(stdin=stdin)

# (b) argv
arg1 = claripy.BVS("arg1", 8 * 16)
state = proj.factory.entry_state(args=["./target", arg1])

# (c) memory / registers (with blank_state/call_state)
state = proj.factory.blank_state(addr=CHECK_FN)
buf = 0x600000                       # any unused address; blank_state memory is lazy
state.memory.store(buf, flag)
state.regs.rdi = buf                 # per-ABI arg register
state.regs.rsi = 32
```

Constrain the alphabet up front — it prunes huge subtrees:

```python
for i in range(32):
    b = flag.get_byte(i)
    state.solver.add(b >= 0x20, b <= 0x7e)       # printable only
```

## 3. Explore and read the answer

```python
simgr = proj.factory.simgr(state)
simgr.explore(
    find=0x401a2c,                                   # address…
    avoid=[0x401b00, 0x401b40],                      # …or list…
)
# …or predicates on the state:
simgr.explore(
    find=lambda s: b"Correct"   in s.posix.dumps(1), # stdout so far
    avoid=lambda s: b"Wrong"    in s.posix.dumps(1),
)

if simgr.found:
    s = simgr.found[0]
    print(s.solver.eval(flag, cast_to=bytes))        # the symbolic var, concretized
    print(s.posix.dumps(0))                          # everything read from stdin
    print(s.posix.dumps(1))                          # stdout produced on this path
else:
    print("not found; deadended:", len(simgr.deadended), "active:", len(simgr.active))
```

- `solver.eval(sym, cast_to=bytes)` = one satisfying value; `solver.eval_upto(sym, 10)`
  = several; `solver.min/max` for numeric bounds.
- `s.posix.dumps(0)` is usually the artifact you want: paste it to the real binary
  (`./target <<< '...'`) to verify, then keep it as evidence.
- Pick find/avoid addresses from your disassembler: `find` = the block after the check
  succeeds (puts("Correct")), `avoid` = the failure block **and** any early `exit()`.

## 4. Path explosion — the controls, in order of cheapness

1. **avoid aggressively** — every avoided address kills a subtree.
2. **Drop the avoid stash** so memory doesn't fill:
   ```python
   simgr.explore(find=FIND, avoid=AVOID,
                 step_func=lambda sm: sm.drop(stash="avoid"))
   ```
3. **Veritesting** (merges paths through if-trees): `proj.factory.simgr(state, veritesting=True)`.
4. **Lazy solving** (defer SAT checks until needed):
   ```python
   state = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
   ```
5. **DFS** (one path at a time, bounded memory):
   `simgr.use_technique(angr.exploration_techniques.DFS())`.
6. **Hook the expensive function** (strlen loop, hash function, sleep, printf) with a
   SimProcedure — the single biggest lever; see `references/simprocedures.md`.
7. Shorter symbolic input; `LoopSeer(bound=50)` against infinite loops;
   `unicorn` state option to execute concrete-only sections at native speed:
   `entry_state(add_options=angr.options.unicorn)`.

## 5. Hooks and SimProcedures

```python
proj.hook(0x401234, lambda state: None, length=5)    # skip 5 bytes (nop a call site)
proj.hook_symbol("ptrace", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
proj.hook_symbol("strcmp", angr.SIM_PROCEDURES["libc"]["strcmp"]())

class FakeCheck(angr.SimProcedure):
    def run(self, buf, length):
        return 1                                     # force the check to pass
proj.hook_symbol("license_check", FakeCheck())
```

Hook anything that: loops over symbolic data (hashes, CRCs — symbolic SHA256 is
unsolvable, replace it and solve around it), does I/O you don't model, or is an
anti-debug (`ptrace`, `alarm`, `sleep`). Full patterns, argument/return handling, and
the built-in `angr.SIM_PROCEDURES` catalog: `references/simprocedures.md`.

## 6. Finding exploitable (unconstrained) states

A state whose instruction pointer became symbolic = attacker data reached PC =
control-flow hijack. angr finds these for you:

```python
simgr = proj.factory.simgr(state, save_unconstrained=True)
simgr.explore()                                      # or .run()
for s in simgr.unconstrained:
    print("hijack state, pc:", s.regs.pc)            # symbolic expression
    # Prove control + extract the offset:
    s.add_constraints(s.regs.pc == 0x41414141)
    if s.satisfiable():
        crash_input = s.posix.dumps(0)               # input that sets PC = 0x41414141
        # Which input bytes land in PC? Solve PC for a marker and diff:
        print("crash stdin:", crash_input)
    # Constrain more: pc == win_addr, stack pivot value in rsp, etc.
```

From here: `s.solver.eval(s.regs.rsp)` and the marker offset give you the exact
overflow layout. Hand the offset + constraints to the `pwntools` skill (process/IO +
payload delivery) and the `rop-chains` skill (gadget chain to replace 0x41414141).
Check `s.memory.load(s.regs.rsp, 8)` symbolic-ness to size the controlled region.

## 7. Script

```bash
python3 scripts/angr_solve.py ./crackme --find 0x401a2c --avoid 0x401b00,0x401b40
python3 scripts/angr_solve.py ./crackme --find-str "Correct" --avoid-str "Wrong" \
    --stdin-len 40 --printable --out solve.json --work-units units.json
python3 scripts/angr_solve.py ./server --hunt-unconstrained --stdin-len 400
```

Prints the solving stdin bytes (and the raw symbolic value), writes a JSON result +
rupu work units, and degrades with install instructions when angr is missing.

## 8. Troubleshooting (generated scripts break here)

| Symptom | Fix |
|---|---|
| Hangs before main / in `__libc_start_main` | Use `entry_state` not `full_init_state`; or `blank_state(addr=main)` and set stdin/regs yourself |
| `SimProcedureError` / warnings about unresolved calls | Fine — stubs returned unconstrained; if the stubbed fn matters, hook it with a real `SIM_PROCEDURES` impl |
| Explores forever, RAM climbs | `drop(stash="avoid")` step_func, DFS, veritesting, hook the hot function, shorten input |
| `simgr.found` empty but target is reachable | find address is wrong base (PIE: angr base 0x400000), or an un-avoided `exit()` ate every path, or stdin too short to pass a length check |
| Answer has nonprintable garbage | add printable constraints per byte; eval_upto for alternatives |
| `scanf("%d")` reads nothing useful | hook `__isoc99_scanf` with a SimProcedure that stores a fresh BVS (recipe in references/simprocedures.md) |
| fs/network input | `state.fs.insert(path, angr.SimFile(...))`; sockets: predicate on `s.posix.dumps(fd)` or hook recv |

## 9. Hand-off and reporting

- Solved check input / recovered serial or password → rupu `findings.report`
  (contract in the `finding-report` skill); solved input bytes are the evidence
  artifact. Mark the check function `binary:symbol` depth `analyzed`/`vuln-identified`
  via `assets.mark` — mapping in `references/rupu.md`.
- Unconstrained state → `vuln-identified`; chain to `pwntools` + `rop-chains`.
- Reached-sink proof (constraints showing attacker bytes reach `system` arg) → chain
  to `qiling-unicorn` to demonstrate dynamically, then report.
