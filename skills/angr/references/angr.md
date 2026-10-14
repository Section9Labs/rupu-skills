# angr — states, simgr, solver, and path-explosion control

## Project loading

```python
import angr

proj = angr.Project("./target", auto_load_libs=False)
proj = angr.Project("./target",                      # control the loader (CLE):
                    main_opts={"base_addr": 0x400000},
                    load_options={"auto_load_libs": False})
proj = angr.Project("libcrypto.so", auto_load_libs=False)   # libraries load fine too

proj.arch            # archinfo object: name, bits, memory_endness, registers
proj.entry           # entry point address
proj.loader.main_object.min_addr / .max_addr
proj.loader.find_symbol("check_password").rebased_addr
proj.loader.main_object.plt                               # dict name -> plt addr
```

`auto_load_libs=False` makes every external call hit an angr SimProcedure (accurate
python models for most of libc) or a `ReturnUnconstrained` stub. This is faster AND
more solvable than executing real libc. Only load real libs when the logic you must
reason about lives there.

CFG when you need addresses programmatically:

```python
cfg = proj.analyses.CFGFast()
for f in cfg.functions.values():
    print(hex(f.addr), f.name)
```

## State factories

| Factory | Starts at | Use when |
|---|---|---|
| `entry_state(args=, env=, stdin=)` | ELF entry | normal CLI programs |
| `full_init_state(...)` | before dynamic loader init | ctors/ifuncs matter (slow, often hangs) |
| `blank_state(addr=A)` | A, memory/regs fully symbolic-lazy | starting at the check function |
| `call_state(A, a0, a1, ..., ret_addr=...)` | A with a proper call frame | solving one function |

`call_state` args: ints, BVs, strings, or `angr.PointerWrapper(bv, buffer=True)` to
auto-place a symbolic buffer in memory and pass its address.

State options worth knowing (`add_options={...}` at creation):

- `angr.options.LAZY_SOLVES` — don't check satisfiability each step; prune later.
- `angr.options.unicorn` — concretely execute non-symbolic stretches in Unicorn, big
  speedup on real binaries.
- `angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY` / `..._REGISTERS` — uninitialized
  reads become 0 instead of fresh symbols (kills warnings + spurious branches).
- `angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY` — the opposite, for hunting
  uninitialized-data bugs.

## State inspection and mutation

```python
state.regs.rax, state.regs.pc, state.regs.sp          # BV-valued; assignable
state.mem[0x601048].uint64_t.resolved                 # typed memory view
state.mem[0x601048].uint64_t = 0x1337
state.memory.load(addr, 32)                           # raw BV load (size bytes)
state.memory.store(addr, bv_or_bytes)
state.callstack                                       # where am I
state.history.bbl_addrs.hardcopy                      # executed block trace for a path
state.posix.dumps(0) / dumps(1) / dumps(2)            # stdin consumed / stdout / stderr
state.globals["key"] = v                              # per-path scratch dict
```

Symbolic values (claripy):

```python
import claripy
x  = claripy.BVS("x", 64)          # symbol
c  = claripy.BVV(0x41, 8)          # concrete bitvector
flag = claripy.Concat(*[claripy.BVS(f"c{i}", 8) for i in range(16)])  # per-byte names
flag.get_byte(i)                   # byte extraction (big-endian index 0 = first byte)
```

## Solver

```python
state.solver.add(x > 10, x < 100)
state.satisfiable()                               # bool
state.solver.eval(x)                              # one solution (int)
state.solver.eval(flag, cast_to=bytes)            # bytes solution
state.solver.eval_upto(x, 20)                     # up to 20 distinct solutions
state.solver.min(x), state.solver.max(x)
state.solver.eval(x, extra_constraints=[x != 5])  # what-if without committing
state.solver.symbolic(state.regs.pc)              # is this value symbolic?
```

## Simulation manager

```python
simgr = proj.factory.simgr(state)
simgr = proj.factory.simgr(state, veritesting=True, save_unconstrained=True)

simgr.active / .found / .avoid / .deadended / .unconstrained / .errored   # stashes
simgr.step()                       # one step for every active state
simgr.run()                        # until all states terminate
simgr.explore(find=F, avoid=A, n=100000, num_find=3)
simgr.move(from_stash="deadended", to_stash="active",
           filter_func=lambda s: b"retry" in s.posix.dumps(1))
simgr.drop(stash="avoid")
simgr.errored[0].reraise()         # debug a crashed path
```

`find` / `avoid` each accept: an int address, an iterable of addresses, or a
predicate `lambda state: bool`. Predicates on output:

```python
find=lambda s: b"Access granted" in s.posix.dumps(1)
avoid=lambda s: b"denied" in s.posix.dumps(1) or s.addr in {0x401b00}
```

`num_find=` keeps exploring for multiple solutions (default stops at 1).

## Exploration techniques

```python
ET = angr.exploration_techniques
simgr.use_technique(ET.DFS())                      # depth-first, 1 active state
simgr.use_technique(ET.LoopSeer(bound=50))         # cap loop iterations -> 'spinning' stash
simgr.use_technique(ET.LengthLimiter(10000))       # cap path length
simgr.use_technique(ET.Timeout(600))               # wall-clock cap on .run/.explore
simgr.use_technique(ET.ExplorationTechnique)       # subclass for custom scheduling
simgr.use_technique(ET.Veritesting())              # same as veritesting=True
simgr.use_technique(ET.Spiller())                  # page inactive states to disk
simgr.use_technique(ET.MemoryWatcher())            # auto-pause when host RAM is low
```

A practical step_func that keeps memory flat and reports progress:

```python
import time
def step_func(sm):
    sm.drop(stash="avoid")
    if int(time.time()) % 10 == 0:
        print(f"active={len(sm.active)} found={len(sm.found)}")
    return sm
simgr.explore(find=F, avoid=A, step_func=step_func)
```

## Path-explosion triage checklist

1. Count: `len(simgr.active)` after N steps. Growing linearly = fine; exponential =
   find the branchy function: `max(simgr.active, key=...)`, look at
   `state.callstack.func_addr`, hook it.
2. strlen/strcmp over symbolic data forks per byte — the built-in libc SimProcedures
   handle these symbolically in one step; make sure `auto_load_libs=False` so they're
   actually used.
3. Hash/CRC/crypto over symbolic input: never solvable byte-wise. Hook it, return a
   fresh symbol, add the equality constraint at the comparison site instead.
4. Reading N symbolic bytes where N is also symbolic: fix N
   (`state.solver.add(n == 32)`) or use `SimFileStream(..., has_end=True)`.
5. Still stuck: narrow the problem — `call_state` directly on the check function with
   a symbolic buffer, solve, then verify end-to-end concretely.

## stdin/file/network modeling

```python
# precise stdin: fixed-size symbolic stream
flag = claripy.BVS("flag", 8*32)
state = proj.factory.entry_state(
    stdin=angr.SimFileStream(name="stdin", content=flag, has_end=True))

# files
simfile = angr.SimFile("cfg", content=claripy.BVS("cfg", 8*64), size=64)
state.fs.insert("/etc/app.cfg", simfile)

# packet-based stdin (default): each read() returns a fresh symbolic packet;
# s.posix.dumps(0) still reconstructs the full input — good enough for most solves.
```

## Verifying a solution

Always confirm concretely before reporting:

```bash
printf '%s' "$(python3 -c 'print("SOLVED-INPUT", end="")')" | ./target
# or echo the exact bytes file: ./target < solution.bin
```

A solution that only works symbolically means a modeling gap (usually a hooked
function whose real behavior differs) — tighten the SimProcedure and re-solve.
