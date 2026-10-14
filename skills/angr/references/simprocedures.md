# angr hooks and SimProcedures

A hook replaces execution at an address or symbol with Python. A SimProcedure is the
structured form: it gets typed arguments, can return values, and integrates with the
calling convention automatically. Replacing one hot/opaque function is routinely the
difference between "solves in 4 seconds" and "never terminates".

## Address hooks

```python
# Function-style: run python, then skip `length` bytes of machine code.
@proj.hook(0x401234, length=5)          # 5 = size of the call instruction being replaced
def skip_check(state):
    state.regs.eax = 1                  # pretend the call returned 1

proj.hook(0x40ffe0, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
proj.is_hooked(0x401234); proj.unhook(0x401234)
```

`length=0` (default for SimProcedure hooks) means "this hook IS the function" — angr
returns to the caller via the calling convention. `length=N` means "run the python,
then continue at addr+N" — use it to neuter a single call/branch in place.

## Symbol hooks

```python
proj.hook_symbol("strcmp", angr.SIM_PROCEDURES["libc"]["strcmp"]())
proj.hook_symbol("ptrace", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
proj.hook_symbol("alarm",  angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
proj.hook_symbol("license_check", MyProc())      # works on local symbols too if named
```

`hook_symbol` resolves through PLT/GOT, so it catches every call site at once.

## Built-in catalog — `angr.SIM_PROCEDURES`

Dict of dicts: `SIM_PROCEDURES[library][name]`. The useful groups:

- `"libc"`: `strcmp, strncmp, strcpy, strlen, memcpy, memset, malloc, free, printf,
  scanf, atoi, puts, fgets, ...` — symbolic-aware models; one step instead of a
  byte-loop fork-fest.
- `"posix"`: `read, write, open, close, mmap, ...`
- `"stubs"`: `ReturnUnconstrained` (returns a fresh symbol), `Redirect`,
  `PathTerminator` (kill paths that reach here — great as a programmatic `avoid`),
  `UserHook`, `Nop`.
- `"glibc"`: `__libc_start_main`, scanf variants (`__isoc99_scanf`).
- `"linux_kernel"`: syscall models.

```python
# Kill all paths entering an error handler instead of exploring it:
proj.hook(0x401b00, angr.SIM_PROCEDURES["stubs"]["PathTerminator"]())
```

## Writing a SimProcedure

```python
import angr, claripy

class FakeHash(angr.SimProcedure):
    def run(self, buf, length):                  # args arrive as BVs per the ABI
        # Treat the hash output as a free symbol; constrain at the compare instead.
        out = claripy.BVS("hash_out", 64)
        self.state.globals["hash_out"] = out
        return out                               # return value, ABI-correct

proj.hook_symbol("custom_hash64", FakeHash())
```

Inside `run()` you have:

- `self.state` — full state access (`memory`, `regs`, `solver`, `posix`, `globals`).
- `self.arguments` — raw arg list; declared parameters (`buf`, `length`) are already
  extracted per the calling convention.
- `self.state.memory.load(buf, 32)` / `.store(buf, bv)` — operate on pointer args.
- `self.ret(value)` or `return value` — return to caller.
- `self.call(addr, args, continue_at="after")` — call back into the binary, resume in
  the method named `after` (define it on the class). For wrapping, not replacing.
- `self.exit(code)` — terminate the path.
- `self.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_ptr).ret_expr` — reuse a
  built-in model inside your own procedure.

### Recipe: scanf("%d") / scanf("%s") replacement

```python
class FakeScanf(angr.SimProcedure):
    def run(self, fmt, ptr):
        val = claripy.BVS("scanf_int", 32)
        self.state.memory.store(ptr, val, endness=self.state.arch.memory_endness)
        self.state.globals.setdefault("scanf_vals", []).append(val)
        return 1                                  # "1 item converted"
proj.hook_symbol("__isoc99_scanf", FakeScanf())
# after explore: found.solver.eval(found.globals["scanf_vals"][0])
```

### Recipe: force a validator to pass vs. model it

Two strategies — pick deliberately:

1. **Force-pass** (`return 1`): fastest; use when you only care about code *after*
  the check and will recover the real input some other way.
2. **Model** (symbolic return tied to inputs): required when the solved input must
  actually pass the real binary. E.g. replace `checksum()` with a free symbol `out`,
  explore to the success state, read the concrete value the program compared against
  (`found.solver.eval(out)`), then invert the real checksum separately (brute it
  under the `qiling-unicorn` skill's Unicorn harness if it's not invertible on paper).

### Recipe: logging tap without changing behavior

```python
class TapSystem(angr.SimProcedure):
    def run(self, cmd_ptr):
        cmd = self.state.memory.load(cmd_ptr, 128)
        if self.state.solver.symbolic(cmd):
            print("[!] SYMBOLIC bytes reach system() — command injection candidate")
            print("    sample:", self.state.solver.eval(cmd, cast_to=bytes))
        return 0
proj.hook_symbol("system", TapSystem())
```

Symbolic data reaching `system`/`execve`/`popen` arguments is a finding: record the
sink symbol with `assets.mark` and report per `references/rupu.md`.

## When to hook (decision table)

| Situation | Action |
|---|---|
| Loop over symbolic bytes (strlen/strcmp hand-rolled) | hook with libc SimProcedure equivalent |
| Hash/CRC/crypto of symbolic input | FakeHash pattern: free symbol + constrain at compare |
| sleep/alarm/ptrace/getenv anti-debug | `ReturnUnconstrained` or `Nop` |
| printf/logging (irrelevant, slow fmt parsing) | `ReturnUnconstrained` |
| Error/cleanup basin eating paths | `PathTerminator` at its entry |
| Function with side effects you need | wrap with `self.call(...)` continuation |
| Syscall-level behavior | `angr.SIM_PROCEDURES["linux_kernel"]`, or `proj.simos.syscall_library` overrides |
