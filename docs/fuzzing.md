### How

Enter dev shell with fuzzing support:

```
nix develop .#fuzz
```

Select fuzzing target:

```
just fuzz-target
```

Starting fuzzing:

```
just fuzz-target <target>
```

If you have found a crash:

```
just fuzz-target-debug <target>
```

When `lldb` shows up:

List the frames in the stack-trace:

```
bt
```

Select the one with a crash/panic/assert:

```
frame 8
```

Inspect the variables and use other debugger facilities, check lldb/gdb tutorial
for more info on that.

See corresponding `just` rules for details.
