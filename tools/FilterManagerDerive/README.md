# FilterManagerDerive

Offline helper for deriving the random-DLL `FilterManager` / `DripValueImpl`
state without launching the game or taking a minidump.

The tool must run as x86 because the random DLLs are 32-bit PE files. It loads
the DLL, calls the internal initialization RVAs directly, and writes a
`drip_program.json` compatible with `src/common/xp3_inspect.py`.

```powershell
dotnet build tools\FilterManagerDerive\FilterManagerDerive.csproj -p:PlatformTarget=x86

& 'C:\Program Files (x86)\dotnet\dotnet.exe' `
  tools\FilterManagerDerive\bin\Debug\net8.0\FilterManagerDerive.dll `
  --dll 9bd81f525ace.dll `
  --out data\9bd81f525ace.drip_program.json `
  --bootstrap-text "<final System.bootStrap string>" `
  --archive-text "<UNIQUE string from BOOTSTRAP DLL>"
```

If `--bootstrap-text` is omitted, the tool uses `UNIQUE + WARNING` from the DLL
config table. That is useful for exploration, but the exact game value may be a
different concatenation supplied by the boot script. Use `--bootstrap-hex` when
you already have the exact UTF-16LE byte sequence.

Useful options:

- `--no-default-warning`: use only `UNIQUE` when no bootstrap text is supplied.
- `--bootstrap-prefix` / `--bootstrap-suffix`: compose the low-level bootstrap
  string without hex encoding it manually.
- `--archive-seed-hex`: override the 8-byte archive seed at RVA `0x81758`.
- `--params-hex`: override the `PARAMS` table entry.
