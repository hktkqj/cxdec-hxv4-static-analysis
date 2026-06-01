using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal static class Program
{
    private const int ImageBase = 0x10000000;
    private const int ManagerSize = 0x30B0;
    private const int ManagerSlotRva = 0xAC9AC;
    private const int TableRva = 0x80E38;
    private const int ArchiveSeedRva = 0x81758;

    private const int RvaManagerCtor = 0x0E2D0;
    private const int RvaHashKeyDerive = 0x10410;
    private const int RvaBootstrapDerive = 0x15630;
    private const int RvaArchiveDerive = 0x157D0;

    private const int ContextOffset = 0x28;
    private const int DripHolderOffset = 0x08;
    private const int DripLaneBaseOffset = 0x04;
    private const int LaneCount = 128;
    private const int LaneSize = 0x10;

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate nint LoadLibraryWDelegate(string path);

    [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
    private delegate nint ManagerCtor(nint thisPtr);

    [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
    private delegate byte BootstrapDerive(
        nint thisPtr,
        nint bootstrapBytes,
        nuint bootstrapSize,
        nint paramsBytes,
        nuint paramsSize);

    [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
    private delegate int ArchiveDerive(
        nint thisPtr,
        nint archiveNameBytes,
        nuint archiveNameSize,
        nint seedBytes);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void HashKeyDerive(
        nint outBytes,
        nuint outSize,
        nint dataBytes,
        nuint dataSize,
        int seed);

    private static int Main(string[] argv)
    {
        Console.OutputEncoding = Encoding.UTF8;
        try
        {
            var args = Args.Parse(argv);
            if (!Environment.Is64BitProcess)
            {
                return Run(args);
            }

            Console.Error.WriteLine("This tool must run as a 32-bit process because the random DLL is x86.");
            Console.Error.WriteLine("Build/run with: dotnet run --project tools/FilterManagerDerive -p:PlatformTarget=x86 -- <args>");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static int Run(Args args)
    {
        if (args.ShowHelp || args.DllPath is null || args.OutputPath is null)
        {
            Args.PrintHelp();
            return args.ShowHelp ? 0 : 2;
        }

        var dllPath = Path.GetFullPath(args.DllPath);
        var module = Native.LoadLibraryW(dllPath);
        if (module == 0)
        {
            throw new InvalidOperationException($"LoadLibraryW failed for {dllPath} (Win32={Marshal.GetLastWin32Error()})");
        }

        var table = ReadConfigTable(module + TableRva);
        var paramsBytes = args.ParamsHex is not null ? ParseHex(args.ParamsHex) : table["PARAMS"];
        var warning = DecodeAscii(table["WARNING"]);
        var unique = DecodeUtf16Le(table["UNIQUE"]);
        var seed = args.ArchiveSeedHex is not null ? ParseHex(args.ArchiveSeedHex) : ReadBytes(module + ArchiveSeedRva, 8);
        if (seed.Length < 8)
        {
            throw new InvalidOperationException("archive seed must be at least 8 bytes");
        }

        var bootstrapBytes = BuildBootstrapBytes(args, unique, warning);
        var archiveNameBytes = args.ArchiveText is null ? null : Encoding.Unicode.GetBytes(args.ArchiveText);

        var manager = Marshal.AllocHGlobal(ManagerSize);
        try
        {
            Zero(manager, ManagerSize);
            GetDelegate<ManagerCtor>(module, RvaManagerCtor)(manager);

            var managerCore = manager + DripHolderOffset;
            WithPinned(bootstrapBytes, bootstrapPtr =>
            WithPinned(paramsBytes, paramsPtr =>
            {
                var ok = GetDelegate<BootstrapDerive>(module, RvaBootstrapDerive)(
                    managerCore,
                    bootstrapPtr,
                    (nuint)bootstrapBytes.Length,
                    paramsPtr,
                    (nuint)paramsBytes.Length);
                if (ok == 0)
                {
                    throw new InvalidOperationException("sub_10015630 failed; check bootstrap text and PARAMS length");
                }
            }));

            var hashKey = DeriveHashKey(module, manager);

            if (archiveNameBytes is not null)
            {
                WithPinned(archiveNameBytes, archivePtr =>
                WithPinned(seed, seedPtr =>
                {
                    GetDelegate<ArchiveDerive>(module, RvaArchiveDerive)(
                        managerCore,
                        archivePtr,
                        (nuint)archiveNameBytes.Length,
                        seedPtr);
                }));
            }

            var payload = BuildPayload(module, dllPath, manager, hashKey);
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            };

            var outPath = Path.GetFullPath(args.OutputPath);
            Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
            File.WriteAllText(outPath, JsonSerializer.Serialize(payload, options), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            Console.WriteLine($"wrote {outPath}");
            Console.WriteLine($"dll unique: {unique}");
            Console.WriteLine($"bootstrap bytes: {bootstrapBytes.Length}");
            Console.WriteLine($"archive update: {(archiveNameBytes is null ? "not applied" : args.ArchiveText)}");
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(manager);
        }
    }

    private static byte[] BuildBootstrapBytes(Args args, string unique, string warning)
    {
        if (args.BootstrapHex is not null)
        {
            return ParseHex(args.BootstrapHex);
        }

        if (args.BootstrapText is not null)
        {
            return Encoding.Unicode.GetBytes(args.BootstrapText);
        }

        var prefix = args.BootstrapPrefix ?? unique;
        var suffix = args.BootstrapSuffix;
        if (suffix is null && !args.NoDefaultWarning)
        {
            suffix = warning;
        }
        return Encoding.Unicode.GetBytes(prefix + (suffix ?? ""));
    }

    private static Payload BuildPayload(nint module, string dllPath, nint manager, byte[] hashKey)
    {
        var managerVa = (uint)manager;
        var dripImpl = ReadU32(manager + DripHolderOffset);
        if (dripImpl == 0)
        {
            throw new InvalidOperationException("DripValueImpl pointer is null after bootstrap derivation");
        }

        var context = manager + ContextOffset;
        var contextSize = ManagerSize - ContextOffset;
        var lanes = new List<LanePayload>(LaneCount);

        for (var laneIndex = 0; laneIndex < LaneCount; laneIndex++)
        {
            var lane = (nint)(dripImpl + DripLaneBaseOffset + laneIndex * LaneSize);
            var begin = ReadU32(lane);
            var end = ReadU32(lane + 4);
            var current = ReadU32(lane + 8);
            var ctx = ReadU32(lane + 12);

            if (end < begin || ((end - begin) % 8) != 0)
            {
                throw new InvalidOperationException($"lane {laneIndex} has invalid record range 0x{begin:x8}..0x{end:x8}");
            }

            var records = new List<uint[]>(checked((int)((end - begin) / 8)));
            for (var record = begin; record < end; record += 8)
            {
                var param = ReadU32((nint)record);
                var callback = ReadU32((nint)(record + 4));
                var callbackRva = callback >= (uint)module && callback < (uint)module + 0x200000
                    ? callback - (uint)module
                    : callback;
                records.Add([param, callbackRva]);
            }

            lanes.Add(new LanePayload
            {
                Index = laneIndex,
                BeginVa = begin,
                EndVa = end,
                CurrentVa = current,
                CtxVa = ctx,
                Records = records,
            });
        }

        return new Payload
        {
            Version = 1,
            SourceModule = Path.GetFileName(dllPath),
            SourceModuleBase = (uint)module,
            ManagerVa = managerVa,
            DripImplVa = dripImpl,
            Hxv4Key = ToHex(ReadBytes(manager + DripHolderOffset + 0x3038, 32)),
            Hxv4Nonce0 = ToHex(ReadBytes(manager + DripHolderOffset + 0x3078, 24)),
            Hxv4Nonce1 = ToHex(ReadBytes(manager + DripHolderOffset + 0x3058, 24)),
            HashKey = ToHex(hashKey),
            HolderWords = ReadU32List(manager + DripHolderOffset, 6),
            ContextVa = (uint)context,
            ContextU32 = ReadU32List(context, contextSize / 4),
            CallbackRvaBase = (uint)module,
            Lanes = lanes,
        };
    }

    private static byte[] DeriveHashKey(nint module, nint manager)
    {
        var outBytes = new byte[32];
        if ((ReadU32(manager + 0x30A0) & 3) != 3)
        {
            return outBytes;
        }

        WithPinned(outBytes, outPtr =>
        {
            GetDelegate<HashKeyDerive>(module, RvaHashKeyDerive)(
                outPtr,
                (nuint)outBytes.Length,
                manager + 0x3040,
                0x40,
                -1);
        });
        return outBytes;
    }

    private static Dictionary<string, byte[]> ReadConfigTable(nint ptr)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var cursor = ptr;
        while (true)
        {
            var label = ReadAsciiZ(cursor);
            if (label.Length == 0)
            {
                break;
            }

            cursor += label.Length + 1;
            var length = ReadU16(cursor);
            cursor += 2;
            result[label] = ReadBytes(cursor, length);
            cursor += length;
        }

        foreach (var key in new[] { "PARAMS", "UNIQUE", "WARNING" })
        {
            if (!result.ContainsKey(key))
            {
                throw new InvalidOperationException($"config table does not contain {key}");
            }
        }
        return result;
    }

    private static T GetDelegate<T>(nint module, int rva) where T : Delegate
    {
        return Marshal.GetDelegateForFunctionPointer<T>(module + rva);
    }

    private static void WithPinned(byte[] bytes, Action<nint> action)
    {
        var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            action(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    private static void Zero(nint ptr, int size)
    {
        unsafe
        {
            new Span<byte>((void*)ptr, size).Clear();
        }
    }

    private static ushort ReadU16(nint ptr)
    {
        unsafe
        {
            return BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>((void*)ptr, 2));
        }
    }

    private static uint ReadU32(nint ptr)
    {
        unsafe
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>((void*)ptr, 4));
        }
    }

    private static List<uint> ReadU32List(nint ptr, int count)
    {
        var values = new List<uint>(count);
        for (var index = 0; index < count; index++)
        {
            values.Add(ReadU32(ptr + index * 4));
        }
        return values;
    }

    private static byte[] ReadBytes(nint ptr, int size)
    {
        var data = new byte[size];
        Marshal.Copy(ptr, data, 0, size);
        return data;
    }

    private static string ReadAsciiZ(nint ptr)
    {
        var bytes = new List<byte>();
        var cursor = ptr;
        while (true)
        {
            var value = Marshal.ReadByte(cursor);
            if (value == 0)
            {
                break;
            }
            bytes.Add(value);
            cursor++;
        }
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private static string DecodeUtf16Le(byte[] data)
    {
        var end = data.Length;
        while (end >= 2 && data[end - 1] == 0 && data[end - 2] == 0)
        {
            end -= 2;
        }
        return Encoding.Unicode.GetString(data, 0, end);
    }

    private static string DecodeAscii(byte[] data)
    {
        var end = Array.IndexOf(data, (byte)0);
        if (end < 0)
        {
            end = data.Length;
        }
        return Encoding.ASCII.GetString(data, 0, end);
    }

    private static byte[] ParseHex(string text)
    {
        var clean = new string(text.Where(Uri.IsHexDigit).ToArray());
        if ((clean.Length & 1) != 0)
        {
            throw new ArgumentException($"hex string has odd length: {text}");
        }
        var bytes = new byte[clean.Length / 2];
        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = Convert.ToByte(clean.Substring(index * 2, 2), 16);
        }
        return bytes;
    }

    private static string ToHex(byte[] bytes)
    {
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private sealed class Args
    {
        public string? DllPath { get; private set; }
        public string? OutputPath { get; private set; }
        public string? BootstrapText { get; private set; }
        public string? BootstrapHex { get; private set; }
        public string? BootstrapPrefix { get; private set; }
        public string? BootstrapSuffix { get; private set; }
        public bool NoDefaultWarning { get; private set; }
        public string? ArchiveText { get; private set; }
        public string? ArchiveSeedHex { get; private set; }
        public string? ParamsHex { get; private set; }
        public bool ShowHelp { get; private set; }

        public static Args Parse(string[] argv)
        {
            var args = new Args();
            for (var index = 0; index < argv.Length; index++)
            {
                var arg = argv[index];
                string Next()
                {
                    if (++index >= argv.Length)
                    {
                        throw new ArgumentException($"{arg} requires a value");
                    }
                    return argv[index];
                }

                switch (arg)
                {
                    case "-h":
                    case "--help":
                        args.ShowHelp = true;
                        break;
                    case "--dll":
                        args.DllPath = Next();
                        break;
                    case "--out":
                        args.OutputPath = Next();
                        break;
                    case "--bootstrap-text":
                        args.BootstrapText = Next();
                        break;
                    case "--bootstrap-hex":
                        args.BootstrapHex = Next();
                        break;
                    case "--bootstrap-prefix":
                        args.BootstrapPrefix = Next();
                        break;
                    case "--bootstrap-suffix":
                        args.BootstrapSuffix = Next();
                        break;
                    case "--no-default-warning":
                        args.NoDefaultWarning = true;
                        break;
                    case "--archive-text":
                        args.ArchiveText = Next();
                        break;
                    case "--archive-seed-hex":
                        args.ArchiveSeedHex = Next();
                        break;
                    case "--params-hex":
                        args.ParamsHex = Next();
                        break;
                    default:
                        throw new ArgumentException($"unknown argument: {arg}");
                }
            }

            if (args.BootstrapText is not null && args.BootstrapHex is not null)
            {
                throw new ArgumentException("use only one of --bootstrap-text and --bootstrap-hex");
            }
            return args;
        }

        public static void PrintHelp()
        {
            Console.WriteLine("""
            Derive a random-DLL FilterManager Drip program without a game minidump.

            Required:
              --dll <path>                 x86 random DLL, e.g. 9bd81f525ace.dll
              --out <path>                 output drip_program.json path

            Bootstrap input:
              --bootstrap-text <text>      exact final TJS string for sub_10015630
              --bootstrap-hex <hex>        exact UTF-16LE/raw bytes for sub_10015630
              --bootstrap-prefix <text>    prefix text; defaults to DLL UNIQUE
              --bootstrap-suffix <text>    suffix text; defaults to DLL WARNING
              --no-default-warning         use empty suffix when no suffix is specified

            Optional archive key update:
              --archive-text <text>        call sub_100157D0 with this UTF-16LE text
              --archive-seed-hex <hex>     override 8-byte archive seed; defaults to DLL seed

            Optional overrides:
              --params-hex <hex>           override DLL PARAMS block
            """);
        }
    }

    private sealed class Payload
    {
        [JsonPropertyName("version")]
        public int Version { get; set; }
        [JsonPropertyName("source_module")]
        public string SourceModule { get; set; } = "";
        [JsonPropertyName("source_module_base")]
        public uint SourceModuleBase { get; set; }
        [JsonPropertyName("manager_va")]
        public uint ManagerVa { get; set; }
        [JsonPropertyName("drip_impl_va")]
        public uint DripImplVa { get; set; }
        [JsonPropertyName("hxv4_key")]
        public string Hxv4Key { get; set; } = "";
        [JsonPropertyName("hxv4_nonce0")]
        public string Hxv4Nonce0 { get; set; } = "";
        [JsonPropertyName("hxv4_nonce1")]
        public string Hxv4Nonce1 { get; set; } = "";
        [JsonPropertyName("hash_key")]
        public string HashKey { get; set; } = "";
        [JsonPropertyName("holder_words")]
        public List<uint> HolderWords { get; set; } = [];
        [JsonPropertyName("context_va")]
        public uint ContextVa { get; set; }
        [JsonPropertyName("context_u32")]
        public List<uint> ContextU32 { get; set; } = [];
        [JsonPropertyName("callback_rva_base")]
        public uint CallbackRvaBase { get; set; }
        [JsonPropertyName("lanes")]
        public List<LanePayload> Lanes { get; set; } = [];
    }

    private sealed class LanePayload
    {
        [JsonPropertyName("index")]
        public int Index { get; set; }
        [JsonPropertyName("begin_va")]
        public uint BeginVa { get; set; }
        [JsonPropertyName("end_va")]
        public uint EndVa { get; set; }
        [JsonPropertyName("current_va")]
        public uint CurrentVa { get; set; }
        [JsonPropertyName("ctx_va")]
        public uint CtxVa { get; set; }
        [JsonPropertyName("records")]
        public List<uint[]> Records { get; set; } = [];
    }

    private static class Native
    {
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern nint LoadLibraryW(string path);
    }
}
