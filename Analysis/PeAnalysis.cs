using System.Reflection.PortableExecutable;
using BinaryExplorer.Core;
using BinaryExplorer.Inspectors;
using Iced.Intel;

namespace BinaryExplorer.Analysis;

public static class PeAnalysis
{
    public static AnalysisIndex Analyze(BinaryContext ctx)
    {
        using var ms = new MemoryStream(ctx.Bytes, writable: false);
        using var pe = new PEReader(ms);
        var opt = pe.PEHeaders.PEHeader;
        if (opt is null) return new AnalysisIndex { Supported = false };

        var machine = pe.PEHeaders.CoffHeader.Machine;
        if (machine != Machine.Amd64 && machine != Machine.I386)
            return new AnalysisIndex { Supported = false };

        int bitness = (opt.Magic == PEMagic.PE32Plus) ? 64 : 32;
        ulong imageBase = opt.ImageBase;
        var idx = new AnalysisIndex
        {
            Bitness = bitness,
            ImageBase = imageBase,
            Supported = true,
        };

        // Seed: entry point.
        if (opt.AddressOfEntryPoint != 0)
            idx.AddOrUpgrade(new FunctionInfo((uint)opt.AddressOfEntryPoint, "entry", true,
                FindSection(pe, (uint)opt.AddressOfEntryPoint)));

        // Seed: named exports.
        foreach (var (name, rva) in ReadExports(ctx.Bytes, pe))
            idx.AddOrUpgrade(new FunctionInfo(rva, name, true, FindSection(pe, rva)));

        // Seed: TLS callbacks.
        var tlsDir = opt.ThreadLocalStorageTableDirectory;
        if (tlsDir.Size != 0
            && LanguageInspector.TryRvaToOffset(pe, tlsDir.RelativeVirtualAddress, out int tlsOff))
        {
            int ptrSize = bitness == 64 ? 8 : 4;
            int cbPtrFieldOff = tlsOff + ptrSize * 3;
            if (cbPtrFieldOff + ptrSize <= ctx.Bytes.Length)
            {
                ulong cbVa = ptrSize == 8
                    ? BitConverter.ToUInt64(ctx.Bytes, cbPtrFieldOff)
                    : BitConverter.ToUInt32(ctx.Bytes, cbPtrFieldOff);
                if (cbVa >= imageBase)
                {
                    int cbRva = (int)(cbVa - imageBase);
                    if (LanguageInspector.TryRvaToOffset(pe, cbRva, out int cbOff))
                    {
                        int cbIdx = 0;
                        while (cbOff + ptrSize <= ctx.Bytes.Length && cbIdx < 32)
                        {
                            ulong fnVa = ptrSize == 8
                                ? BitConverter.ToUInt64(ctx.Bytes, cbOff)
                                : BitConverter.ToUInt32(ctx.Bytes, cbOff);
                            if (fnVa == 0) break;
                            long fnRva = (long)fnVa - (long)imageBase;
                            if (fnRva > 0 && fnRva < int.MaxValue)
                                idx.AddOrUpgrade(new FunctionInfo((uint)fnRva, $"tls_cb_{cbIdx}", true,
                                    FindSection(pe, (uint)fnRva)));
                            cbOff += ptrSize;
                            cbIdx++;
                        }
                    }
                }
            }
        }

        // Linear sweep of every executable section, collecting call targets.
        foreach (var sec in pe.PEHeaders.SectionHeaders)
        {
            if ((sec.SectionCharacteristics & SectionCharacteristics.MemExecute) == 0) continue;
            int off = sec.PointerToRawData;
            int size = sec.SizeOfRawData;
            if (off <= 0 || size <= 0 || off + size > ctx.Bytes.Length) continue;

            var reader = new ByteArrayCodeReader(ctx.Bytes, off, size);
            var decoder = Iced.Intel.Decoder.Create(bitness, reader);
            ulong startVa = imageBase + (ulong)sec.VirtualAddress;
            decoder.IP = startVa;
            ulong endVa = startVa + (ulong)size;

            while (decoder.IP < endVa)
            {
                ulong ip = decoder.IP;
                decoder.Decode(out var instr);
                if (instr.IsInvalid) continue;

                // Track call/jmp targets.
                if (instr.IsCallNear)
                {
                    ulong target = instr.NearBranch64;
                    if (target >= imageBase && target < imageBase + (ulong)int.MaxValue)
                    {
                        uint targetRva = (uint)(target - imageBase);
                        if (RvaInExecutableSection(pe, targetRva))
                        {
                            idx.AddOrUpgrade(new FunctionInfo(targetRva, $"sub_{target:X}", false,
                                FindSection(pe, targetRva)));
                            idx.AddXref(target, ip);
                        }
                    }
                }
                else if (instr.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
                         && (instr.IsJmpNear || instr.IsJmpShort || instr.IsJccNear || instr.IsJccShort))
                {
                    // Jumps within the same function are common; only record xrefs.
                    ulong target = instr.NearBranch64;
                    if (target >= imageBase && target < imageBase + (ulong)int.MaxValue)
                        idx.AddXref(target, ip);
                }
            }
        }

        idx.SortByRva();
        return idx;
    }

    private static string? FindSection(PEReader pe, uint rva)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize)
                return s.Name;
        }
        return null;
    }

    private static bool RvaInExecutableSection(PEReader pe, uint rva)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            if ((s.SectionCharacteristics & SectionCharacteristics.MemExecute) == 0) continue;
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize) return true;
        }
        return false;
    }

    private static IEnumerable<(string Name, uint Rva)> ReadExports(byte[] bytes, PEReader pe)
    {
        var dir = pe.PEHeaders.PEHeader?.ExportTableDirectory;
        if (dir is null || dir.Value.Size == 0) yield break;
        if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int exportOff)) yield break;

        uint numberOfNames = BitConverter.ToUInt32(bytes, exportOff + 24);
        uint addressOfFunctions = BitConverter.ToUInt32(bytes, exportOff + 28);
        uint addressOfNames = BitConverter.ToUInt32(bytes, exportOff + 32);
        uint addressOfNameOrdinals = BitConverter.ToUInt32(bytes, exportOff + 36);

        if (!LanguageInspector.TryRvaToOffset(pe, (int)addressOfNames, out int nameTableOff)) yield break;
        if (!LanguageInspector.TryRvaToOffset(pe, (int)addressOfNameOrdinals, out int ordTableOff)) yield break;
        if (!LanguageInspector.TryRvaToOffset(pe, (int)addressOfFunctions, out int fnTableOff)) yield break;

        for (int i = 0; i < numberOfNames && i < 8192; i++)
        {
            int nameRvaOff = nameTableOff + i * 4;
            if (nameRvaOff + 4 > bytes.Length) yield break;
            uint nameRva = BitConverter.ToUInt32(bytes, nameRvaOff);
            if (!LanguageInspector.TryRvaToOffset(pe, (int)nameRva, out int nOff)) continue;
            int end = nOff;
            while (end < bytes.Length && bytes[end] != 0) end++;
            string fnName = System.Text.Encoding.ASCII.GetString(bytes, nOff, end - nOff);

            int ordOff = ordTableOff + i * 2;
            if (ordOff + 2 > bytes.Length) continue;
            ushort ord = BitConverter.ToUInt16(bytes, ordOff);
            int fnRvaOff = fnTableOff + ord * 4;
            if (fnRvaOff + 4 > bytes.Length) continue;
            uint fnRva = BitConverter.ToUInt32(bytes, fnRvaOff);
            if (fnRva == 0) continue;
            yield return (fnName, fnRva);
        }
    }
}
