using System.Reflection.PortableExecutable;
using System.Text;

namespace BinaryExplorer.Mcp;

// Standalone copy of the imports reader (no dependency on the WinUI3 project).
internal static class PeImportsRaw
{
    public sealed record DllImports(string Dll, List<string> Functions, List<int> Ordinals);

    public static List<DllImports> Read(PEReader pe, byte[] bytes, out bool pe32Plus)
    {
        pe32Plus = pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus;
        int thunkSize = pe32Plus ? 8 : 4;
        ulong ordinalFlag = pe32Plus ? 0x8000000000000000UL : 0x80000000UL;

        var result = new List<DllImports>();
        var dir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return result;

        if (!TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int offset))
            return result;

        while (offset + 20 <= bytes.Length)
        {
            uint origFirstThunk = BitConverter.ToUInt32(bytes, offset);
            uint nameRva = BitConverter.ToUInt32(bytes, offset + 12);
            uint firstThunk = BitConverter.ToUInt32(bytes, offset + 16);
            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            var rec = new DllImports("", new List<string>(), new List<int>());
            if (nameRva != 0 && TryRvaToOffset(pe, (int)nameRva, out int nameOff))
                rec = rec with { Dll = ReadAsciiZ(bytes, nameOff) };

            uint thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            if (thunkRva != 0 && TryRvaToOffset(pe, (int)thunkRva, out int thunkOff))
                ReadThunkArray(pe, bytes, thunkOff, thunkSize, ordinalFlag, rec.Functions, rec.Ordinals);

            result.Add(rec);
            offset += 20;
        }
        return result;
    }

    private static void ReadThunkArray(PEReader pe, byte[] bytes, int offset,
        int thunkSize, ulong ordinalFlag, List<string> functions, List<int> ordinals)
    {
        while (offset + thunkSize <= bytes.Length)
        {
            ulong thunk = thunkSize == 8
                ? BitConverter.ToUInt64(bytes, offset)
                : BitConverter.ToUInt32(bytes, offset);
            if (thunk == 0) break;
            offset += thunkSize;

            if ((thunk & ordinalFlag) != 0)
            {
                ordinals.Add((int)(thunk & 0xFFFF));
            }
            else
            {
                int hintNameRva = (int)(thunk & 0x7FFFFFFF);
                if (TryRvaToOffset(pe, hintNameRva, out int hnOff) && hnOff + 2 < bytes.Length)
                {
                    string name = ReadAsciiZ(bytes, hnOff + 2);
                    if (name.Length > 0) functions.Add(name);
                }
            }
        }
    }

    public static bool TryRvaToOffset(PEReader pe, int rva, out int offset)
    {
        foreach (var s in pe.PEHeaders.SectionHeaders)
        {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize)
            {
                offset = s.PointerToRawData + (rva - s.VirtualAddress);
                return true;
            }
        }
        offset = 0;
        return false;
    }

    private static string ReadAsciiZ(byte[] bytes, int offset)
    {
        int end = offset;
        while (end < bytes.Length && bytes[end] != 0) end++;
        if (end == offset) return "";
        return Encoding.ASCII.GetString(bytes, offset, end - offset);
    }
}
