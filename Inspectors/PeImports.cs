using System.Reflection.PortableExecutable;
using System.Text;

namespace BinaryExplorer.Inspectors;

public static class PeImports
{
    public sealed record DllImports(string Dll, List<string> Functions, List<int> Ordinals);

    public static List<DllImports> Read(PEReader pe, out bool pe32Plus)
    {
        pe32Plus = pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus;
        int thunkSize = pe32Plus ? 8 : 4;
        ulong ordinalFlag = pe32Plus ? 0x8000000000000000UL : 0x80000000UL;

        var imgImm = pe.GetEntireImage().GetContent();
        ReadOnlySpan<byte> image = imgImm.AsSpan();

        var result = new List<DllImports>();
        var dir = pe.PEHeaders.PEHeader?.ImportTableDirectory;
        if (dir is null || dir.Value.Size == 0) return result;

        if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int offset))
            return result;

        while (offset + 20 <= image.Length)
        {
            uint origFirstThunk = BitConverter.ToUInt32(image.Slice(offset, 4));
            uint nameRva = BitConverter.ToUInt32(image.Slice(offset + 12, 4));
            uint firstThunk = BitConverter.ToUInt32(image.Slice(offset + 16, 4));
            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            var rec = new DllImports("", new List<string>(), new List<int>());
            if (nameRva != 0 && LanguageInspector.TryRvaToOffset(pe, (int)nameRva, out int nameOff))
                rec = rec with { Dll = ReadAsciiZ(image, nameOff) };

            uint thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            if (thunkRva != 0 && LanguageInspector.TryRvaToOffset(pe, (int)thunkRva, out int thunkOff))
            {
                ReadThunkArray(pe, image, thunkOff, thunkSize, ordinalFlag, rec.Functions, rec.Ordinals);
            }

            result.Add(rec);
            offset += 20;
        }
        return result;
    }

    private static void ReadThunkArray(PEReader pe, ReadOnlySpan<byte> image, int offset,
        int thunkSize, ulong ordinalFlag, List<string> functions, List<int> ordinals)
    {
        while (offset + thunkSize <= image.Length)
        {
            ulong thunk = thunkSize == 8
                ? BitConverter.ToUInt64(image.Slice(offset, 8))
                : BitConverter.ToUInt32(image.Slice(offset, 4));
            if (thunk == 0) break;
            offset += thunkSize;

            if ((thunk & ordinalFlag) != 0)
            {
                ordinals.Add((int)(thunk & 0xFFFF));
            }
            else
            {
                int hintNameRva = (int)(thunk & 0x7FFFFFFF);
                if (LanguageInspector.TryRvaToOffset(pe, hintNameRva, out int hnOff) && hnOff + 2 < image.Length)
                {
                    string name = ReadAsciiZ(image, hnOff + 2);
                    if (name.Length > 0) functions.Add(name);
                }
            }
        }
    }

    private static string ReadAsciiZ(ReadOnlySpan<byte> image, int offset)
    {
        int end = offset;
        while (end < image.Length && image[end] != 0) end++;
        if (end == offset) return "";
        return Encoding.ASCII.GetString(image.Slice(offset, end - offset));
    }
}
