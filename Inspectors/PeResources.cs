using System.Reflection.PortableExecutable;
using System.Text;

namespace BinaryExplorer.Inspectors;

public sealed record ResourceEntry(
    string TypeDisplay,
    int? TypeId,
    string? TypeString,
    string NameDisplay,
    int? NameId,
    string? NameString,
    uint Language,
    int FileOffset,
    int Size,
    uint CodePage);

public static class PeResources
{
    private static readonly Dictionary<int, string> RtNames = new()
    {
        [1] = "RT_CURSOR",       [2] = "RT_BITMAP",
        [3] = "RT_ICON",         [4] = "RT_MENU",
        [5] = "RT_DIALOG",       [6] = "RT_STRING",
        [7] = "RT_FONTDIR",      [8] = "RT_FONT",
        [9] = "RT_ACCELERATOR",  [10] = "RT_RCDATA",
        [11] = "RT_MESSAGETABLE",[12] = "RT_GROUP_CURSOR",
        [14] = "RT_GROUP_ICON",  [16] = "RT_VERSION",
        [17] = "RT_DLGINCLUDE",  [19] = "RT_PLUGPLAY",
        [20] = "RT_VXD",         [21] = "RT_ANICURSOR",
        [22] = "RT_ANIICON",     [23] = "RT_HTML",
        [24] = "RT_MANIFEST",
    };

    public static List<ResourceEntry> Walk(byte[] bytes)
    {
        var result = new List<ResourceEntry>();
        try
        {
            using var ms = new MemoryStream(bytes, writable: false);
            using var pe = new PEReader(ms);
            var dir = pe.PEHeaders.PEHeader?.ResourceTableDirectory;
            if (dir is null || dir.Value.Size == 0) return result;
            if (!LanguageInspector.TryRvaToOffset(pe, dir.Value.RelativeVirtualAddress, out int baseOffset))
                return result;

            WalkDirectory(bytes, pe, baseOffset, baseOffset, level: 0,
                typeId: null, typeStr: null,
                nameId: null, nameStr: null,
                result);
            result.Sort((a, b) =>
            {
                int c = string.Compare(a.TypeDisplay, b.TypeDisplay, StringComparison.Ordinal);
                if (c != 0) return c;
                c = string.Compare(a.NameDisplay, b.NameDisplay, StringComparison.Ordinal);
                if (c != 0) return c;
                return a.Language.CompareTo(b.Language);
            });
        }
        catch { /* best effort */ }
        return result;
    }

    private static void WalkDirectory(
        byte[] bytes,
        PEReader pe,
        int resBase,
        int dirOffset,
        int level,
        int? typeId, string? typeStr,
        int? nameId, string? nameStr,
        List<ResourceEntry> sink)
    {
        if (dirOffset + 16 > bytes.Length) return;
        ushort namedCount = BitConverter.ToUInt16(bytes, dirOffset + 12);
        ushort idCount    = BitConverter.ToUInt16(bytes, dirOffset + 14);
        int entriesStart  = dirOffset + 16;
        int totalEntries  = namedCount + idCount;

        for (int i = 0; i < totalEntries; i++)
        {
            int entryOff = entriesStart + i * 8;
            if (entryOff + 8 > bytes.Length) return;
            uint nameField = BitConverter.ToUInt32(bytes, entryOff);
            uint dataField = BitConverter.ToUInt32(bytes, entryOff + 4);

            string? nodeStr = null;
            int? nodeId = null;
            if ((nameField & 0x80000000) != 0)
            {
                int strOff = resBase + (int)(nameField & 0x7FFFFFFF);
                if (strOff + 2 > bytes.Length) continue;
                ushort len = BitConverter.ToUInt16(bytes, strOff);
                if (strOff + 2 + len * 2 > bytes.Length) continue;
                nodeStr = Encoding.Unicode.GetString(bytes, strOff + 2, len * 2);
            }
            else
            {
                nodeId = (int)nameField;
            }

            bool isSubdir = (dataField & 0x80000000) != 0;
            if (isSubdir)
            {
                int childOff = resBase + (int)(dataField & 0x7FFFFFFF);
                if (level == 0)
                {
                    WalkDirectory(bytes, pe, resBase, childOff, level + 1,
                        typeId: nodeId, typeStr: nodeStr,
                        nameId: null, nameStr: null,
                        sink);
                }
                else if (level == 1)
                {
                    WalkDirectory(bytes, pe, resBase, childOff, level + 1,
                        typeId: typeId, typeStr: typeStr,
                        nameId: nodeId, nameStr: nodeStr,
                        sink);
                }
                // level 2 is languages, level 3 is data; we stop here.
            }
            else
            {
                // Leaf at level 2 (language)
                int leafOff = resBase + (int)dataField;
                if (leafOff + 16 > bytes.Length) continue;
                uint dataRva = BitConverter.ToUInt32(bytes, leafOff);
                uint size    = BitConverter.ToUInt32(bytes, leafOff + 4);
                uint codePage = BitConverter.ToUInt32(bytes, leafOff + 8);

                if (!LanguageInspector.TryRvaToOffset(pe, (int)dataRva, out int fileOff)) continue;
                if (fileOff + size > bytes.Length) continue;

                uint lang = (uint)(nodeId ?? 0);
                string typeDisplay = typeStr ?? (typeId is int tid
                    ? (RtNames.TryGetValue(tid, out var n) ? n : $"Type {tid}")
                    : "?");
                string nameDisplay = nameStr ?? (nameId is int nid ? "#" + nid : "?");

                sink.Add(new ResourceEntry(
                    typeDisplay, typeId, typeStr,
                    nameDisplay, nameId, nameStr,
                    lang, fileOff, (int)size, codePage));
            }
        }
    }
}
