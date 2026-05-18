using System.IO;

namespace BinaryExplorer.Core;

public sealed class BinaryContext
{
    public string Path { get; }
    public byte[] Bytes { get; }
    public long Length => Bytes.LongLength;

    public BinaryContext(string path)
    {
        Path = path;
        Bytes = File.ReadAllBytes(path);
    }

    public MemoryStream OpenStream() => new MemoryStream(Bytes, writable: false);
}
