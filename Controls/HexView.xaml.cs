using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace BinaryExplorer.Controls;

public sealed partial class HexView : UserControl
{
    public HexView()
    {
        InitializeComponent();
    }

    public static readonly DependencyProperty BytesProperty =
        DependencyProperty.Register(nameof(Bytes), typeof(byte[]), typeof(HexView),
            new PropertyMetadata(null, (d, _) => ((HexView)d).Rebuild()));

    public byte[]? Bytes
    {
        get => (byte[]?)GetValue(BytesProperty);
        set => SetValue(BytesProperty, value);
    }

    public static readonly DependencyProperty BaseOffsetProperty =
        DependencyProperty.Register(nameof(BaseOffset), typeof(long), typeof(HexView),
            new PropertyMetadata(0L, (d, _) => ((HexView)d).Rebuild()));

    /// <summary>Address shown in the gutter for the first byte of <see cref="Bytes"/>.</summary>
    public long BaseOffset
    {
        get => (long)GetValue(BaseOffsetProperty);
        set => SetValue(BaseOffsetProperty, value);
    }

    public static readonly DependencyProperty MaxBytesProperty =
        DependencyProperty.Register(nameof(MaxBytes), typeof(int), typeof(HexView),
            new PropertyMetadata(64 * 1024, (d, _) => ((HexView)d).Rebuild()));

    public int MaxBytes
    {
        get => (int)GetValue(MaxBytesProperty);
        set => SetValue(MaxBytesProperty, value);
    }

    public static readonly DependencyProperty SkipProperty =
        DependencyProperty.Register(nameof(Skip), typeof(int), typeof(HexView),
            new PropertyMetadata(0, (d, _) => ((HexView)d).Rebuild()));

    /// <summary>How many bytes from the start of <see cref="Bytes"/> to skip before rendering.</summary>
    public int Skip
    {
        get => (int)GetValue(SkipProperty);
        set => SetValue(SkipProperty, value);
    }

    private void Rebuild()
    {
        var bytes = Bytes;
        if (bytes is null || bytes.Length == 0)
        {
            DumpText.Text = "(no data)";
            return;
        }

        int skip = Math.Max(0, Math.Min(Skip, bytes.Length));
        int max = Math.Max(1, MaxBytes);
        int count = Math.Min(bytes.Length - skip, max);
        if (count <= 0)
        {
            DumpText.Text = "(skip exceeds available bytes)";
            return;
        }

        var sb = new StringBuilder(count * 4);
        long baseAddr = BaseOffset + skip;
        int rowSize = 16;
        for (int rowStart = 0; rowStart < count; rowStart += rowSize)
        {
            sb.Append((baseAddr + rowStart).ToString("X8"));
            sb.Append("  ");
            int rowEnd = Math.Min(rowStart + rowSize, count);
            for (int i = rowStart; i < rowStart + rowSize; i++)
            {
                if (i < rowEnd) sb.Append(bytes[skip + i].ToString("X2"));
                else sb.Append("  ");
                sb.Append(' ');
                if (i == rowStart + 7) sb.Append(' ');
            }
            sb.Append(' ');
            for (int i = rowStart; i < rowEnd; i++)
            {
                byte b = bytes[skip + i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }

        if (skip + count < bytes.Length)
        {
            sb.AppendLine();
            long remaining = bytes.Length - (long)skip - count;
            sb.Append($"... ({remaining:N0} more bytes, increase MaxBytes or page forward)");
        }

        DumpText.Text = sb.ToString();
    }
}
