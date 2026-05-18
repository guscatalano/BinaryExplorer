using System.ComponentModel;
using System.Reflection.Metadata;
using BinaryExplorer.Services;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace BinaryExplorer.Pages;

public sealed partial class DecompilePage : Page
{
    private CSharpDecompiler? _decompiler;
    private string? _loadedPath;
    private List<(ITypeDefinition Type, IReadOnlyList<IMethod> Methods)>? _allTypes;

    public DecompilePage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged += OnStateChanged;
        Refresh();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        AppState.Instance.PropertyChanged -= OnStateChanged;
    }

    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        DispatcherQueue.TryEnqueue(Refresh);
    }

    private void Refresh()
    {
        var ctx = AppState.Instance.Binary;
        if (ctx is null)
        {
            HeadlineText.Text = "No file loaded.";
            TypeTree.RootNodes.Clear();
            ShowStatus("Open a file on the Overview page first.");
            _decompiler = null;
            _loadedPath = null;
            _allTypes = null;
            return;
        }
        if (_loadedPath == ctx.Path) return;

        try
        {
            // Quick pre-check via BCL so we never call into ICSharpCode for native PEs (its
            // PEFile constructor throws MetadataFileNotSupportedException on non-managed files).
            using (var bclMs = new MemoryStream(ctx.Bytes, writable: false))
            using (var bclPe = new System.Reflection.PortableExecutable.PEReader(bclMs))
            {
                if (!bclPe.HasMetadata)
                {
                    HeadlineText.Text = "Not a managed (.NET) assembly.";
                    TypeTree.RootNodes.Clear();
                    ShowStatus("This binary has no CLR metadata, so there's nothing to decompile here. For native code, see the Disassembly page.");
                    _decompiler = null;
                    _loadedPath = ctx.Path;
                    _allTypes = null;
                    return;
                }
            }

            PEFile module;
            try
            {
                module = new PEFile(ctx.Path);
            }
            catch (ICSharpCode.Decompiler.Metadata.MetadataFileNotSupportedException)
            {
                HeadlineText.Text = "Not a managed (.NET) assembly.";
                TypeTree.RootNodes.Clear();
                ShowStatus("ICSharpCode.Decompiler couldn't parse managed metadata from this file. For native code, see the Disassembly page.");
                _decompiler = null;
                _loadedPath = ctx.Path;
                _allTypes = null;
                return;
            }
            // Tolerant resolver: skip references we can't find on disk instead of throwing.
            var resolver = new UniversalAssemblyResolver(
                ctx.Path,
                throwOnError: false,
                targetFramework: module.DetectTargetFrameworkId(),
                runtimePack: module.DetectRuntimePack());
            _decompiler = new CSharpDecompiler(module, resolver, new DecompilerSettings());
            _loadedPath = ctx.Path;
            _allTypes = _decompiler.TypeSystem.MainModule.TypeDefinitions
                .Select(t => ((ITypeDefinition)t, (IReadOnlyList<IMethod>)t.Methods.ToList()))
                .ToList();
            HeadlineText.Text = $"{System.IO.Path.GetFileName(ctx.Path)} — click a method to decompile";
            BuildTree("");
            ShowStatus("Pick a method on the left to decompile.");
        }
        catch (Exception ex)
        {
            HeadlineText.Text = "Decompiler failed to load";
            ShowStatus(ex.ToString());
            _decompiler = null;
            _loadedPath = null;
            _allTypes = null;
        }
    }

    private void BuildTree(string filter)
    {
        TypeTree.RootNodes.Clear();
        if (_allTypes is null) return;

        bool Match(string s) => filter.Length == 0 || s.Contains(filter, StringComparison.OrdinalIgnoreCase);

        var nsGroups = _allTypes
            .GroupBy(p => string.IsNullOrEmpty(p.Type.Namespace) ? "<global>" : p.Type.Namespace)
            .OrderBy(g => g.Key, StringComparer.Ordinal);

        foreach (var grp in nsGroups)
        {
            bool nsMatch = Match(grp.Key);
            var nsNode = new TreeViewNode
            {
                Content = new DecompileNode(grp.Key, NodeKind.Namespace, default),
                IsExpanded = filter.Length > 0 || grp.Key == "<global>"
            };
            bool typeAdded = false;
            foreach (var (type, methods) in grp.OrderBy(p => p.Type.Name, StringComparer.Ordinal))
            {
                string typeLabel = FormatTypeLabel(type);
                var matchingMethods = methods.Where(m => Match(FormatMethodLabel(m))).ToList();
                bool typeNameMatch = Match(typeLabel);
                bool keepType = nsMatch || typeNameMatch || matchingMethods.Count > 0;
                if (!keepType) continue;

                var tNode = new TreeViewNode
                {
                    Content = new DecompileNode(typeLabel, NodeKind.Type, type.MetadataToken),
                    IsExpanded = filter.Length > 0 && (matchingMethods.Count > 0 || typeNameMatch),
                };
                var methodsToShow = (nsMatch || typeNameMatch) ? methods.ToList() : matchingMethods;
                foreach (var m in methodsToShow.OrderBy(m => m.Name, StringComparer.Ordinal))
                {
                    tNode.Children.Add(new TreeViewNode
                    {
                        Content = new DecompileNode(FormatMethodLabel(m), NodeKind.Method, m.MetadataToken),
                    });
                }
                nsNode.Children.Add(tNode);
                typeAdded = true;
            }
            if (typeAdded) TypeTree.RootNodes.Add(nsNode);
        }
    }

    private static string FormatTypeLabel(ITypeDefinition t)
    {
        if (t.TypeParameterCount > 0)
            return $"{t.Name}<{string.Join(",", t.TypeParameters.Select(p => p.Name))}>";
        return t.Name;
    }

    private static string FormatMethodLabel(IMethod m)
    {
        var args = string.Join(", ", m.Parameters.Select(p => p.Type.Name));
        return $"{m.Name}({args}) : {m.ReturnType.Name}";
    }

    private async void TypeTree_ItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
    {
        if (args.InvokedItem is not TreeViewNode node) return;
        if (node.Content is not DecompileNode dn) return;
        if (_decompiler is null) return;

        if (dn.Kind == NodeKind.Namespace) return;

        try
        {
            ShowCode("// Decompiling...");
            string code = await Task.Run(() => _decompiler.DecompileAsString(dn.Token));
            ShowCode(code);
        }
        catch (Exception ex)
        {
            ShowCode($"// Decompilation failed:\n// {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void TypeFilter_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
        BuildTree(sender.Text?.Trim() ?? "");
    }

    private void ShowStatus(string message)
    {
        StatusText.Text = message;
        StatusText.Visibility = Visibility.Visible;
        CodeScroller.Visibility = Visibility.Collapsed;
    }

    private void ShowCode(string code)
    {
        CodeBox.Text = code;
        StatusText.Visibility = Visibility.Collapsed;
        CodeScroller.Visibility = Visibility.Visible;
    }

    private enum NodeKind { Namespace, Type, Method }
    private sealed class DecompileNode
    {
        public string Label { get; }
        public NodeKind Kind { get; }
        public EntityHandle Token { get; }
        public DecompileNode(string label, NodeKind kind, EntityHandle token)
        {
            Label = label; Kind = kind; Token = token;
        }
        public override string ToString() => Label;
    }
}
