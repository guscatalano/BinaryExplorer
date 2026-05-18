using System.Security.Cryptography.X509Certificates;
using BinaryExplorer.Core;

namespace BinaryExplorer.Inspectors;

public sealed class SignatureInspector : IBinaryInspector
{
    public string Name => "Signature";

    public Task<InspectionResult> InspectAsync(BinaryContext context, CancellationToken ct = default)
    {
        return Task.Run<InspectionResult>(() =>
        {
            var findings = new List<Finding>();
            try
            {
                X509Certificate2? signer = null;
                try
                {
                    // CreateFromSignedFile returns the embedded signing cert from an Authenticode-signed file.
#pragma warning disable SYSLIB0057
                    var raw = X509Certificate.CreateFromSignedFile(context.Path);
                    signer = X509CertificateLoader.LoadCertificate(raw.GetRawCertData());
#pragma warning restore SYSLIB0057
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    return new InspectionResult
                    {
                        InspectorName = Name,
                        Headline = "Not signed (no embedded Authenticode certificate)",
                        Findings = Array.Empty<Finding>(),
                    };
                }

                findings.Add(new Finding("Subject", signer.Subject));
                findings.Add(new Finding("Issuer", signer.Issuer));
                findings.Add(new Finding("Serial", signer.SerialNumber ?? ""));
                findings.Add(new Finding("Thumbprint", signer.Thumbprint ?? ""));
                findings.Add(new Finding("NotBefore", signer.NotBefore.ToUniversalTime().ToString("u")));
                findings.Add(new Finding("NotAfter", signer.NotAfter.ToUniversalTime().ToString("u")));
                findings.Add(new Finding("SignatureAlgorithm", signer.SignatureAlgorithm.FriendlyName ?? signer.SignatureAlgorithm.Value ?? ""));
                findings.Add(new Finding("PublicKeyAlgorithm", signer.PublicKey.Oid.FriendlyName ?? signer.PublicKey.Oid.Value ?? ""));

                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                bool ok = chain.Build(signer);
                var severity = ok ? Severity.Info : Severity.Warning;
                var statusText = ok
                    ? "Chain built OK"
                    : string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation?.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)));
                findings.Add(new Finding("ChainStatus", ok ? "OK" : "Issues", statusText, severity));

                for (int i = 0; i < chain.ChainElements.Count; i++)
                {
                    var el = chain.ChainElements[i];
                    findings.Add(new Finding(
                        $"Chain[{i}]",
                        el.Certificate.Subject,
                        $"Issuer: {el.Certificate.Issuer}\nThumbprint: {el.Certificate.Thumbprint}\nNotAfter: {el.Certificate.NotAfter:u}"));
                }

                string commonName = ExtractCommonName(signer.Subject) ?? signer.Subject;
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = $"Signed by {commonName}",
                    Findings = findings,
                };
            }
            catch (Exception ex)
            {
                return new InspectionResult
                {
                    InspectorName = Name,
                    Headline = "Signature inspection failed",
                    Findings = findings,
                    Error = ex.Message,
                };
            }
        }, ct);
    }

    private static string? ExtractCommonName(string dn)
    {
        // DN form: "CN=Microsoft Corporation, O=..., L=..."
        foreach (var part in dn.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmed.Substring(3);
        }
        return null;
    }
}
