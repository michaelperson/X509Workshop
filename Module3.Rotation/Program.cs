using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// =============================================================================
//  Module 3 — Rotation « Zero-Downtime » du certificat serveur
//  Kestrel appelle ServerCertificateSelector à CHAQUE nouvelle connexion :
//  on peut donc remplacer le certificat en mémoire sans redémarrer le process.
// =============================================================================

var builder = WebApplication.CreateBuilder(args);

var certManager = new DynamicCertificateManager();
builder.Services.AddSingleton(certManager);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(5001, listenOptions =>
    {
        listenOptions.UseHttps(new HttpsConnectionAdapterOptions
        {
            // Appelé à chaque connexion : récupération instantanée du cert à jour.
            ServerCertificateSelector = (connectionContext, name) =>
                certManager.GetCurrentCertificate()
        });
    });
});

var app = builder.Build();

// Inspecter le certificat courant
app.MapGet("/api/cert-info", (DynamicCertificateManager manager) =>
{
    var cert = manager.GetCurrentCertificate();
    return new { cert.Thumbprint, cert.Subject, ValidTo = cert.NotAfter };
});

// Simuler une rotation (déclenchée par un cron, un webhook, cert-manager...)
app.MapPost("/api/rotate", (DynamicCertificateManager manager) =>
{
    manager.RotateCertificate();
    return Results.Ok("Certificat renouvelé à chaud avec succès !");
});

app.Run();

// -----------------------------------------------------------------------------
//  Gère la génération et la rotation du certificat en mémoire.
// -----------------------------------------------------------------------------
public sealed class DynamicCertificateManager
{
    private X509Certificate2 _currentCert;

    public DynamicCertificateManager() => _currentCert = GenerateNewCertificate();

    public X509Certificate2 GetCurrentCertificate() => _currentCert;

    public void RotateCertificate()
    {
        // Remplacement atomique de l'instance : les connexions en cours ne sont pas coupées.
        var previous = _currentCert;
        _currentCert = GenerateNewCertificate();
        previous.Dispose();
    }

    private static X509Certificate2 GenerateNewCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN=localhost-dynamic-{Guid.NewGuid().ToString()[..4]}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // EKU « Server Authentication »
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));

        // SAN localhost (requis par les clients TLS modernes)
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        // Important pour Kestrel : associer la clé privée.
        return cert.CopyWithPrivateKey(rsa);
    }
}
