using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Module1.Lab;

// =============================================================================
//  Module 1 — Génération éphémère 100% C# (.NET 10)
//  Objectif : créer une Root CA en mémoire, signer un certificat serveur,
//             puis le recharger via X509CertificateLoader (API .NET 10).
//  Aucun droit administrateur, aucune dépendance externe.
// =============================================================================
internal static class Program
{
    private static void Main()
    {
        Console.WriteLine("--- Génération éphémère 100% C# (.NET 10) ---");

        // 1. Autorité de Certification (Root CA) parente -----------------------
        using RSA caRsa = RSA.Create(4096);  
        var caRequest = new CertificateRequest(
            "CN=MonAutoriteLocaleRoot",
            caRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Contraintes de base : ce certificat EST une CA (peut signer d'autres certs)
        caRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        // Une CA doit pouvoir signer des certificats et des CRL
        caRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));

        using X509Certificate2 caCert = caRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));
        Console.WriteLine($"[CA]      Générée. Empreinte : {caCert.Thumbprint}");

        // 2. Certificat serveur enfant, signé par la CA -----------------------
        using RSA serverRsa = RSA.Create(2048);
        var serverRequest = new CertificateRequest(
            "CN=localhost",
            serverRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // EKU « Server Authentication » : sans cela, ASP.NET Core / les navigateurs rejettent le cert
        serverRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));

        // Subject Alternative Name (SAN) : obligatoire pour les clients TLS modernes
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        serverRequest.CertificateExtensions.Add(sanBuilder.Build());

        // Numéro de série aléatoire (unicité)
        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);

        using X509Certificate2 serverCert = serverRequest.Create(
            caCert,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30),
            serialNumber);

        // ÉTAPE CRUCIALE : Create() ne renvoie QUE la clé publique.
        // On associe la clé privée pour obtenir un certificat utilisable par Kestrel.
        using X509Certificate2 serverCertWithKey = serverCert.CopyWithPrivateKey(serverRsa);
        Console.WriteLine($"[SERVEUR] Certificat signé par la CA. Subject : {serverCertWithKey.Subject}");

        // 3. Export PFX puis rechargement via l'API .NET 10 -------------------
        const string pfxPassword = "MotDePasseSecurise";
        byte[] pfxBytes = serverCertWithKey.Export(X509ContentType.Pfx, pfxPassword);

        // X509CertificateLoader remplace systématiquement new X509Certificate2(...)
        // (immuable, thread-safe, allocations quasi nulles)
        using X509Certificate2 loadedCert = X509CertificateLoader.LoadPkcs12(pfxBytes, pfxPassword);
        Console.WriteLine($"[LOADER]  Certificat rechargé. Subject : {loadedCert.Subject}");
        Console.WriteLine($"[LOADER]  Clé privée présente : {loadedCert.HasPrivateKey}");
    }
}
