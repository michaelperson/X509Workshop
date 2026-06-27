using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// =============================================================================
//  Module 2 — Client console présentant son certificat (mTLS)
//  Génère un certificat client éphémère (EKU « Client Authentication »),
//  l'injecte dans le HttpClientHandler et appelle l'API sécurisée.
// =============================================================================

// 1. Certificat client éphémère attendu par le serveur -----------------------
using RSA clientRsa = RSA.Create(2048);
var request = new CertificateRequest(
    "CN=MonClientAutorise",
    clientRsa,
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);

// EKU « Client Authentication » (1.3.6.1.5.5.7.3.2)
request.CertificateExtensions.Add(
    new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], critical: false));

using X509Certificate2 clientCert = request.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddDays(-1),
    DateTimeOffset.UtcNow.AddDays(1));
using X509Certificate2 clientCertWithKey = clientCert.CopyWithPrivateKey(clientRsa);

// 2. Injection du certificat dans le handler HTTP ----------------------------
var handler = new HttpClientHandler();
handler.ClientCertificates.Add(clientCertWithKey);

// Labo éphémère uniquement : on accepte n'importe quel certificat SERVEUR.
// NE JAMAIS faire ceci en production.
handler.ServerCertificateCustomValidationCallback =
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

using var client = new HttpClient(handler);

Console.WriteLine("Appel de l'API sécurisée en mTLS...");
try
{
    var response = await client.GetStringAsync("https://localhost:5001/api/secure-data");
    Console.WriteLine($"Réponse du serveur : {response}");
}
catch (Exception ex)
{
    Console.WriteLine($"Échec de la connexion : {ex.Message}");
}
