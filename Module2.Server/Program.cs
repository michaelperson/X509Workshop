using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// =============================================================================
//  Module 2 — Serveur API exigeant un certificat client (mTLS)
//  Écoute en HTTPS sur https://localhost:5001 et refuse toute connexion
//  qui ne présente pas un certificat client dont le CN contient
//  « MonClientAutorise ».
// =============================================================================

var builder = WebApplication.CreateBuilder(args);

// 1. Authentification par certificat -----------------------------------------
builder.Services
    .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        // Labo éphémère : on accepte les certificats auto-signés.
        options.AllowedCertificateTypes = CertificateTypes.All;
        // Pas de vérification de révocation (CRL/OCSP) pour des certs éphémères locaux.
        options.RevocationMode = X509RevocationMode.NoCheck;

        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                // Autorisation applicative : on vérifie l'identité (CN / Thumbprint).
                if (context.ClientCertificate.Subject.Contains("MonClientAutorise"))
                {
                    context.Success();
                }
                else
                {
                    context.Fail("Certificat valide, mais identité non autorisée.");
                }
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// 2. Kestrel : exiger le certificat client (mTLS) ----------------------------
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(5001, listenOptions =>
    {
        // Certificat SERVEUR : on réutilise le certificat de développement.
        // -> exécuter au préalable :  dotnet dev-certs https --trust
        listenOptions.UseHttps(httpsOptions =>
        {
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        });
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/secure-data", () => new
{
    Message = "Accès mTLS réussi ! Données secrètes."
}).RequireAuthorization();

app.Run();
