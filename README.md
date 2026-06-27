# Workshop X.509 sous ASP.NET Core .NET 10 — code des labs

Solution support du workshop *« Les Certificats X.509 sous ASP.NET Core .NET 10 »* (bstorm training). Trois labs fil rouge, 100 % C#, certificats éphémères en mémoire — aucun droit administrateur requis.

## Prérequis

- SDK **.NET 10** (`dotnet --version` → `10.0.x`)
- Windows · VS Code ou Visual Studio 2022+
- Une seule fois, pour le certificat serveur de développement :

```bash
dotnet dev-certs https --trust
```

## Contenu

| Projet | Module | Rôle |
|--------|--------|------|
| `Module1.Lab` | 1 | Console — génère une Root CA, signe un certificat serveur, recharge via `X509CertificateLoader` |
| `Module2.Server` | 2 | API mTLS — Kestrel exige un certificat client valide (CN `MonClientAutorise`) |
| `Module2.Client` | 2 | Console — présente un certificat client et appelle l'API sécurisée |
| `Module3.Rotation` | 3 | API — rotation à chaud du certificat via `ServerCertificateSelector` |

## Exécution

### Module 1 — génération

```bash
dotnet run --project Module1.Lab
```

### Module 2 — mTLS (deux terminaux)

```bash
# Terminal 1 — serveur
dotnet run --project Module2.Server
# Terminal 2 — client
dotnet run --project Module2.Client
```

Attendu côté client : `Réponse du serveur : { "message": "Accès mTLS réussi ! ..." }`.
Modifiez le CN du client (≠ `MonClientAutorise`) pour observer le rejet par le serveur.

### Module 3 — rotation à chaud

```bash
dotnet run --project Module3.Rotation
# puis, dans un autre terminal :
curl -k https://localhost:5001/api/cert-info       # note le Thumbprint
curl -k -X POST https://localhost:5001/api/rotate  # rotation
curl -k https://localhost:5001/api/cert-info       # Thumbprint différent, sans redémarrage
```


> ⚠ `DangerousAcceptAnyServerCertificateValidator` et `RevocationMode.NoCheck` sont réservés au labo local éphémère. En production : chaîne de confiance complète + révocation.
