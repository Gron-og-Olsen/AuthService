using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;

var endPoint = "https://localhost:8201/";
var httpClientHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback =
        (message, cert, chain, sslPolicyErrors) => true // Kun til udvikling/test
};

// Initialiser auth-metoden med et rigtigt token.
IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

// Opsæt Vault-klienten.
var vaultClientSettings = new VaultClientSettings(endPoint, authMethod)
{
    Namespace = "", // Udfyld kun, hvis du bruger namespaces i Vault.
    MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
    {
        BaseAddress = new Uri(endPoint)
    }
};

IVaultClient vaultClient = new VaultClient(vaultClientSettings);

try
{
    // Læs en hemmelighed fra Vault.
    Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2
        .ReadSecretAsync(path: "hemmeligheder", mountPoint: "secret");
    
    var PeterJensen = kv2Secret.Data.Data["PeterJensen"];
    Console.WriteLine($"PeterJensen: {PeterJensen}");

    var UllaSmil = kv2Secret.Data.Data["UllaSmil"];
    Console.WriteLine($"UllaSmil: {UllaSmil}");

    var KarlUrl = kv2Secret.Data.Data["KarlUrl"];
    Console.WriteLine($"KarlUrl: {KarlUrl}");
}
catch (Exception ex)
{
    Console.WriteLine($"Fejl ved læsning af hemmelighed: {ex.Message}");
}
