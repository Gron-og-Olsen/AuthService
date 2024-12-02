using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Models;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private string _issuer;
        private string _secret;

        // Correct constructor to properly inject IHttpClientFactory
        public AuthController(ILogger<AuthController> logger, IConfiguration config, IHttpClientFactory httpClientFactory)
        {
            _config = config;
            _logger = logger;
            _httpClientFactory = httpClientFactory; // Injected here correctly
        }

        // Method to generate the JWT token
        private async Task<string> GenerateJwtToken(string username)
        {
            await GetVaultSecret(); // Ensure secrets are retrieved from Vault
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username)
            };
            var token = new JwtSecurityToken(
                _issuer, // Uses the issuer value retrieved from Vault
                "http://localhost", // This can be changed to your actual domain or API URL
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token); // Generate and return token
        }

        // Method to fetch user data from the external service
        private async Task<User?> GetUserData(LoginModel login)
        {
            var endpointUrl = _config["UserServiceEndpoint"]! + "/" + login.Username;
            _logger.LogInformation("Retrieving user data from: {}", endpointUrl);
            var client = _httpClientFactory.CreateClient(); // Create HTTP client
            HttpResponseMessage response;
            try {
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                response = await client.GetAsync(endpointUrl); // Fetch user data from the API
            } catch (Exception ex) {
                _logger.LogError(ex, ex.Message); // Log any errors
                return null;
            }
            if (response.IsSuccessStatusCode)
            {
                try {
                    string? userJson = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<User>(userJson); // Deserialize user object
                } catch (Exception ex) {
                    _logger.LogError(ex, ex.Message); // Log any errors
                    return null;
                }
            }
            return null; // Return null if no valid response
        }

        // POST method to handle login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            if (string.IsNullOrEmpty(login.Username) || string.IsNullOrEmpty(login.Password))
                return BadRequest("Invalid login data");

            var user = await GetUserData(login); // Get user data from the service

            if (user == null || user.Password != login.Password)
                return Unauthorized("Invalid username or password");

            var token = await GenerateJwtToken(user.Username); // Await the token generation
            return Ok(new { Token = token }); // Return the generated JWT token
        }

        // Method to get Vault secret values for issuer and secret
        private async Task GetVaultSecret()
        {
            var EndPoint = "https://localhost:8201/";
            var httpClientHandler = new HttpClientHandler();
            httpClientHandler.ServerCertificateCustomValidationCallback =
                (message, cert, chain, sslPolicyErrors) => { return true; };

            // Initialize Vault auth method using token
            IAuthMethodInfo authMethod =
                new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

            // Initialize Vault client settings
            var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
            {
                Namespace = "",
                MyHttpClientProviderFunc = handler
                    => new HttpClient(httpClientHandler)
                    {
                        BaseAddress = new Uri(EndPoint)
                    }
            };
            IVaultClient vaultClient = new VaultClient(vaultClientSettings);

            // Retrieve secrets from Vault
            Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2
                .ReadSecretAsync(path: "hemmeligheder", mountPoint: "secret");
            _issuer = kv2Secret.Data.Data["Issuer"].ToString()!;
            _secret = kv2Secret.Data.Data["Secret"].ToString()!;

            _logger.LogInformation("issuer: {0}", _issuer);
            _logger.LogInformation("secret: {0}", _secret);
        }
    }
}
