using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Models;
using System.Text.Json;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp;
using VaultSharp.V1.Commons;
using VaultSharp.Core;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;


        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IPasswordHasher<User> _passwordHasher;
        private string? _issuer;
        private string? _secret;

        public AuthController(
            ILogger<AuthController> logger,
            IConfiguration config,
            IHttpClientFactory httpClientFactory,
            IPasswordHasher<User> passwordHasher)
        {
            _config = config;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _passwordHasher = passwordHasher;
        }

        private async Task<User?> GetUserData(LoginModel login)
        {
            _logger.LogInformation("Entering GetUserData method.");
            var endpointUrl = _config["UserServiceEndpoint"]! + "/User/Username/" + login.Username;
            _logger.LogInformation("Constructed endpoint URL: {EndpointUrl}", endpointUrl);

            var client = _httpClientFactory.CreateClient();
            HttpResponseMessage response;

            try
            {
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                _logger.LogInformation("Sending request to UserService...");
                response = await client.GetAsync(endpointUrl);
                _logger.LogInformation("Received response with status code: {StatusCode}", response.StatusCode);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during HTTP request to UserService.");
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                try
                {
                    string? userJson = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation("User JSON received: {UserJson}", userJson);

                    var user = JsonSerializer.Deserialize<User>(userJson);
                    _logger.LogInformation("Deserialized user object: {User}", JsonSerializer.Serialize(user));
                    return user;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error deserializing user data.");
                    return null;
                }
            }

            _logger.LogWarning("Unsuccessful response from UserService: {StatusCode}", response.StatusCode);
            return null;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            _logger.LogInformation("Login attempt for user: {Username}", login.Username);

            if (string.IsNullOrEmpty(login.Username) || string.IsNullOrEmpty(login.Password))
            {
                _logger.LogWarning("Invalid login data provided.");
                return BadRequest(new { message = "Invalid login data" });
            }

            var user = await GetUserData(login);

            if (user == null)
            {
                _logger.LogWarning("No user found with username: {Username}", login.Username);
                return Unauthorized(new { message = "Invalid username" });
            }

            var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, login.Password);

            if (passwordVerificationResult != PasswordVerificationResult.Success)
            {
                _logger.LogWarning("Password verification failed for username: {Username}", login.Username);
                return Unauthorized(new { message = "Invalid password" });
            }

            _logger.LogInformation("Generating JWT token for username: {Username}", login.Username);
            var token = await GenerateJwtToken(user.Username, user.Role);

            _logger.LogInformation("Login successful for username: {Username}", login.Username);
            return Ok(new { Token = token });
        }

        private async Task GetVaultSecret()
        {
            _logger.LogInformation("Fetching secrets from Vault...");
            var EndPoint = "https://vault_dev:8201/";
            var httpClientHandler = new HttpClientHandler();
            httpClientHandler.ServerCertificateCustomValidationCallback =
                (message, cert, chain, sslPolicyErrors) => true;

            IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
            var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
            {
                Namespace = "",
                MyHttpClientProviderFunc = handler
                    => new HttpClient(httpClientHandler) { BaseAddress = new Uri(EndPoint) }
            };

            IVaultClient vaultClient = new VaultClient(vaultClientSettings);

            try
            {
                _logger.LogInformation("Reading secrets from Vault path: secret/hemmeligheder");
                Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                    path: "hemmeligheder",
                    mountPoint: "secret"
                );

                _issuer = kv2Secret.Data.Data["Issuer"].ToString();
                _secret = kv2Secret.Data.Data["Secret"].ToString();

                _logger.LogInformation("Vault secrets retrieved: Issuer={Issuer}, Secret=******", _issuer);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving secrets from Vault.");
                throw;
            }
        }

        private async Task<string> GenerateJwtToken(string username, string role)
        {
            _logger.LogInformation("Generating JWT token...");
            await GetVaultSecret();

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Role, role)
            };

            var token = new JwtSecurityToken(
            issuer: _issuer,         // Udgiveren af tokenet
            audience: null,          // Fjernet ved at sætte den til null
            claims: claims,          // Tokenets indhold
            expires: DateTime.Now.AddHours(2), // Udløbstid
            signingCredentials: credentials    // Signeringsoplysninger
);


            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            _logger.LogInformation("JWT token generated successfully.");
            return jwt;
        }

        [HttpGet("GetValidationKeys")]
        public async Task<IActionResult> GetValidationKeys()
        {
            _logger.LogInformation("Fetching validation keys...");
            await GetVaultSecret();
            return Ok(new
            {
                Issuer = _issuer,
                Secret = _secret
            });
        }
    }
}

