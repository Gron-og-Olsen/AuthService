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
        
        // Method to fetch user data from the external service
        private async Task<User?> GetUserData(LoginModel login)
        {
            var endpointUrl = _config["UserServiceEndpoint"]! + "/User/Username/" + login.Username;
            _logger.LogInformation("Retrieving user data from: {}", endpointUrl);
            var client = _httpClientFactory.CreateClient(); // Create HTTP client
            HttpResponseMessage response;

            try
            {
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                response = await client.GetAsync(endpointUrl); // Fetch user data from the API
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message); // Log any errors
                return null;
            }

            // Log the status code to verify if the response is successful
            _logger.LogInformation("Response status code: {StatusCode}", response.StatusCode);

            if (response.IsSuccessStatusCode)
            {
                try
                {
                    string? userJson = await response.Content.ReadAsStringAsync();

                    // Log the raw JSON to check the content
                    _logger.LogInformation("Raw User JSON: {UserJson}", userJson);

                    var user = JsonSerializer.Deserialize<User>(userJson); // Deserialize user object

                    if (user != null)
                    {
                        // Log the deserialized user object to confirm all fields are present
                        _logger.LogInformation("Deserialized User Object: {User}", JsonSerializer.Serialize(user));
                    }

                    return user; // Return deserialized user object
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, ex.Message); // Log any errors
                    return null;
                }
            }

            // Log if the response wasn't successful
            _logger.LogWarning("Failed to retrieve user data: {StatusCode}", response.StatusCode);
            return null; // Return null if no valid response
        }


        // POST method to handle login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            if (string.IsNullOrEmpty(login.Username) || string.IsNullOrEmpty(login.Password))
                return BadRequest(new { message = "Invalid login data" });

            var user = await GetUserData(login); // Get user data from the external UserService

            if (user == null)
                return Unauthorized(new { message = "Invalid username or password" });

            // Verify the entered password against the stored hashed password
            var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, login.Password);

            if (passwordVerificationResult != PasswordVerificationResult.Success)
                return Unauthorized(new { message = "Invalid username or password" });

            var token = await GenerateJwtToken(user.Username,user.Role); // Generate JWT token
            return Ok(new { Token = token }); // Return the token
        }
        

        // Method to get Vault secret values for issuer and secret
        private async Task GetVaultSecret()
        {
            var EndPoint = "https://localhost:8201/";
            var httpClientHandler = new HttpClientHandler();
            httpClientHandler.ServerCertificateCustomValidationCallback =
            (message, cert, chain, sslPolicyErrors) => { return true; };

            // Initialize one of the several auth methods.
            IAuthMethodInfo authMethod =
            new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
            // Initialize settings. You can also set proxies, custom delegates etc. here.
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

            // Use client to read a key-value secret.
            Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2
            .ReadSecretAsync(path: "hemmeligheder", mountPoint: "secret");
            _issuer = kv2Secret.Data.Data["Issuer"].ToString()!;

            // Use client to read a key-value secret.
            _secret = kv2Secret.Data.Data["Secret"].ToString()!;
            _logger.LogInformation("issue: {0}", _issuer);
            _logger.LogInformation("secret: {0}", _secret);
        }

        
        // Method to generate the JWT token
        private async Task<string> GenerateJwtToken(string username,string role)
        {
            await GetVaultSecret(); // Ensure secrets are retrieved from Vault
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Role, role)
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
        

    }
}
