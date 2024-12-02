using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();
builder.Services.AddControllers();

// Læs de hemmelige værdier fra miljøvariabler
string mySecret = Environment.GetEnvironmentVariable("Secret") ?? "defaultsecret";
string myIssuer = Environment.GetEnvironmentVariable("Issuer") ?? "defaultissuer";

// Tilføj JWT Bearer Authentication
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = myIssuer,
            ValidAudience = "http://localhost", // Du kan ændre dette til den ønskede værdi
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
        };
    });

var app = builder.Build();

// Brug af autentifikation og autorisation
app.UseAuthentication(); // Denne linje aktiverer autentifikationen
app.UseAuthorization();  // Denne linje aktiverer autorisationen

app.MapControllers();

app.Run();
