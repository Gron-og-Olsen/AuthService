using System.Text.Json.Serialization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Models;


public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.String)] // Ensures the Guid is stored as a string in MongoDB
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("username")]
    public string Username { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }

    [JsonPropertyName("address")]
    public string Address { get; set; }

    [JsonPropertyName("city")]
    public string City { get; set; }

    [JsonPropertyName("postalCode")]
    public int PostalCode { get; set; }

    [JsonPropertyName("role")]
    public string Role { get; set; }

    [JsonPropertyName("tlf")]
    public string TLF { get; set; }
}

