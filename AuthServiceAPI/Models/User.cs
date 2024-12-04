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

    [JsonPropertyName("address1")]
    public string Address1 { get; set; }

    [JsonPropertyName("city")]
    public string City { get; set; }

    [JsonPropertyName("postalCode")]
    public int PostalCode { get; set; }

    [JsonPropertyName("contactName")]
    public string ContactName { get; set; }

    [JsonPropertyName("taxNumber")]
    public string TaxNumber { get; set; }
}

