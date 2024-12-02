using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Models;

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.String)] // Ensures the Guid is stored as a string in MongoDB
    public Guid Id { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }
    public string? Address1 { get; set; }
    public string? City { get; set; }
    public int PostalCode { get; set; }
    public string? ContactName { get; set; }
    public string? TaxNumber { get; set; }
}
