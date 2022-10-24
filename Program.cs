using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;


var jwksJson = @"
{
  ""keys"": [
    {
      ""kty"": ""RSA"",
      ""use"": ""sig"",
      ""kid"": ""0313B7152576EF7415003F309C7E7F5EABADD0B7RS256"",
      ""x5t"": ""AxO3FSV273QVAD8wnH5_Xqut0Lc"",
      ""e"": ""AQAB"",
      ""n"": ""3FOm0fOmXa4TvBEP4iFqjYaBXPYXokf3kBF-I-JqMaZkbYgB9Vl1v9ra5H8ZKKYeYW7_3R-BmjZ6f0vAnEgtRjC9rm2OJnQcc4hcMhpSAeMoH2gX7DLK8eDQQ0V7uQvpMnPAAV-O9Hh5xq409-xOa1RQ-0rzS963S8H1t47FoJ0"",
      ""x5c"": [
        ""MIIBrTCCARagAwIBAgIQAII32TMUdYLycl7/4+nW/zANBgkqhkiG9w0BAQ0FADAUMRIwEAYDVQQDDAlPcnBoeUtleXMwIBcNMjAwODEwMTYwODE4WhgPMjExMDA4MTAxNjA4MThaMBQxEjAQBgNVBAMMCU9ycGh5S2V5czCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3FOm0fOmXa4TvBEP4iFqjYaBXPYXokf3kBF+I+JqMaZkbYgB9Vl1v9ra5H8ZKKYeYW7/3R+BmjZ6f0vAnEgtRjC9rm2OJnQcc4hcMhpSAeMoH2gX7DLK8eDQQ0V7uQvpMnPAAV+O9Hh5xq409+xOa1RQ+0rzS963S8H1t47FoJ0CAwEAATANBgkqhkiG9w0BAQ0FAAOBgQDQLXIsBcGDTqlG3eF39E3r+mukYj6BGvTRZecn1FOnTbQUSdf1/wccTP45y6dl7Xkg9bSZzOxi+FZwCDuEmb7u56PAN1k5Tz0addv/OD1l8Wm8WGFxPG44WJGd7tFl9J/OWrv1n6n/kkNzLlPCpLcmY+gu7morWfOJX40lH4FdKA==""
      ],
      ""alg"": ""RS256""
    }
  ]
}   
";


var token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAzMTNCNzE1MjU3NkVGNzQxNTAwM0YzMDlDN0U3RjVFQUJBREQwQjdSUzI1NiIsInR5cCI6ImF0K2p3dCIsIng1dCI6IkF4TzNGU1YyNzNRVkFEOHduSDVfWHF1dDBMYyJ9.eyJuYmYiOjE2NjY2MzA4NzEsImV4cCI6MTY2NjYzNDQ3MSwiaXNzIjoiaHR0cHM6Ly9kZXYuaWRzcnYud2ViYWNjb3VudHBsdXMuY29tIiwiYXVkIjpbIk9ycGh5T2RhdGFBUEkiLCJPcnBoeUludGVybmFsQVBJIiwiT3JwaHlQdWJsaWNBUEkiXSwiY2xpZW50X2lkIjoiT3JwaHlTd2FnZ2VyIiwic3ViIjoiMDkwMjlmYjYtODgxYS00YjIwLWJlNTktM2JmODk3Njg5OTA4IiwiYXV0aF90aW1lIjoxNjY2NjMwNDk5LCJpZHAiOiJsb2NhbCIsInN5c3RlbV9zdXBlcnZpc29yIjoidHJ1ZSIsImVtYWlsIjoic3VAb3JwaGlzLmNvbSIsInNpZCI6IkY3OEY4NDJBMjc3RkQ0QjQwOTRGQ0RDMDkyN0UyOUM4IiwiaWF0IjoxNjY2NjMwODcxLCJzY29wZSI6WyJvcnBoeV9vZGF0YV9hcGkiLCJvcnBoeV9pbnRlcm5hbF9hcGkiLCJvcnBoeV9wdWJsaWNfYXBpIl0sImFtciI6WyJwd2QiXX0.MllQyNIDjRtem7fO02SHZKt-fZcwo8dBeBPbDb69v54JSvtgv12dSMxSntAqvvyLW8INyHJazpN-O5AA_RwSE6p9KJ8gtOz46sYpA5W05VBIYALiFhJite0201I59W93syjqM3Kq8YEIm6xYuOLxXqcR35tGiESg6QktYx7QBZw";
var jwks = new JsonWebKeySet(jwksJson);
var jwk = jwks.Keys.First();

var validationParameters = new TokenValidationParameters
{
	IssuerSigningKey = jwk,
	ValidateAudience = true,
	ValidateIssuer = true,
	ValidAudiences = new []{"OrphyOdataAPI","OrphyInternalAPI","OrphyPublicAPI"}, // Your API Audience, can be disabled via ValidateAudience = false
	ValidIssuer = "https://dev.idsrv.webaccountplus.com"  // Your token issuer, can be disabled via ValidateIssuer = false
};

if (ValidateToken(token, validationParameters))
{
	Console.WriteLine("Token Valid");
}
Console.WriteLine("Token Invalid");

static bool ValidateToken(string token, TokenValidationParameters validationParameters)
{
	var tokenHandler = new JwtSecurityTokenHandler();
	try
	{
		tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
		return validatedToken != null;
	}
	catch (Exception e)
	{
		Console.WriteLine(e);
		return false;
	}
}