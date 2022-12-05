using Microsoft.AspNetCore.Authentication;

namespace WhichTokenApi.Authentications
{
    public class CustomSchemeOptions : AuthenticationSchemeOptions
    {
        public const string Name = "CustomSchemeOptions";
    }
}