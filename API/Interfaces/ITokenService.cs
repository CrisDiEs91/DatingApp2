using API.Controllers;
using API.Entities;

namespace API.Services;

public interface TokenService:ITokenService
{
    string CreateToken(AppUser user);    
}