namespace API.Controllers;
using API.Data;
using API.Data.Migrations;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[Authorize]
public class UsersController : BaseApiController
{
    private readonly DataContext _context;
    private readonly IMapper _mapper;

    public UsersController(IUserRepository repository, IMapper mapper)
    {
        _repository = repository;
        _mapper = mapper;
    }

    //[AllowAnonymous]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<AppUser>>> GetUsersAsync()
    {
        var users = await _repository.GetAllAsync();

        var response = _mapper.Map<IEnumerable<MemberResponse>>(users);
        return Ok(response);
    }

    //[Authorize]
    [HttpGet("{id:int}")] // api/users/2
    public async Task<ActionResult<AppUser>> GetUsersByIdAsync(int id)
    {
        var user = await _context.Users.FindAsync(id);

        if (user == null)
        {
            return NotFound();
        }

        return _mapper.Map<MemberResponse>(user);
    }

    [HttpGet("{username}")] // api/users/Calamardo
    public async Task<ActionResult<MemberResponse>> GetByUsernameAsync(string username)
    {
        var user = await _repository.GetByUsernameAsync(username);

        if (user == null)
        {
            return NotFound();
        }
         return _mapper.Map<MemberResponse>(user);
    }
}