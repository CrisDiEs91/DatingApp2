namespace API.Controllers;
using API.Data;
using API.Data.Migrations;
using API.DTOs;
using API.DataEntities;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc;

[Authorize]
public class UsersController : BaseApiController
{
    private readonly IUserRepository _repository;
    private readonly IMapper _mapper;

    public UsersController(IUserRepository repository)
    {
        _repository = repository;
    }

    //[AllowAnonymous]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<AppUser>>> GetAllAsync()
    {
        var users = await _repository.GetAllAsync();
        return Ok(users);
    }

    [HttpGet("{username}")] // api/users/Calamardo
    public async Task<ActionResult<AppUser>> GetByIdAsync(int id)
    {
        var user = await _repository.GetByIdAsync(id);

        if (user == null)
        {
            return NotFound();
        }

        return user;
    }

    [HttpGet("{username}")] // api/users/Calamardo
    public async Task<ActionResult<AppUser>> GetByUsernameAsync(string username)
    {
        var user = await _repository.GetByUsernameAsync(username);
        if (user == null)
        {
            return NotFound();
        }
        return user;
    }
}