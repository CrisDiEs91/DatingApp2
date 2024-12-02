namespace API.Data;

using API.Data.Migrations;
using API.DTOs;
using API.DataEntities;
using AutoMapper;
using AutoMapper.QueryableExtensions;
using Microsoft.EntityFrameworkCore;

public class UserRepository(DataContext context, IMapper mapper) : IUserRepository
{
    public async Task<IEnumerable<AppUser>> GetAllAsync()
        => await context.Users
                .Include(u => u.Photos)
                .ToListAsync();

    public async Task<AppUser?> GetByIdAsync(int id)
        => await context.Users
                .Include(u => u.Photos)
                .FirstOrDefaultAsync(u => u.Id == id);

    public async Task<AppUser?> GetByUsernameAsync(string username)
        => await context.Users
                .Include(u => u.Photos)
                .SingleOrDefaultAsync(u => u.UserName == username);

    public async Task<MemberResponse?> GetMemberAsync(string username)
        => await context.Users
                .Where(u => u.UserName == username)
                .ProjectTo<MemberResponse>(mapper.ConfigurationProvider)
                .SingleOrDefaultAsync();
    public async Task<IEnumerable<MemberResponse>> GetMembersAsync()
        => await context.Users
                .ProjectTo<MemberResponse>(mapper.ConfigurationProvider)
                .ToListAsync();

    public void Update(AppUser user)
        => context.Entry(user).State = EntityState.Modified;
}