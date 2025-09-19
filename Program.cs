using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;

var builder = WebApplication.CreateBuilder(args);

// 데이터베이스 설정
builder.Services.AddDbContext<TodoDbContext>(options =>
    options.UseSqlite("Data Source=todos.db"));

// JWT 인증 설정
const string JWT_SECRET_KEY = "990be4b2ef4c4f88800c3d628d98b8040eb45154071b20adc0d736f541408992";
var key = Encoding.ASCII.GetBytes(JWT_SECRET_KEY);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseDefaultFiles();
app.UseStaticFiles();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

// 회원가입 API
app.MapPost("/auth/register", async (RegisterRequest request, TodoDbContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Username == request.Username))
    {
        return Results.BadRequest("이미 존재하는 사용자명입니다.");
    }

    if (await db.Users.AnyAsync(u => u.Email == request.Email))
    {
        return Results.BadRequest("이미 존재하는 이메일입니다.");
    }

    var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

    var user = new User
    {
        Username = request.Username,
        Email = request.Email,
        PasswordHash = passwordHash
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "회원가입이 완료되었습니다.", userId = user.Id });
})
.WithName("Register");

// 로그인 API
app.MapPost("/auth/login", async (LoginRequest request, TodoDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
    
    if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
    {
        return Results.BadRequest("사용자명 또는 비밀번호가 올바르지 않습니다.");
    }
    
    // 로그인 API 안에서
    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenKey = Encoding.ASCII.GetBytes(JWT_SECRET_KEY);  // 같은 키 사용
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("userId", user.Id.ToString()),
            new Claim("username", user.Username)
        }),
        Expires = DateTime.UtcNow.AddDays(7),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
    };
    
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);
    
    return Results.Ok(new LoginResponse(tokenString, user.Username, user.Id));
})
.WithName("Login");

app.MapGet("/todos", async (TodoDbContext db, HttpContext context) =>
{
    var userId = GetUserIdFromToken(context);
    if (userId == null) return Results.Unauthorized();
    
    var todos = await db.Todos.Where(t => t.UserId == userId.Value).ToListAsync();
    return Results.Ok(todos);
})
.WithName("GetTodos")
.RequireAuthorization();

app.MapGet("/todos/{id}", async (int id, TodoDbContext db, HttpContext context) =>
{
    var userId = GetUserIdFromToken(context);
    if (userId == null) return Results.Unauthorized();
    
    var todo = await db.Todos.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId.Value);
    
    if (todo == null)
    {
        return Results.NotFound();
    }
    
    return Results.Ok(todo);
})
.WithName("GetTodoById")
.RequireAuthorization();

app.MapPost("/todos", async (TodoItem newTodo, TodoDbContext db, HttpContext context) =>
{
    var userId = GetUserIdFromToken(context);
    if (userId == null) return Results.Unauthorized();
    
    newTodo.UserId = userId.Value;
    db.Todos.Add(newTodo);
    await db.SaveChangesAsync();
    
    return Results.Created($"/todos/{newTodo.Id}", newTodo);
})
.WithName("CreateTodo")
.RequireAuthorization();

app.MapPut("/todos/{id}", async (int id, TodoItem updatedTodo, TodoDbContext db, HttpContext context) =>
{
    var userId = GetUserIdFromToken(context);
    if (userId == null) return Results.Unauthorized();
    
    var existingTodo = await db.Todos.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId.Value);
    
    if (existingTodo == null)
    {
        return Results.NotFound();
    }
    
    existingTodo.Title = updatedTodo.Title;
    existingTodo.IsCompleted = updatedTodo.IsCompleted;
    await db.SaveChangesAsync();
    
    return Results.Ok(existingTodo);
})
.WithName("UpdateTodo")
.RequireAuthorization();

app.MapDelete("/todos/{id}", async (int id, TodoDbContext db, HttpContext context) =>
{
    var userId = GetUserIdFromToken(context);
    if (userId == null) return Results.Unauthorized();
    
    var todo = await db.Todos.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId.Value);
    
    if (todo == null)
    {
        return Results.NotFound();
    }
    
    db.Todos.Remove(todo);
    await db.SaveChangesAsync();
    
    return Results.NoContent();
})
.WithName("DeleteTodo")
.RequireAuthorization();

// 토큰에서 사용자 ID 추출하는 헬퍼 함수
int? GetUserIdFromToken(HttpContext context)
{
    var userIdClaim = context.User.FindFirst("userId");
    if (userIdClaim != null && int.TryParse(userIdClaim.Value, out int userId))
    {
        return userId;
    }
    return null;
}

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

public class TodoItem
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public bool IsCompleted { get; set; }
    public int UserId { get; set; }
    public User User { get; set; } = null!;
}

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public List<TodoItem> Todos { get; set; } = new();
}

public record RegisterRequest(string Username, string Email, string Password);
public record LoginRequest(string Username, string Password);
public record LoginResponse(string Token, string Username, int UserId);

public class TodoDbContext : DbContext
{
    public TodoDbContext(DbContextOptions<TodoDbContext> options) : base(options)
    {
    }

    public DbSet<TodoItem> Todos { get; set; }
    public DbSet<User> Users { get; set; }
}