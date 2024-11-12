using AuthServer.Helpers;
using AuthServer.Services;
using AuthServer.Authorization;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("appsettings.Development.json");
var config = builder.Configuration;


builder.Logging.AddConsole();
builder.Logging.AddDebug();

builder.Services.AddAuthentication("Bearer").AddJwtBearer(options =>
{
    options.Authority = "https://localhost:44308";
    options.RequireHttpsMetadata = false;
    options.Audience = "https://localhost:44308";
});

builder.Services.AddAuthorization();
builder.Services.AddControllers()
    .AddJsonOptions(x => x.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.Configure<JwtSettings>(config.GetSection("JwtSettings"));
builder.Services.AddScoped<IJwtUtils, JwtUtils>();
builder.Services.AddScoped<IUserService, UserService>();


builder.Services.AddSingleton<ConnectionMultiplexer>(sp =>
{
    var redisConfig = sp.GetRequiredService<IConfiguration>().GetSection("RedisOptions");
    var configuration = ConfigurationOptions.Parse(redisConfig["ConnectionString"]);
    return ConnectionMultiplexer.Connect(configuration);
});

//builder.Services.AddStackExchangeRedisCache(options =>
//{
//    var redisConfig = config.GetSection("RedisOptions");
//    options.Configuration = redisConfig["ConnectionString"];
//});


builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy",
        policy =>
        {
            policy.AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowAnyOrigin();
        });
});


var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseRouting();

app.UseHttpsRedirection();

app.UseCors("CorsPolicy");

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<ErrorHandlerMiddleware>();
app.UseMiddleware<JwtMiddleware>();

app.MapControllers();

app.Run();