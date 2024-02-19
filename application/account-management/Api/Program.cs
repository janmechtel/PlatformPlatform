using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PlatformPlatform.AccountManagement.Api.Auth;
using PlatformPlatform.AccountManagement.Api.Tenants;
using PlatformPlatform.AccountManagement.Api.Users;
using PlatformPlatform.AccountManagement.Application;
using PlatformPlatform.AccountManagement.Infrastructure;
using PlatformPlatform.SharedKernel.ApiCore;
using PlatformPlatform.SharedKernel.ApiCore.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Configure services for the Application, Infrastructure, and Api layers like Entity Framework, Repositories, MediatR,
// FluentValidation validators, Pipelines.
builder.Services
    .AddApplicationServices()
    .AddDatabaseContext(builder)
    .AddInfrastructureServices()
    .AddApiCoreServices(builder)
    .AddIdentityServices();

var app = builder.Build();

// Add common configuration for all APIs like Swagger, HSTS, DeveloperExceptionPage, and run EF database migrations.
app.AddApiCoreConfiguration<AccountManagementDbContext>();
app.UseWebAppMiddleware();

app.MapUserEndpoints();
app.MapTenantEndpoints();
app.MapIdentityEndpoints();
app.MapIdentityApi<ApplicationUser>();

app.UseAuthentication();

app.MapGet("/api/secret", (ClaimsPrincipal user) => $"Hello {user.Identity?.Name}. My secret")
    .RequireAuthorization();
app.MapGet("/api/secret2", () => "This is a different secret!")
    .RequireAuthorization(p => p.RequireClaim("scope", "myapi:secrets"));

app.Run();