using System.Security;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace PlatformPlatform.SharedKernel.ApiCore.Middleware;

public class WebAppMiddlewareConfiguration
{
    private readonly bool _isDevelopment;
    private readonly string HtmlTemplatePath = GetHtmlTemplatePath();
    private string? _htmlTemplate;
    public const string PublicUrlKey = "PUBLIC_URL";
    public const string CdnUrlKey = "CDN_URL";
    private const string PublicKeyPrefix = "PUBLIC_";
    private const string ApplicationVersionKey = "APPLICATION_VERSION";
    private readonly string[] _publicAllowedKeys = [CdnUrlKey, ApplicationVersionKey];
    
    public WebAppMiddlewareConfiguration(IOptions<JsonOptions> jsonOptions, bool isDevelopment)
    {
        _isDevelopment = isDevelopment;
        // Environment variables are empty when generating EF Core migrations
        PublicUrl = Environment.GetEnvironmentVariable(PublicUrlKey) ?? string.Empty;
        CdnUrl = Environment.GetEnvironmentVariable(CdnUrlKey) ?? string.Empty;
        var applicationVersion = Assembly.GetEntryAssembly()!.GetName().Version!.ToString();
        
        StaticRuntimeEnvironment = new Dictionary<string, string>
        {
            { PublicUrlKey, PublicUrl },
            { CdnUrlKey, CdnUrl },
            { ApplicationVersionKey, applicationVersion }
        };
        
        var json = JsonSerializer.Serialize(StaticRuntimeEnvironment, jsonOptions.Value.SerializerOptions);
        StaticRuntimeEnvironmentEncoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
        
        VerifyRuntimeEnvironment(StaticRuntimeEnvironment);
        
        BuildRootPath = GetWebAppDistRoot("WebApp", "dist");
        PermissionPolicies = GetPermissionsPolicies();
        ContentSecurityPolicies = GetContentSecurityPolicies(isDevelopment);
    }
    
    private string CdnUrl { get; }
    
    private string PublicUrl { get; }
    
    public string BuildRootPath { get; }
    
    public string GetHtmlTemplate()
    {
        if(_htmlTemplate is not null)
        {
            return _htmlTemplate;
        }
        
        if (!File.Exists(HtmlTemplatePath))
        {
            throw new FileNotFoundException("index.html does not exist.", HtmlTemplatePath);
        }
        
        _htmlTemplate = File.ReadAllText(HtmlTemplatePath, new UTF8Encoding());
        return _htmlTemplate;
    }
    
    public Dictionary<string, string> StaticRuntimeEnvironment { get; }
    
    public string StaticRuntimeEnvironmentEncoded { get; }
    
    public StringValues PermissionPolicies { get; }
    
    public string ContentSecurityPolicies { get; }
    
    private static string GetWebAppDistRoot(string webAppProjectName, string webAppDistRootName)
    {
        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        
        var directoryInfo = new DirectoryInfo(assemblyPath);
        while (directoryInfo is not null &&
               directoryInfo.GetDirectories(webAppProjectName).Length == 0 &&
               !Path.Exists(Path.Join(directoryInfo.FullName, webAppProjectName, webAppDistRootName))
              )
        {
            directoryInfo = directoryInfo.Parent;
        }
        
        return Path.Join(directoryInfo!.FullName, webAppProjectName, webAppDistRootName);
    }
    
    public static string GetHtmlTemplatePath()
    {
        var buildRootPath = GetWebAppDistRoot("WebApp", "dist");
        var htmlTemplatePath = Path.Combine(buildRootPath, "index.html");
        
        for (var i = 0; i < 5; i++)
        {
            // Hack. We have a race condition where this method might be called when the file is recreated.
            // This is OK when building the API and generating the Swagger.json, but not when running the application.
            if (File.Exists(htmlTemplatePath)) break;
            Thread.Sleep(TimeSpan.FromSeconds(1));
        }

        return htmlTemplatePath;
    }
    
    private StringValues GetPermissionsPolicies()
    {
        var permissionsPolicies = new Dictionary<string, string[]>
        {
            { "geolocation", [] },
            { "microphone", [] },
            { "camera", [] },
            { "picture-in-picture", [] },
            { "display-capture", [] },
            { "fullscreen", [] },
            { "web-share", [] },
            { "identity-credentials-get", [] }
        };
        
        return string.Join(", ", permissionsPolicies.Select(p => $"{p.Key}=({string.Join(", ", p.Value)})"));
    }
    
    private string GetContentSecurityPolicies(bool isDevelopment)
    {
        var trustedHosts = $"{PublicUrl} {CdnUrl}";
        
        if (isDevelopment)
        {
            var webSocketHost = CdnUrl.Replace("https", "wss");
            trustedHosts += $" {webSocketHost}";
        }
        
        var contentSecurityPolicies = new[]
        {
            $"script-src {trustedHosts} 'strict-dynamic' https:",
            $"script-src-elem {trustedHosts}",
            $"default-src {trustedHosts}",
            $"connect-src {trustedHosts}",
            $"img-src {trustedHosts} data:",
            "object-src 'none'",
            "base-uri 'none'"
            // "require-trusted-types-for 'script'"
        };
        
        return string.Join(";", contentSecurityPolicies);
    }
    
    private void VerifyRuntimeEnvironment(Dictionary<string, string> environmentVariables)
    {
        foreach (var key in environmentVariables.Keys)
        {
            if (key.StartsWith(PublicKeyPrefix) || _publicAllowedKeys.Contains(key)) continue;
            
            throw new SecurityException($"Environment variable '{key}' is not allowed to be public.");
        }
    }
}
