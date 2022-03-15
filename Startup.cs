using isds_oauth2_proxy.Services;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

[assembly: FunctionsStartup(typeof(isds_oauth2_proxy.Startup))]
namespace isds_oauth2_proxy
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            builder.Services.AddScoped<JwtTokenService>();
        }
    }
}
