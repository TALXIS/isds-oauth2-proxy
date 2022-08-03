using Azure.Data.Tables;
using isds_oauth2_proxy.Extensions;
using isds_oauth2_proxy.Model;
using isds_oauth2_proxy.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;

namespace isds_oauth2_proxy
{
    public class Controller
    {
        private readonly IConfiguration _configuration;
        private readonly ISDS.GetCredential.EndSessionClient _getCredentialService;
        private readonly JwtTokenService _jwtTokenService;
        public Controller(IConfiguration configuration, JwtTokenService jwtTokenService)
        {
            _configuration = configuration;

            _getCredentialService = new ISDS.GetCredential.EndSessionClient();
            _getCredentialService.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindBySubjectName, _configuration["ISDS:CertificateSubject"]);

            _jwtTokenService = jwtTokenService;
        }
        [FunctionName("Authorize")]
        public async Task<IActionResult> Authorize(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth2/authorize")] HttpRequest req,
            [Table("RedirectUrlCache")] TableClient cloudTable,
            ILogger log)
        {
            var query = req.QueryString.ToUriComponent();

            var rng = new Random();
            var id = rng.NextULong(1000000000000000, 9999999999999999999);

            await cloudTable.UpsertEntityAsync(new IsdsRedirectState()
            {
                PartitionKey = "state",
                RowKey = id.ToString(),
                State = query
            }, TableUpdateMode.Replace);

            return new RedirectResult($"https://www.mojedatovaschranka.cz/as/login?atsId={_configuration["ISDS:atsId"]}&appToken={id}");
        }
        [FunctionName("AuthResp")]
        public async Task<IActionResult> AuthResp(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "isds/authresp")] HttpRequest req,
            [Table("RedirectUrlCache")] TableClient cloudTable,
            ILogger log)
        {
            var sessionId = req.Query["sessionId"];
            var id = req.Query["appToken"];

            var response = await _getCredentialService.authConfirmationAsync(new ISDS.GetCredential.authConfirmationRequestType
            {
                sessionId = sessionId
            });

            var tableResponse = await cloudTable.GetEntityAsync<IsdsRedirectState>("state", id);

            var parsedQuery = HttpUtility.ParseQueryString(tableResponse.Value.State);

            var token = _jwtTokenService.GenerateToken(new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, response.authConfirmationResponse1.attributes.Where(x => x.name == "timeLimitedId").First().value),
                new Claim("ic", response.authConfirmationResponse1.attributes.Where(x => x.name == "ic").First().value),
                new Claim("firmName", response.authConfirmationResponse1.attributes.Where(x => x.name == "firmName").First().value),
                new Claim("dbType", response.authConfirmationResponse1.attributes.Where(x => x.name == "dbType").First().value),
                new Claim("dbID", response.authConfirmationResponse1.attributes.Where(x => x.name == "dbID").First().value),
                new Claim("timeLimitedId", response.authConfirmationResponse1.attributes.Where(x => x.name == "timeLimitedId").First().value),
            });

            var redirectUrl = $"{parsedQuery["redirect_uri"]}?code={token}&state={parsedQuery["state"]}";

            await cloudTable.DeleteEntityAsync("state", id);

            //return new OkObjectResult(new { query = parsedQuery, attributes = response.authConfirmationResponse1.attributes, redirectUrl = redirectUrl });
            return new RedirectResult(redirectUrl);
        }
        [FunctionName("Token")]
        public async Task<IActionResult> Token([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "oauth2/token")] HttpRequest req, ILogger log)
        {
            var body = HttpUtility.ParseQueryString(await req.ReadAsStringAsync());
            return new OkObjectResult(new
            {
                access_token = body["code"],
                token_type = "Bearer",
                expires_in = 3599,
                scope = "isds",
                refresh_token = ""
            });
        }
        [FunctionName("UserInfo")]
        public async Task<IActionResult> UserInfo([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth2/userinfo")] HttpRequest req, ILogger log)
        {
            var token = req.Query["access_token"];

            var valid = _jwtTokenService.ValidateToken(token);
            if (valid)
            {
                var securityToken = _jwtTokenService.ReadToken(token);
                var claims = new Dictionary<string, string>();
                foreach (var claim in securityToken.Claims)
                {
                    claims.Add(claim.Type, claim.Value);
                }
                return new OkObjectResult(claims);
            }

            return new BadRequestObjectResult(new ProblemDetails
            {
                Title = "Token validation failed!",
                Status = 400,
            });
        }
    }
}
