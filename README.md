# ISDS OAuth2 Proxy
This code allows your to integrate [Czech Data Boxes (ISDS)](https://www.mojedatovaschranka.cz/) with your application via standardized OAuth2 protocol. For example, you can add it as an Identity Provider to Azure AD B2C.

```json
{
  "ISDS": {
    "atsId": "<ats-id>",
    "CertificateSubject": "<subject>"
  },
  "Token": {
    "Secret": "<token-secret>",
    "Issuer": "<issuer>",
    "Audience": "<audience>"
  }
}
```

## Endpoints
* Authorize: `/api/oauth2/authorize`
* Token: `/api/oauth2/token`
* User Info: `/api/oauth2/userinfo`

## Future improvements
* Support only specified redirect URLs
* Support only specified client ID and client secret