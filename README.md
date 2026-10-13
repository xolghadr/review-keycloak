# Keycloak Authentication Flows: Review Reference

A study and review sheet covering Keycloak basics, OAuth 2.0 / OpenID Connect flows, Keycloak's built-in authentication flows, and a deep dive into Authorization Code + PKCE.

## 1. Keycloak in a nutshell

Keycloak is a free, open-source identity and access management tool that handles **logging in** for your apps, so you don't have to build it yourself. It is maintained by Red Hat and is part of the CNCF.

Instead of every app having its own login system, user database, and password reset flow, you set up login once in Keycloak and all apps rely on it.

**What it provides**

- Login and registration pages
- Single Sign-On (SSO): log in once, access all connected apps
- Social login (Google, GitHub, Facebook, ...)
- Roles and permissions
- Security features: 2FA, password rules, account lockout
- User management admin console

**Key terms**

| Term | Meaning |
| --- | --- |
| Realm | A separate space with its own users and settings (like a workspace per company or project) |
| Client | An app that uses Keycloak for login |
| User | A person with an account |
| Role | A label such as "admin" or "editor" that controls access |
| Token | A signed proof from Keycloak saying who the user is and what they may do |

Keycloak uses standard protocols: OpenID Connect, OAuth 2.0, and SAML.

## 2. OAuth 2.0 / OIDC flows (how an app gets a token)

### 2.1 Authorization Code Flow (with PKCE)

**Use case:** web apps, single-page apps (React, Angular), and mobile apps. This is the recommended default for anything with a human user.

**How it works**

1. The app redirects the user to Keycloak's login page.
2. The user logs in (password, 2FA, social login, ...).
3. Keycloak redirects back to the app with a short-lived **authorization code**.
4. The app exchanges the code for tokens by calling Keycloak's token endpoint directly (back-channel).
5. Keycloak returns an **access token**, an **ID token**, and usually a **refresh token**.

**Why it's safe:** tokens never pass through the browser URL, only the one-time code does. PKCE (section 4) protects that code.

### 2.2 Client Credentials Flow

**Use case:** machine-to-machine calls with no user, such as backend services, cron jobs, and microservices.

1. The service sends its `client_id` and `client_secret` (or a signed JWT or certificate) to the token endpoint.
2. Keycloak returns an access token representing the **service account** itself.

No login page and no refresh token. The service just requests a new token when needed.

### 2.3 Device Authorization Flow

**Use case:** devices with no browser or poor input: smart TVs, CLI tools, IoT.

1. The device asks Keycloak for a **device code** and a **user code**.
2. The device shows: "Go to the verification URL and enter code ABCD-1234."
3. The user opens that URL on a phone or laptop, logs in, and enters the code.
4. Meanwhile the device polls Keycloak. Once the user approves, it receives tokens.

### 2.4 Refresh Token Flow

**Use case:** keeping a user logged in without asking for their password again.

Access tokens are short-lived (for example 5 minutes). When one expires, the app sends the refresh token to Keycloak and gets a new access token. Keycloak can **rotate** refresh tokens (each is single-use) to limit damage if one leaks.

### 2.5 Token Exchange

**Use case:** swapping one token for another:

- Service A calls Service B on behalf of the user (delegation)
- Exchanging an external token (Google, GitHub) for a Keycloak token
- Getting a token with a different audience or scope

### 2.6 CIBA (Client-Initiated Backchannel Authentication)

**Use case:** the user authenticates on a *different device* than where the app runs, for example a call-center agent triggering a bank approval that the customer confirms on their phone.

The app tells Keycloak who the user is. Keycloak sends them a push or notification. The user approves on their device. The app polls and receives tokens.

### 2.7 Legacy flows (avoid in new projects)

| Flow | Why it's discouraged |
| --- | --- |
| Implicit | Tokens are exposed in the URL. Use Authorization Code + PKCE instead. |
| Resource Owner Password Credentials ("Direct Access Grants" in Keycloak) | The app handles the user's password directly, so no SSO or 2FA benefits. Only for trusted legacy apps or testing. |

### 2.8 Quick chooser

| Situation | Flow |
| --- | --- |
| Web app, SPA, or mobile app with users | Authorization Code + PKCE |
| Backend service, no user | Client Credentials |
| TV or CLI | Device Flow |
| Keep the session alive | Refresh Token |
| Call another service as the user | Token Exchange |
| Approval on a separate device | CIBA |

## 3. Keycloak's built-in Authentication Flows (the login screen steps)

In the Admin Console under **Authentication → Flows**, a flow is a configurable sequence of steps (**authenticators**) that run when someone logs in.

**Built-in flows**

- **Browser:** the normal login page flow
- **Direct Grant:** used by the password grant (REST login)
- **Registration:** self-signup
- **Reset Credentials:** "forgot password"
- **First Broker Login:** what happens the first time someone logs in via an external identity provider such as Google

**Requirement levels for each step**

| Level | Meaning |
| --- | --- |
| Required | Must succeed |
| Alternative | At least one alternative in the group must succeed (for example password **or** passkey) |
| Conditional | Runs only if a condition is met (for example ask for OTP only if the user has it configured) |
| Disabled | Skipped |

**Example:** the default Browser flow first checks for an existing SSO session cookie (so logged-in users skip the login page), otherwise shows username and password, then asks for OTP if conditions apply.

You can copy a flow and customize it: add WebAuthn/passkeys, require 2FA only for admins, or add a custom authenticator written in Java.

## 4. PKCE deep dive

### 4.1 The problem it solves

In the plain Authorization Code flow, the authorization code travels through the browser (the redirect URL). On mobile and in SPAs it can be intercepted (custom URL schemes, browser history, logs, injected scripts). A normal confidential client proves its identity with a `client_secret` when redeeming the code, but **public clients** (SPAs and mobile apps) can't keep a secret.

PKCE (pronounced "pixy", Proof Key for Code Exchange) gives every login attempt its own **one-time secret**, created on the fly.

### 4.2 The core idea

1. Before redirecting, the app invents a random secret: the **`code_verifier`**.
2. It sends only a **hash** of it: the **`code_challenge`**. A hash can't be reversed.
3. Keycloak stores the challenge alongside the authorization code it issues.
4. When redeeming the code, the app sends the **original verifier**. Keycloak hashes it and compares with the stored challenge.

An attacker who steals the code only gets the hash side, not the verifier, so the code is useless to them.

### 4.3 Step 0: generate verifier and challenge

- `code_verifier`: random string, 43 to 128 characters from `A-Z a-z 0-9 - . _ ~`
- `code_challenge` = `BASE64URL( SHA256( code_verifier ) )`

```javascript
function randomString(len = 64) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    .slice(0, len);
}

async function sha256Base64Url(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const codeVerifier  = randomString(64);
const codeChallenge = await sha256Base64Url(codeVerifier);
const state = randomString(32);
const nonce = randomString(32);
// Store state, nonce and codeVerifier for later steps
```

### 4.4 Step 1: redirect to Keycloak (authorization request)

```
GET https://auth.example.com/realms/myrealm/protocol/openid-connect/auth
  ?response_type=code
  &client_id=my-spa
  &redirect_uri=https://app.example.com/callback
  &scope=openid profile email
  &state=Xy7...            (CSRF protection)
  &nonce=Ab3...            (binds the ID token to this request)
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

Keycloak shows the login page (or skips it if the user has an SSO session) and stores the `code_challenge` with this login attempt.

### 4.5 Step 2: Keycloak redirects back with the code

```
https://app.example.com/callback
  ?code=a1b2c3...          (short-lived, single-use)
  &state=Xy7...
  &session_state=...
  &iss=https://auth.example.com/realms/myrealm
```

The app **must check that `state` matches** what it saved. If not, it aborts.

### 4.6 Step 3: exchange the code for tokens (back-channel)

```
POST https://auth.example.com/realms/myrealm/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=my-spa
&code=a1b2c3...
&redirect_uri=https://app.example.com/callback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Keycloak computes `BASE64URL(SHA256(code_verifier))`, compares it with the stored challenge, and if they match returns:

```json
{
  "access_token": "eyJhbGciOi...",
  "expires_in": 300,
  "refresh_token": "eyJhbGciOi...",
  "refresh_expires_in": 1800,
  "id_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "scope": "openid profile email"
}
```

If the verifier is wrong or missing, you get `400 invalid_grant` (PKCE verification failed).

### 4.7 Step 4: use the tokens

- Send `Authorization: Bearer <access_token>` to your API.
- Your API validates the JWT: signature (using Keycloak's public keys at `/realms/myrealm/protocol/openid-connect/certs`), `iss`, `aud`, `exp`.
- The client validates the **ID token**, including that its `nonce` claim matches the stored nonce.

### 4.8 Sequence at a glance

```
App                     Browser                  Keycloak
 |-- make verifier+challenge                         |
 |-- redirect w/ challenge ------------------------->|
 |                          |<-- login page ---------|
 |                          |--- credentials ------->|  (stores challenge + code)
 |<-- redirect w/ code (+state) ---------------------|
 |-- POST code + verifier ---------------------------->|
 |                         hash(verifier) == challenge?
 |<-- access / ID / refresh tokens ---------------------|
```

### 4.9 Configuring it in Keycloak

In the Admin Console, open **Clients → your client**:

- **Client authentication: Off** (public client, for SPAs and mobile)
- **Standard flow: On** (this is the Authorization Code flow)
- **Implicit flow** and **Direct access grants: Off**
- **Valid redirect URIs:** exact URLs, avoid wildcards
- **Web origins:** your app's origin (CORS on the token endpoint)
- **Advanced → Advanced settings → Proof Key for Code Exchange Code Challenge Method: `S256`.** This **enforces** PKCE, so requests without a valid challenge are rejected. If left empty, Keycloak accepts PKCE when the client sends it but doesn't require it.

### 4.10 `state` vs `nonce` vs PKCE

| Parameter | Protects against | Checked by |
| --- | --- | --- |
| `state` | CSRF: someone tricking your app into accepting a foreign callback | Your app, on the redirect |
| `nonce` | ID token replay or injection | Your app, inside the ID token |
| PKCE | Authorization code theft or injection | Keycloak, at the token endpoint |

Use all three.

### 4.11 Common mistakes

- **Using `plain` instead of `S256`.** `plain` sends the verifier as the challenge, so anyone who sees the first request knows the secret. Use S256 only.
- **Low-entropy or reused verifiers.** Generate a fresh, cryptographically random one per login attempt.
- **Skipping `state` validation.** PKCE doesn't replace it.
- **Wildcard redirect URIs.** They widen the attack surface. Register exact URIs.
- **Storing tokens in `localStorage`.** Vulnerable to XSS. Prefer in-memory storage, or a backend-for-frontend (BFF) that keeps tokens server-side behind an HttpOnly cookie.
- **Using the password grant "because it's simpler."** You lose SSO, 2FA, and social login.

### 4.12 Should confidential clients use PKCE too?

Yes. OAuth 2.1 and current security best practice recommend PKCE for **all** clients, including server-side apps with a client secret. It adds protection against code injection at almost no cost.

### 4.13 Don't hand-roll it

Use a maintained library, which does all of this for you:

- JS/SPA: `keycloak-js` (set `pkceMethod: 'S256'`), `oidc-client-ts`, `angular-auth-oidc-client`
- Mobile: AppAuth (iOS/Android)
- Server: Spring Security, `openid-client` (Node), and others

## 5. The corrected flow summary (your recap, fixed)

1. App generates `state`, `nonce`, `code_verifier`, and `code_challenge`. It **stores state, nonce, and verifier**.
2. App redirects the user to Keycloak with `code_challenge` + `code_challenge_method=S256`, `state`, `nonce`, `redirect_uri`, plus `client_id`, `response_type=code`, and `scope=openid ...`.
3. User logs in. Keycloak generates a `code`, stores it with the `code_challenge` (and the nonce), and redirects to the callback URL with `code` + `state`.
4. App checks that `state` matches the stored value. If not, it aborts.
5. App POSTs `code` + `code_verifier` to the token endpoint (with `grant_type`, `client_id`, and `redirect_uri`). Keycloak hashes the verifier and compares it with the stored challenge. If they match, it returns the tokens.
6. App validates the **ID token** (signature, `iss`, `aud`, `exp`) and checks that its **`nonce` claim equals the stored nonce**.

**Two easy-to-miss points**

- The nonce is checked in the **ID token**, not the access token. The access token is meant for your API.
- `redirect_uri` in step 5 must match the one used in step 2 exactly.

## 6. Self-check questions

1. Which flow should a SPA with logged-in users use? *Authorization Code + PKCE.*
2. Which flow fits a nightly backend job with no user? *Client Credentials.*
3. What does PKCE protect against? *An attacker stealing the authorization code and exchanging it for tokens.*
4. Which flow shows a short code on a TV to be entered on a phone? *Device Authorization Flow.*
5. Which requirement level means "at least one in this group must succeed"? *Alternative.*
6. Where is the `nonce` verified? *In the ID token, by the client app.*
7. Who verifies the `code_verifier`, and where? *Keycloak, at the token endpoint.*
8. Why is `S256` preferred over `plain`? *`plain` exposes the verifier in the first request, defeating the purpose.*

## 7. One-page cheat sheet

- Users + browser or mobile app: **Authorization Code + PKCE (S256)**
- No user: **Client Credentials**
- Limited-input device: **Device Flow**
- Stay logged in: **Refresh Token** (with rotation)
- Delegation or swapping tokens: **Token Exchange**
- Approval on another device: **CIBA**
- Avoid: **Implicit**, **Password grant**
- Always: exact redirect URIs, validate `state`, validate ID token `nonce`, keep tokens out of `localStorage`

## 8. SPA + API architecture

When you have a SPA and a separate API, the SPA logs in with Keycloak directly and the API only validates tokens.

```
SPA                      Keycloak                   API
 |-- Auth Code + PKCE ---->|                          |
 |<---- access token ------|                          |
 |                                                    |
 |-- GET /orders, Authorization: Bearer <token> ----->|
 |                                   validates JWT locally
 |<---------------- 200 / 401 / 403 ------------------|
```

1. **The SPA talks to Keycloak directly** (Authorization Code + PKCE, public client) and receives the tokens.
2. **The SPA sends the access token to the API** in the `Authorization: Bearer` header.
3. **The API validates the JWT itself**. It does not call Keycloak on every request.

**What the API checks** (it is a *resource server*; it downloads Keycloak's public keys once from the JWKS endpoint, `/realms/myrealm/protocol/openid-connect/certs`, and caches them):

- **Signature**, using the public key matching the token's `kid` header
- **`iss`**: must be your realm URL
- **`exp`** and `nbf`: token must be within its lifetime
- **`aud`**: token must be meant for *this* API
- **Authorization**: roles or scopes in the token decide whether the request is allowed

It returns **401** if the token is missing or invalid, and **403** if the token is valid but the user lacks permission. The API never redirects to a login page; that is the SPA's job.

**Details people often miss**

- **Audience:** by default the access token's `aud` won't contain your API. Add an **Audience mapper** (or audience client scope) in Keycloak so the token includes your API's client ID, and make the API reject tokens without it.
- **Key rotation:** cache the JWKS and re-fetch when you see an unknown `kid`. Never hardcode the public key.
- **Use the access token, not the ID token**, to call the API. The ID token is for the SPA to learn who logged in.
- **Revocation lag:** local validation means a token stays valid until it expires, even if the user is logged out or disabled. Keep access tokens short-lived (about 5 minutes). For instant revocation, use Keycloak's **token introspection** endpoint at the cost of a network call.
- **CORS:** set *Web origins* in Keycloak for the SPA's token requests, and CORS on the API for the SPA's origin.
- **API calling other services:** on behalf of the user, use Token Exchange; as itself, use Client Credentials.
- **BFF alternative:** a backend-for-frontend does the login, keeps tokens server-side, and gives the SPA an HttpOnly session cookie. Safer against XSS token theft.

## 9. ASP.NET Core API configuration (Program.cs)

This is a full resource-server setup for .NET 8 or later (minimal hosting model). It covers the `builder.Services.Add...` registrations and the `app.Use...` middleware pipeline, with an explanation of each.

**NuGet packages**

- `Microsoft.AspNetCore.Authentication.JwtBearer`
- `Swashbuckle.AspNetCore` (only if you want Swagger)

### 9.1 Full Program.cs

```csharp
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

var kc        = builder.Configuration.GetSection("Keycloak");
var authority = kc["Authority"]!;   // https://auth.example.com/realms/myrealm
var audience  = kc["Audience"]!;    // my-api  (client ID of the API)
var spaOrigin = kc["SpaOrigin"]!;   // https://app.example.com

// ===================== SERVICES =====================

builder.Services.AddControllers();
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

builder.Services.AddCors(o => o.AddPolicy("Spa", p => p
    .WithOrigins(spaOrigin)
    .WithHeaders("Authorization", "Content-Type")
    .WithMethods("GET", "POST", "PUT", "DELETE")));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;                       // where to find signing keys (OIDC discovery)
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.MapInboundClaims = false;                    // keep original claim names (sub, preferred_username)

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = authority,
            ValidateAudience         = true,
            ValidAudience            = audience,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            ClockSkew                = TimeSpan.FromSeconds(30),
            NameClaimType            = "preferred_username",
            RoleClaimType            = "role"
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = ctx =>
            {
                MapKeycloakRoles(ctx.Principal!, audience);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(o =>
{
    // Secure by default: every endpoint needs a valid token unless [AllowAnonymous]
    o.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();

    o.AddPolicy("AdminOnly", p => p.RequireRole("admin"));

    o.AddPolicy("OrdersRead", p => p.RequireAssertion(ctx =>
        ctx.User.FindFirstValue("scope")?.Split(' ').Contains("orders:read") == true));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
        }] = Array.Empty<string>()
    });
});

// ===================== MIDDLEWARE PIPELINE =====================

var app = builder.Build();

app.UseForwardedHeaders();
app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("Spa");
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health").AllowAnonymous();
app.MapControllers();

app.Run();

// ===================== HELPERS =====================

// Keycloak puts roles in nested JSON claims, not in a flat "role" claim.
// realm_access        -> { "roles": ["admin", ...] }
// resource_access     -> { "my-api": { "roles": ["orders-manager"] } }
static void MapKeycloakRoles(ClaimsPrincipal principal, string clientId)
{
    if (principal.Identity is not ClaimsIdentity identity) return;
    AddRoles(identity, principal.FindFirst("realm_access")?.Value, null);
    AddRoles(identity, principal.FindFirst("resource_access")?.Value, clientId);
}

static void AddRoles(ClaimsIdentity identity, string? json, string? clientId)
{
    if (string.IsNullOrEmpty(json)) return;
    using var doc = JsonDocument.Parse(json);
    var node = doc.RootElement;

    if (clientId is not null && !node.TryGetProperty(clientId, out node)) return;

    if (node.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
    {
        foreach (var r in roles.EnumerateArray())
            if (r.GetString() is { } role)
                identity.AddClaim(new Claim("role", role));
    }
}
```

### 9.2 Example controller

```csharp
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/orders")]
public class OrdersController : ControllerBase
{
    // Any authenticated user (fallback policy)
    [HttpGet("me")]
    public IActionResult Me() => Ok(new
    {
        sub  = User.FindFirstValue("sub"),
        name = User.FindFirstValue("preferred_username")
    });

    // Needs the orders:read scope
    [HttpGet]
    [Authorize(Policy = "OrdersRead")]
    public IActionResult List() => Ok(Array.Empty<string>());

    // Needs the admin role
    [HttpDelete("{id:int}")]
    [Authorize(Policy = "AdminOnly")]
    public IActionResult Delete(int id) => NoContent();

    // No token needed
    [HttpGet("public-info")]
    [AllowAnonymous]
    public IActionResult Info() => Ok("hello");
}
```

### 9.3 What each service registration does

| Configuration | What it does | Which part of the flow it serves |
| --- | --- | --- |
| `AddControllers()` | Registers MVC controllers, model binding, and JSON serialization | The API endpoints themselves |
| `AddProblemDetails()` | Makes errors (exceptions, 401, 403, 404) return standard `application/problem+json` bodies | Consistent error responses the SPA can parse |
| `AddHealthChecks()` | Registers health check services used by `/health` | Container and load balancer probes; no token involved |
| `Configure<ForwardedHeadersOptions>` | Tells ASP.NET to trust `X-Forwarded-For` and `X-Forwarded-Proto` from a reverse proxy | Makes the API see the real scheme (https) and client IP behind nginx, ingress, etc. |
| `AddCors(...)` | Defines the "Spa" CORS policy: allowed origin, headers, and methods | Lets the browser SPA call the API from a different origin, including the `Authorization` header |
| `AddAuthentication(JwtBearerDefaults.AuthenticationScheme)` | Makes JWT Bearer the default scheme for identifying the caller | Step 3 of the SPA + API flow: reading the `Authorization: Bearer` header |
| `AddJwtBearer(options => ...)` | Configures how tokens are validated (details in the next table) | JWT validation using Keycloak's public keys |
| `AddAuthorization(...)` | Defines policies and the fallback policy | The 403 decision: is this valid user allowed to do this? |
| `AddEndpointsApiExplorer()` + `AddSwaggerGen(...)` | Generates OpenAPI docs and adds a Bearer "Authorize" button in Swagger UI | Developer testing only |

### 9.4 What each `AddJwtBearer` option does

| Option | What it does | Why it matters |
| --- | --- | --- |
| `Authority` | Base URL of the Keycloak realm. The API fetches `/.well-known/openid-configuration` from it, then the JWKS (public keys) | This is how the API gets the public key, once, then caches it and refreshes on key rotation |
| `RequireHttpsMetadata` | Requires HTTPS when downloading the discovery document | Keep `true` in production; relax only in local dev with HTTP Keycloak |
| `MapInboundClaims = false` | Stops .NET from renaming claims to old WS-Federation URIs (`sub` would become a long `...nameidentifier` URI) | Lets you use `sub`, `preferred_username`, `scope` as they appear in the token |
| `ValidateIssuer` / `ValidIssuer` | Token's `iss` must equal your realm URL | Rejects tokens from other realms or other identity providers |
| `ValidateAudience` / `ValidAudience` | Token's `aud` must contain your API's client ID | Rejects tokens meant for other apps (needs the Audience mapper in Keycloak) |
| `ValidateLifetime` | Checks `exp` and `nbf` | Rejects expired tokens |
| `ValidateIssuerSigningKey` | Requires a valid signature from a trusted key | Rejects forged or tampered tokens |
| `ClockSkew` | Tolerance for clock differences (default is 5 minutes, which is long) | Smaller value means expired tokens are rejected closer to their real expiry |
| `NameClaimType` | Which claim populates `User.Identity.Name` | Keycloak uses `preferred_username` |
| `RoleClaimType` | Which claim `IsInRole` and `RequireRole` look at | Must match the claim type you create in `OnTokenValidated` |
| `Events.OnTokenValidated` | Runs after the token is validated; here it converts Keycloak's nested role JSON into flat `role` claims | Makes `RequireRole("admin")` and `[Authorize(Roles = "admin")]` work |

### 9.5 What each authorization setting does

| Setting | What it does |
| --- | --- |
| `FallbackPolicy = RequireAuthenticatedUser` | Applies to every endpoint that has no explicit `[Authorize]` or `[AllowAnonymous]`. Secure by default: you must opt out to make something public |
| `AddPolicy("AdminOnly", ...)` | Requires the `admin` role (from `realm_access.roles` or your client's roles) |
| `AddPolicy("OrdersRead", ...)` | Requires the `orders:read` scope. The `scope` claim is one space-separated string, so it is split before checking |

### 9.6 What each middleware does, in order

| Order | Middleware | What it does |
| --- | --- | --- |
| 1 | `UseForwardedHeaders()` | Applies proxy headers first so everything after sees the real scheme and IP |
| 2 | `UseExceptionHandler()` | Catches unhandled exceptions and returns a ProblemDetails 500 instead of a stack trace |
| 3 | `UseStatusCodePages()` | Gives empty 401, 403, and 404 responses a ProblemDetails body |
| 4 | `UseSwagger()` / `UseSwaggerUI()` | Serves OpenAPI JSON and UI, development only |
| 5 | `UseHttpsRedirection()` | Redirects HTTP to HTTPS (skip if TLS terminates at a proxy and you handle it there) |
| 6 | `UseCors("Spa")` | Answers the browser's preflight `OPTIONS` request and adds CORS headers |
| 7 | `UseAuthentication()` | Reads the Bearer token, validates it, and builds `HttpContext.User`. A bad token yields an anonymous user |
| 8 | `UseAuthorization()` | Checks the endpoint's policy against `User`. Returns **401** if not authenticated, **403** if authenticated but not allowed |
| 9 | `MapHealthChecks(...).AllowAnonymous()` | Public `/health` endpoint that bypasses the fallback policy |
| 10 | `MapControllers()` | Routes requests to controller actions |

### 9.7 Why the order matters

- **`UseCors` before `UseAuthentication`:** the browser's preflight `OPTIONS` request carries no token. If authentication ran first, the preflight would fail with 401 and the SPA would see a CORS error.
- **`UseAuthentication` before `UseAuthorization`:** authorization needs `User` to be populated already.
- **`UseForwardedHeaders` first:** otherwise HTTPS redirection and issuer checks may see `http` instead of `https`.

### 9.8 Request lifecycle with this setup

1. SPA sends `GET /api/orders` with `Authorization: Bearer <access_token>`.
2. `UseCors` allows the origin.
3. `UseAuthentication` / JwtBearer checks signature (cached Keycloak key), `iss`, `aud`, and `exp`; `OnTokenValidated` flattens roles.
4. `UseAuthorization` evaluates `OrdersRead`. Missing scope returns **403**; invalid or missing token returns **401**.
5. The controller action runs and returns data.

### 9.9 Pitfalls

- **Audience mismatch** is the most common failure (`IDX10214: Audience validation failed`). Add an Audience mapper in Keycloak for your API's client ID.
- **Issuer mismatch in Docker:** if the API reaches Keycloak at an internal URL (`http://keycloak:8080/...`) but tokens carry the public URL as `iss`, set `options.MetadataAddress` to the internal discovery URL while keeping `ValidIssuer` as the public URL.
- **Roles not recognized:** Keycloak roles are nested JSON, so without the `OnTokenValidated` mapping `RequireRole` never matches.
- **Forgetting `MapInboundClaims = false`:** `User.FindFirst("sub")` returns null because the claim was renamed.
- **Wildcard CORS** (`AllowAnyOrigin`) is unnecessary here and weakens security. List the exact SPA origin.
- **Long clock skew** lets expired tokens work for up to 5 more minutes by default.
- **Not caching or validating keys yourself:** let JwtBearer handle JWKS download, caching, and rotation.
