# Simple Discord Auth

SDA (Simple Discord Auth) aims to simplify the Discord OAuth2 flow. It enables you to easily authenticate users with their Discord accounts and retrieve their information.

Essentially, SDA handles the entire Discord OAuth2 process and returns a JWT signed using your key back to your project.

## Usage

Fix the config.toml based on config.toml.example.

Then you can use the `GET /login` endpoint to start a login.

### Redirecting back to your app

If you want the user to be redirected back to your application after authentication, provide a `redirect_uri` parameter:

`GET /login?redirect_uri=https://myapp.com/callback`

After a successful login, SDA will redirect the user to:

`https://myapp.com/callback?access_token=...&refresh_token=...`

You can whitelist allowed redirect URIs in `config.toml`:

```toml
AllowedRedirects = ["https://myapp.com"]
```

### Refreshing tokens

Use `POST /refresh` with the `refresh_token` in the JSON body to obtain a new `access_token`.