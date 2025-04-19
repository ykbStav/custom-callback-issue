// lib/auth.ts
import { type AuthOptions } from "next-auth";
import { type OAuthConfig } from "next-auth/providers/index";

const vkProvider: OAuthConfig<any> = {
  id: "vk",
  name: "VK",
  type: "oauth",
  version: "2.0",
  clientId: process.env.AUTH_VK_ID,
  clientSecret: process.env.AUTH_VK_SECRET,
  authorization: {
    url: "https://id.vk.com/authorize",
    params: {
      response_type: "code",
      scope: "email",
      code_challenge_method: "S256", // VK require PKCE
    },
  },
  token: {
    async request(context: any) {
      const { provider, checks, params } = context;
      const code_verifier = checks.code_verifier;
      const code = params.code;

      const formData = new URLSearchParams({
        client_id: provider.clientId!,
        grant_type: "authorization_code",
        code,
        code_verifier,
        redirect_uri: provider.callbackUrl,
        // ISSUE: Custom query parameters like `device_id` are removed from the callback URL
        // because NextAuth uses `openid-client` -> `client.callbackParams()`.
        // This function strips all non-standard OAuth2/OpenID params, including `device_id`.
        //
        // As a result, `params.device_id` is undefined in the `token.request()` function,
        // even if it was included in the original authorization redirect.
        //
        // Workaround needed to access state params like `device_id` in `token.request()`.
        device_id: params.device_id,
      });

      const res = await fetch("https://id.vk.com/oauth2/auth", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: formData,
      });

      const data = await res.json();

      if (!res.ok || !data.access_token) {
        throw new Error(
          `VK token exchange failed: ${res.status} ${
            res.statusText
          }\nResponse: ${JSON.stringify(data)}`
        );
      }

      return {
        tokens: {
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          id_token: data.id_token,
          expires_in: data.expires_in,
          scope: data.scope,
          token_type: "bearer",
        },
      };
    },
  },
  userinfo: {
    url: "https://api.vk.com/method/users.get?fields=photo_100&v=5.131",
  },
  checks: ["pkce", "state"],
  profile(profile: any) {
    return {
      id: profile.id,
      name: [profile.first_name, profile.last_name].filter(Boolean).join(" "),
      email: profile.email ?? null,
      image: profile.photo_100,
    };
  },
};

export const authOptions: AuthOptions = {
  secret: process.env.AUTH_SECRET,
  providers: [vkProvider],
  debug: process.env.NODE_ENV == "development",
};
