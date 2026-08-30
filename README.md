# Dyna Google Login

Server-side Google OAuth 2.0 sign-in for the WooCommerce **My Account** and **Checkout** pages on [dyna-nutrition.com](https://www.dyna-nutrition.com). No JavaScript SDK, no Composer, no third-party runtime services.

A focused, dependency-free plugin that adds a "Continue with Google" button to `/my-account/` and `/checkout/`. Designed to work behind reverse proxies (Cloudflare, nginx) and with custom themes (Divi, etc.) that override the default WooCommerce login form.

## Features

- 🔐 **Server-side OAuth 2.0** — full authorization-code flow, JWT signature verified against Google's published JWKS
- 🛒 **WooCommerce-aware** — auto-creates customers, preserves guest cart across login
- 🛍️ **Checkout-page support** — show the Google button at the top of the checkout form for guest checkout; after login the customer is returned to the same checkout page with their cart intact
- 🧩 **Divi / custom-theme friendly** — `[dyna_google_login]` shortcode for the Divi My Account page
- 🔁 **Smart account linking** — silently links by email match; stores Google's stable `sub` in user meta for future re-login
- ☁️ **Cloudflare-compatible** — detects HTTPS through `is_ssl()`, `X-Forwarded-Proto`, and `CF-Visitor` headers so the auth cookie is set with the correct `Secure` flag on proxied sites
- 🚫 **No external services** — no JS SDK loaded on the page, no third-party auth-as-a-service
- ✅ **Tested** — 23 regression tests covering JWT verification, account linking, the Cloudflare HTTPS-detection flow, and the checkout-page button

## Installation

1. Download `dyna-google-login.zip` from the [latest release](https://github.com/guoloong/dyna-google-login/releases).
2. WP Admin → **Plugins → Add New → Upload Plugin** → choose the zip → **Install Now** → **Activate**.
3. WP Admin → **Settings → Dyna Google Login**.
4. Paste your Google **Client ID** and **Client Secret** (create them in [Google Cloud Console](https://console.cloud.google.com/apis/credentials)).
5. Copy the **Authorized redirect URI** shown in the settings page into your OAuth client's redirect URIs.
6. Configure the OAuth consent screen (External user type, support email, scopes: `openid email profile`).
7. If your app is still in **Testing** mode, add your test Gmail under **Test users** — Google blocks unlisted users with a 403 otherwise.
8. Test in an incognito window from `/my-account/` and `/checkout/`.

### Showing the button on a Divi page

If your theme (e.g. Divi) replaces the default WooCommerce login form, drop the shortcode into the **My Account** page as a Text or Code module:

```
[dyna_google_login]
```

This renders the button regardless of what the theme does to the form underneath.

## Configuration

| Setting | Default | Description |
|---|---|---|
| **Client ID / Secret** | — | From Google Cloud Console → APIs & Services → Credentials |
| **Button text** | `Continue with Google` | Customize the label |
| **Show on Checkout page** | ✅ | Also render the button at the top of `/checkout/` (above the billing fields). After Google login the customer is returned to the same checkout page. |
| **Auto-link by email** | ✅ | Silently log in existing WP users whose email matches the Google account |
| **Default role for new users** | `Customer (WooCommerce)` | New users are created with the WooCommerce customer role |

Theming hint: the `dyna_google_login_show_on_checkout` filter lets you force-hide the checkout button from a theme or custom plugin without touching the admin setting.

## Security

- **JWT signature verification** against Google's JWKS, with 1-hour cache (and automatic flush on `kid` miss for key rotation)
- **`alg` whitelist** — only RS256 accepted; rejects `alg=none` and HS256 confusion attacks
- **Strict claim checks** — `aud` must match Client ID, `iss` must be `accounts.google.com`, `exp`/`iat` validated with 5-minute clock skew, `email_verified` must be `true`
- **CSRF protection** — random 32-byte `state` token, single-use, stored in transient for 10 minutes, with soft IP-prefix binding
- **No token persistence** — `id_token` and `access_token` are dropped after each login. Only Google's stable `sub` is kept in `wp_usermeta`
- **`wp_safe_redirect` for all redirects** — same-host only, prevents open-redirect attacks
- **Generic error messages** — failed callbacks redirect to `/my-account/` with `?dyna_google_error=1`; the detailed reason is never exposed in the URL

## Compatibility

- **WordPress:** 5.8+
- **WooCommerce:** 5.0+
- **PHP:** 7.4+ (uses typed properties, `random_bytes`, `hash_hmac`, `openssl_verify`)
- **Browser cookie handling:** works with browsers that follow RFC 6265 (all modern browsers)

### Tested against

- ✅ Cloudflare-fronted WordPress + WooCommerce (with Flexible SSL)
- ✅ Divi-themed My Account pages
- ✅ Coexistence with Nextend Social Login (soft warning, no conflict)
- ✅ Guest cart preservation across Google login
- ✅ Guest checkout with the "Continue with Google" button (v1.1.0)

## Development

```bash
# Run the test suite
php tests/run-tests.php
```

Tests stub the WordPress functions used by the plugin and exercise the security-critical paths (JWT verification, account linking, username collisions, HTTPS detection) plus UI rendering. **23/23 tests should pass.**

## Changelog

### 1.1.0
- **New:** The "Continue with Google" button now also appears on the WooCommerce Checkout page (top of the form, above the billing fields) for guest checkout. After Google login the customer is returned to the same checkout page and their guest cart is preserved.
- **New:** Added a "Placement" setting (Settings → Dyna Google Login → Show on Checkout page) so the admin can turn the checkout button off if they only want it on the My Account form.
- **New:** Added a filter `dyna_google_login_show_on_checkout` for themes/plugins to force-hide the checkout button.
- **Tweak:** Checkout-specific CSS — the button is constrained to a sensible column width and a small "or continue as guest" divider is added below it so it doesn't look orphaned.
- **Tests:** Added regression tests 21–23 covering the new setting default, the off-by-setting path, and the checkout HTML output.

### 1.0.2
- **Bug fix:** Logged-in users who clicked "Dashboard" in the admin bar were bounced to `/wp-login.php?reauth=1` after Google login. Front-end (orders, admin bar) worked, but `/wp-admin/` rejected the auth cookie. Cause: behind Cloudflare, `is_ssl()` returns false at the origin, so `wp_set_auth_cookie()` was writing a non-Secure auth cookie while `/wp-admin/` was looking for `SECURE_AUTH_COOKIE` (because of a Flexible-SSL shim or similar on the admin side). Fix: detect HTTPS via `is_ssl()`, `HTTP_X_FORWARDED_PROTO`, and Cloudflare's `CF-Visitor` JSON header, and pass the result as `$secure` to `wp_set_auth_cookie()`. Also calls `wp_clear_auth_cookie()` first to match the standard `wp_signon()` flow. Added regression tests for all three HTTPS-detection paths.

### 1.0.1
- **Bug fix:** Second-time Google login was crashing with `TypeError: Argument 1 passed to update_existing_user() must be an instance of WP_User, instance of stdClass given`. Cause: `get_users()` was called with a `fields` list, which makes WordPress return partial `stdClass` objects instead of full `WP_User` objects. The `fields` arg is now removed; users are matched by sub via full `WP_User` queries. A regression test was added.

### 1.0.0
- Initial release.

## License

GPL-2.0-or-later — see [LICENSE](LICENSE) for the full text.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

## Support

This is a focused internal plugin developed for [dyna-nutrition.com](https://www.dyna-nutrition.com). Issues and PRs welcome at [github.com/guoloong/dyna-google-login](https://github.com/guoloong/dyna-google-login).
