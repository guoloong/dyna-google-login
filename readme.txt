=== Dyna Google Login ===
Contributors: dyna-nutrition
Tags: woocommerce, google, oauth, login, social login
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
WC requires at least: 5.0
Stable tag: 1.0.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Adds a "Continue with Google" button to the WooCommerce My Account page. Server-side OAuth 2.0, no JavaScript SDK, no external dependencies.

== Description ==

A focused, dependency-free Google sign-in plugin for the WooCommerce My Account page.

Features:

* Server-side OAuth 2.0 authorization-code flow — no JavaScript SDK loaded on the page.
* Auto-creates WordPress users as WooCommerce customers.
* Silently links existing WordPress accounts by email match (toggleable).
* Stores Google `sub` (stable user ID) in user_meta for re-login.
* Preserves guest cart across Google login.
* JWT signature verified against Google's published JWKS (cached 1h).
* Shortcode `[dyna_google_login]` for Divi / custom themes.
* No Composer, no npm, no third-party runtime services.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/dyna-google-login/`, or zip and upload via WP Admin → Plugins → Add New → Upload Plugin.
2. Activate the plugin through the "Plugins" menu in WordPress.
3. Go to **Settings → Dyna Google Login**.
4. Paste your Google **Client ID** and **Client Secret**.
5. Copy the **Authorized redirect URI** shown on the settings page into your Google Cloud Console → APIs & Services → Credentials → your OAuth client.
6. Make sure your OAuth consent screen is configured (External user type, support email, scopes: openid + email + profile).
7. If your app is still in "Testing" mode, add your test Gmail addresses under "Test users" — otherwise Google will block them.
8. Test in an incognito window from `/my-account/`.

== Configuration ==

* **Client ID / Secret** — From Google Cloud Console → APIs & Services → Credentials.
* **Button text** — Customize the label. Default: "Continue with Google".
* **Auto-link by email** — If a Google account's email matches an existing WordPress user, log them in as that user silently. Recommended.
* **Default role for new users** — Customer (WooCommerce) or Subscriber.

== Frequently Asked Questions ==

= Does this work with Divi? =

Yes. Auto-injection on the WooCommerce login form works for the default WC form. If Divi replaces the form on your My Account page, drop the shortcode `[dyna_google_login]` into a Text or Code module on that page.

= Will it conflict with Nextend Social Login or other Google login plugins? =

It will show a soft admin warning. You can run both, but you'll see duplicate buttons on `wp-login.php`. Consider deactivating the other plugin for cleanliness.

= Does it store Google access tokens? =

No. Only the `sub` (Google's stable user ID) and `picture` URL are kept in `wp_usermeta` so future logins can match by sub. Tokens are dropped after use.

= What about the user's password? =

New users get a random 32-character password they never see. They can request a password reset email later if they want a password login as a backup.

== Changelog ==

= 1.0.2 =
* **Bug fix:** Logged-in users who clicked "Dashboard" in the admin bar were bounced to `/wp-login.php?reauth=1` after Google login. Front-end (orders, admin bar) worked, but `/wp-admin/` rejected the auth cookie. Cause: behind Cloudflare, `is_ssl()` returns false at the origin, so `wp_set_auth_cookie()` was writing a non-Secure auth cookie while `/wp-admin/` was looking for `SECURE_AUTH_COOKIE` (because of a Flexible-SSL shim or similar on the admin side). Fix: detect HTTPS via `is_ssl()`, `HTTP_X_FORWARDED_PROTO`, and Cloudflare's `CF-Visitor` JSON header, and pass the result as `$secure` to `wp_set_auth_cookie()`. Also calls `wp_clear_auth_cookie()` first to match the standard `wp_signon()` flow. Added regression tests for all three HTTPS-detection paths.

= 1.0.1 =
* **Bug fix:** Second-time Google login was crashing with `TypeError: Argument 1 passed to update_existing_user() must be an instance of WP_User, instance of stdClass given`. Cause: `get_users()` was called with a `fields` list, which makes WordPress return partial `stdClass` objects instead of full `WP_User` objects. The `fields` arg is now removed; users are matched by sub via full `WP_User` queries. A regression test was added.

= 1.0.0 =
* Initial release.
