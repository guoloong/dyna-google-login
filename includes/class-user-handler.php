<?php
namespace DynaGoogleLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * After a verified Google login, find or create the corresponding WordPress user
 * and log them in.
 *
 * Linking policy (configurable in admin):
 *   - auto_link=1 (default): If a WP user with the same email already exists, log them in as that user.
 *     The Google `sub` is recorded in user_meta so future logins can find them by sub even if the email changes.
 *   - auto_link=0: If a user with the same email already exists, refuse and return WP_Error.
 *
 * On user creation:
 *   - Username is generated from the email local-part (with collision suffixes).
 *   - Random 32-char password (user can reset later if they want a password login).
 *   - Role defaults to 'customer' (WooCommerce) or 'subscriber' per admin setting.
 *   - `user_register` action is fired so WooCommerce's customer hooks run.
 *   - We don't send the new-user email — Google already verified the address.
 */
class User_Handler {

	/** @var Settings */
	private $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * @param array  $claims     Verified Google JWT claims.
	 * @param string $return_to  Where to send the user after login.
	 * @return array|\WP_Error   ['redirect' => url] on success, WP_Error on failure.
	 */
	public function handle( $claims, $return_to = '' ) {
		$email      = strtolower( trim( $claims['email'] ?? '' ) );
		$sub        = $claims['sub'] ?? '';
		$full_name  = $claims['name'] ?? '';
		$first_name = $claims['given_name'] ?? '';
		$last_name  = $claims['family_name'] ?? '';
		$picture    = $claims['picture'] ?? '';

		if ( '' === $email || '' === $sub ) {
			return new \WP_Error( 'missing_claims', 'Email and sub are required from Google.' );
		}

		// Look up an existing WP user. Prefer sub match (most reliable), fall back to email.
		$user = $this->find_user_by_sub( $sub );
		if ( ! $user ) {
			$user = get_user_by( 'email', $email );
		}

		// Auto-link policy: if a user with this email already exists, only proceed if enabled.
		if ( $user && ! $this->settings->get( 'auto_link', 1 ) ) {
			return new \WP_Error( 'auto_link_disabled', __( 'An account with this email already exists. Please sign in with your password.', 'dyna-google-login' ) );
		}

		if ( $user ) {
			$this->update_existing_user( $user, $sub, $picture );
		} else {
			$user = $this->create_user( $email, $sub, $full_name, $first_name, $last_name, $picture );
			if ( is_wp_error( $user ) ) {
				return $user;
			}
		}

		// Log the user in. WooCommerce's session handler will migrate the guest cart to this user.
		$this->login_user( $user );

		$redirect = $return_to ? $return_to : $this->default_redirect();
		return [ 'redirect' => $redirect ];
	}

	/**
	 * @return \WP_User|null
	 */
	private function find_user_by_sub( $sub ) {
		// IMPORTANT: do NOT pass `fields` here. The default is 'all' which returns WP_User objects.
		// Passing a fields list (e.g. ['ID', 'user_login']) makes get_users() return stdClass with
		// only those properties — which then breaks the \WP_User type hint downstream.
		$users = get_users( [
			'meta_key'   => 'dyna_google_sub', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
			'meta_value' => $sub, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
			'number'     => 1,
		] );
		if ( ! empty( $users ) ) {
			return $users[0];
		}
		return null;
	}

	private function update_existing_user( \WP_User $user, $sub, $picture ) {
		// Persist sub so we can match by sub next time even if email changes.
		update_user_meta( $user->ID, 'dyna_google_sub', $sub );
		if ( ! empty( $picture ) ) {
			update_user_meta( $user->ID, 'dyna_google_picture', esc_url_raw( $picture ) );
		}
		update_user_meta( $user->ID, 'dyna_google_last_login', time() );
	}

	/**
	 * @return \WP_User|\WP_Error
	 */
	private function create_user( $email, $sub, $full_name, $first_name, $last_name, $picture ) {
		$default_role = $this->settings->get( 'default_role', 'customer' );
		$username     = $this->generate_unique_username( $email );

		$user_id = wp_insert_user( [
			'user_login'   => $username,
			'user_email'   => $email,
			'user_pass'    => wp_generate_password( 32, true, true ),
			'display_name' => '' !== $full_name ? $full_name : $email,
			'first_name'   => $first_name,
			'last_name'    => $last_name,
			'role'         => $default_role,
		] );

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		update_user_meta( $user_id, 'dyna_google_sub', $sub );
		if ( ! empty( $picture ) ) {
			update_user_meta( $user_id, 'dyna_google_picture', esc_url_raw( $picture ) );
		}
		update_user_meta( $user_id, 'dyna_google_last_login', time() );

		// Fire user_register so WooCommerce's customer_created hook runs, transactional emails go out, etc.
		// We skip wp_new_user_notification_email to avoid the default "your username and password" email,
		// since this user has no usable password — but other plugins listening on user_register still get notified.
		do_action( 'user_register', $user_id );

		return get_user_by( 'id', $user_id );
	}

	/**
	 * Generate a unique WordPress username from the email's local-part.
	 * Falls back to "user" if the local-part sanitizes to empty.
	 * Appends a numeric suffix on collision.
	 */
	private function generate_unique_username( $email ) {
		$base = strtolower( trim( explode( '@', $email, 2 )[0] ) );
		$base = sanitize_user( $base, true );
		if ( '' === $base ) {
			$base = 'user';
		}

		$username = $base;
		$i        = 1;
		while ( username_exists( $username ) ) {
			$username = $base . $i;
			$i++;
			if ( $i > 1000 ) {
				// Pathological case — bail with a random suffix.
				$username = $base . '_' . wp_generate_password( 4, false, false );
				break;
			}
		}
		return $username;
	}

	private function login_user( \WP_User $user ) {
		// Clear any pre-existing auth cookies first. This matches what wp_signon() does
		// during a standard form login, and prevents stale auth state from interfering
		// when a user logs in via Google after a partial form-login attempt.
		wp_clear_auth_cookie();

		// Switch the global user context so WooCommerce's session handler migrates
		// the guest cart to the new user.
		wp_set_current_user( $user->ID, $user->user_login );

		// Detect HTTPS robustly. Behind Cloudflare and most reverse proxies, is_ssl()
		// returns false at the origin (because the proxy → origin connection is HTTP),
		// even though the browser → proxy connection is HTTPS. Without forcing the
		// Secure flag here, wp_set_auth_cookie() writes a non-Secure auth cookie,
		// while /wp-admin/ — which may evaluate is_ssl() differently due to a
		// Flexible-SSL shim plugin or wp-config tweak — expects SECURE_AUTH_COOKIE.
		// Result: the user appears logged in (LOGGED_IN_COOKIE works, admin bar
		// shows) but /wp-admin/ auth validation fails with reauth=1.
		$is_https = is_ssl();
		if ( ! $is_https && ! empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) {
			$is_https = strtolower( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) === 'https';
		}
		if ( ! $is_https && ! empty( $_SERVER['HTTP_CF_VISITOR'] ) ) {
			$cf = json_decode( $_SERVER['HTTP_CF_VISITOR'], true );
			if ( is_array( $cf ) && isset( $cf['scheme'] ) ) {
				$is_https = strtolower( $cf['scheme'] ) === 'https';
			}
		}

		wp_set_auth_cookie( $user->ID, true, $is_https );

		do_action( 'wp_login', $user->user_login, $user );
	}

	private function default_redirect() {
		if ( function_exists( 'wc_get_page_permalink' ) ) {
			$url = wc_get_page_permalink( 'myaccount' );
			if ( $url ) {
				return $url;
			}
		}
		return home_url( '/my-account/' );
	}
}
