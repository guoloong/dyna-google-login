<?php
namespace DynaGoogleLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Implements the OAuth 2.0 authorization-code flow with Google.
 *
 * Public surface:
 *   - get_authorize_url($return_to)   Build Google's auth URL with a fresh state token.
 *   - maybe_handle_callback()         Hooked to `init`; intercepts ?dyna_google_callback=1.
 *
 * Security:
 *   - `state` is random 32 bytes, stored in a transient keyed by the value, deleted on use.
 *   - Code is single-use on Google's side; we re-check `state` to ensure we initiated it.
 *   - All redirects go through `wp_safe_redirect` (same-host only).
 *   - Failure responses only leak a short error code in the URL — never the full message.
 */
class OAuth {

	const AUTH_URL       = 'https://accounts.google.com/o/oauth2/v2/auth';
	const TOKEN_URL      = 'https://oauth2.googleapis.com/token';
	const STATE_PREFIX   = 'dyna_gl_state_';
	const STATE_TTL      = 600; // 10 minutes — long enough for the round trip, short enough to limit replay.
	const QUERY_VAR      = 'dyna_google_callback';
	const ERROR_QUERY    = 'dyna_google_error';

	/** @var Settings */
	private $settings;

	/** @var Token_Verifier */
	private $verifier;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
		$this->verifier = new Token_Verifier();
	}

	public function register_hooks() {
		// Priority 1: intercept the callback before WP tries to render anything.
		add_action( 'init', [ $this, 'maybe_handle_callback' ], 1 );
	}

	/**
	 * Build the Google authorization URL with a freshly-generated state token.
	 * The state token is persisted in a transient so we can validate it on callback.
	 *
	 * @param string $return_to URL to send the user to after successful login. Empty = default.
	 * @return string Full Google authorize URL, or empty string if not configured.
	 */
	public function get_authorize_url( $return_to = '' ) {
		$client_id = $this->settings->get( 'client_id' );
		if ( empty( $client_id ) ) {
			return '';
		}

		// 32 random bytes, hex-encoded. wp_generate_password(false) gives only alphanumerics.
		$state = bin2hex( random_bytes( 32 ) );
		set_transient( self::STATE_PREFIX . $state, [
			'return_to' => $return_to ? esc_url_raw( $return_to ) : '',
			'created'   => time(),
			'ip_prefix' => $this->ip_prefix(), // soft binding — not strict, but rejects obviously-different clients.
		], self::STATE_TTL );

		$params = [
			'client_id'     => $client_id,
			'redirect_uri'  => $this->settings->get_redirect_uri(),
			'response_type' => 'code',
			'scope'         => 'openid email profile',
			'access_type'   => 'online',
			'prompt'        => 'select_account',
			'state'         => $state,
		];

		return add_query_arg( $params, self::AUTH_URL );
	}

	/**
	 * `init` hook handler. Exits immediately on a match — no WP template is rendered.
	 */
	public function maybe_handle_callback() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- OAuth callback, not a form post.
		if ( empty( $_GET[ self::QUERY_VAR ] ) ) {
			return;
		}

		// Mark as no-cache for any proxies (Cloudflare, Varnish) — login state must not be cached.
		nocache_headers();

		if ( ! $this->settings->is_configured() ) {
			$this->fail_with_redirect( 'not_configured' );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['error'] ) ) {
			// Google returned an error: e.g. access_denied, redirect_uri_mismatch, etc.
			$this->fail_with_redirect( 'google_' . sanitize_key( wp_unslash( $_GET['error'] ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$code  = isset( $_GET['code'] )  ? sanitize_text_field( wp_unslash( $_GET['code'] ) )  : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';

		if ( '' === $code || '' === $state ) {
			$this->fail_with_redirect( 'missing_params' );
		}

		// Validate state. Single-use: delete immediately after reading.
		$state_data = get_transient( self::STATE_PREFIX . $state );
		delete_transient( self::STATE_PREFIX . $state );

		if ( ! is_array( $state_data ) ) {
			$this->fail_with_redirect( 'state_mismatch' );
		}

		// Soft IP-prefix check — if someone snuck the state token across networks, reject.
		// (Not bulletproof — IP can change on mobile — but raises the bar.)
		if ( ! empty( $state_data['ip_prefix'] ) && $state_data['ip_prefix'] !== $this->ip_prefix() ) {
			$this->fail_with_redirect( 'state_mismatch' );
		}

		$return_to = ! empty( $state_data['return_to'] ) ? $state_data['return_to'] : '';

		// Exchange the code for tokens.
		$tokens = $this->exchange_code_for_tokens( $code );
		if ( is_wp_error( $tokens ) ) {
			$this->fail_with_redirect( $this->short_error_code( $tokens ) );
		}

		if ( empty( $tokens['id_token'] ) ) {
			$this->fail_with_redirect( 'no_id_token' );
		}

		// Verify the id_token (signature, audience, issuer, expiry, email_verified).
		$claims = $this->verifier->verify( $tokens['id_token'], $this->settings->get( 'client_id' ) );
		if ( is_wp_error( $claims ) ) {
			$this->fail_with_redirect( $this->short_error_code( $claims ) );
		}

		// Hand off to the user handler — creates or links the WP user, sets auth cookie.
		$result = Plugin::instance()->user_handler->handle( $claims, $return_to );
		if ( is_wp_error( $result ) ) {
			$this->fail_with_redirect( $this->short_error_code( $result ) );
		}

		// Success — redirect to /my-account/ (or wherever they came from).
		$target = ! empty( $result['redirect'] ) ? $result['redirect'] : $this->default_redirect();
		wp_safe_redirect( $target, 302 );
		exit;
	}

	/**
	 * POST the authorization code to Google's token endpoint.
	 *
	 * @return array|\WP_Error  Token response array or WP_Error.
	 */
	private function exchange_code_for_tokens( $code ) {
		$response = wp_remote_post( self::TOKEN_URL, [
			'timeout' => 15,
			'headers' => [ 'Accept' => 'application/json' ],
			'body'    => [
				'code'          => $code,
				'client_id'     => $this->settings->get( 'client_id' ),
				'client_secret' => $this->settings->get( 'client_secret' ),
				'redirect_uri'  => $this->settings->get_redirect_uri(),
				'grant_type'    => 'authorization_code',
			],
		] );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$http_code = wp_remote_retrieve_response_code( $response );
		$body_raw  = wp_remote_retrieve_body( $response );
		$body      = json_decode( $body_raw, true );

		if ( 200 !== $http_code || ! is_array( $body ) ) {
			// Surface Google's own error code/description in the WP_Error for debugging,
			// but the URL we redirect to only contains a short generic code.
			$detail = is_array( $body ) ? trim( ( $body['error'] ?? '' ) . ' ' . ( $body['error_description'] ?? '' ) ) : ( 'HTTP ' . $http_code );
			return new \WP_Error( 'token_exchange', 'Google token exchange failed: ' . $detail );
		}

		return $body;
	}

	/**
	 * Build a short, safe error code for the redirect URL.
	 * Strips everything except alphanumerics + underscore, caps length.
	 */
	private function short_error_code( \WP_Error $err ) {
		$code = $err->get_error_code();
		$code = strtolower( preg_replace( '/[^a-z0-9_]/i', '', $code ) );
		return substr( $code, 0, 32 ) ?: 'unknown';
	}

	/**
	 * Redirect to the login/my-account page with a generic error flag.
	 * The detailed message is intentionally NOT exposed to the URL.
	 */
	private function fail_with_redirect( $short_code ) {
		status_header( 400 );
		nocache_headers();

		$target = $this->default_redirect();
		$target = add_query_arg( self::ERROR_QUERY, '1', $target );
		// We do NOT include the actual error code in the URL — generic error UI is enough.
		// If the user reports a persistent failure, they can check WP debug.log (when WP_DEBUG_LOG is on).

		wp_safe_redirect( $target, 302 );
		exit;
	}

	/**
	 * Where to send users after a successful login (or a failed one).
	 * Prefers WooCommerce's My Account page if available.
	 */
	private function default_redirect() {
		if ( function_exists( 'wc_get_page_permalink' ) ) {
			$url = wc_get_page_permalink( 'myaccount' );
			if ( $url ) {
				return $url;
			}
		}
		return home_url( '/my-account/' );
	}

	/**
	 * First 3 octets of the client IP, for soft state-binding.
	 * Not security-grade on its own, but raises the cost of replay across networks.
	 */
	private function ip_prefix() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( '' === $ip ) {
			return '';
		}
		$parts = explode( '.', $ip );
		return implode( '.', array_slice( $parts, 0, 3 ) );
	}
}
