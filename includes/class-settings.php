<?php
namespace DynaGoogleLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin settings page under Settings → Dyna Google Login.
 * Stores Client ID, Secret, default role, auto-link policy, button label.
 */
class Settings {

	const OPTION_KEY = 'dyna_google_login_options';

	/** Default values, merged with stored options on read. */
	private function defaults() {
		return [
			'client_id'       => '',
			'client_secret'   => '',
			'default_role'    => 'customer',
			'auto_link'       => 1,
			'button_text'     => 'Continue with Google',
			'show_on_checkout' => 1,
		];
	}

	public function get_all() {
		$stored = get_option( self::OPTION_KEY, [] );
		if ( ! is_array( $stored ) ) {
			$stored = [];
		}
		return wp_parse_args( $stored, $this->defaults() );
	}

	public function get( $key, $default = null ) {
		$all = $this->get_all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $default;
	}

	public function is_configured() {
		$id     = $this->get( 'client_id' );
		$secret = $this->get( 'client_secret' );
		return ! empty( $id ) && ! empty( $secret );
	}

	/**
	 * Whether the Google button should be injected on the WooCommerce checkout page.
	 * Default: on. Admin can disable from Settings → Dyna Google Login.
	 */
	public function is_show_on_checkout() {
		return (bool) $this->get( 'show_on_checkout', 1 );
	}

	/**
	 * Redirect URI for Google OAuth. Must match exactly what's in Google Console.
	 * Using home_url so it works on subdirectory installs and with permalinks off.
	 */
	public function get_redirect_uri() {
		return home_url( '/' ) . '?dyna_google_callback=1';
	}

	public function register_hooks() {
		add_action( 'admin_menu', [ $this, 'add_menu' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
	}

	public function add_menu() {
		add_options_page(
			__( 'Dyna Google Login', 'dyna-google-login' ),
			__( 'Dyna Google Login', 'dyna-google-login' ),
			'manage_options',
			'dyna-google-login',
			[ $this, 'render_page' ]
		);
	}

	public function register_settings() {
		register_setting(
			'dyna_google_login_group',
			self::OPTION_KEY,
			[
				'sanitize_callback' => [ $this, 'sanitize' ],
				'default'           => $this->defaults(),
			]
		);
	}

	public function sanitize( $input ) {
		$out                 = [];
		$out['client_id']     = sanitize_text_field( $input['client_id'] ?? '' );
		$out['client_secret'] = sanitize_text_field( $input['client_secret'] ?? '' );
		$out['default_role']  = sanitize_key( $input['default_role'] ?? 'customer' );
		// Only allow safe roles; default to customer otherwise.
		if ( ! in_array( $out['default_role'], [ 'customer', 'subscriber' ], true ) ) {
			$out['default_role'] = 'customer';
		}
		$out['auto_link']   = ! empty( $input['auto_link'] ) ? 1 : 0;
		$out['button_text'] = sanitize_text_field( $input['button_text'] ?? 'Continue with Google' );
		$out['show_on_checkout'] = ! empty( $input['show_on_checkout'] ) ? 1 : 0;
		if ( '' === $out['button_text'] ) {
			$out['button_text'] = 'Continue with Google';
		}
		return $out;
	}

	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'dyna-google-login' ) );
		}

		$opts          = $this->get_all();
		$redirect_uri  = $this->get_redirect_uri();
		$is_configured = $this->is_configured();
		$myaccount_url = function_exists( 'wc_get_page_permalink' )
			? wc_get_page_permalink( 'myaccount' )
			: home_url( '/my-account/' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Dyna Google Login', 'dyna-google-login' ); ?></h1>
			<p><?php esc_html_e( 'Server-side Google sign-in for the WooCommerce My Account page. No JavaScript SDK, no third-party scripts.', 'dyna-google-login' ); ?></p>

			<form method="post" action="options.php">
				<?php settings_fields( 'dyna_google_login_group' ); ?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="dyna_gl_client_id"><?php esc_html_e( 'Google Client ID', 'dyna-google-login' ); ?></label></th>
						<td>
							<input
								type="text"
								id="dyna_gl_client_id"
								name="<?php echo esc_attr( self::OPTION_KEY ); ?>[client_id]"
								value="<?php echo esc_attr( $opts['client_id'] ); ?>"
								class="regular-text code"
								placeholder="123456789-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com"
								autocomplete="off"
							/>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="dyna_gl_client_secret"><?php esc_html_e( 'Google Client Secret', 'dyna-google-login' ); ?></label></th>
						<td>
							<input
								type="password"
								id="dyna_gl_client_secret"
								name="<?php echo esc_attr( self::OPTION_KEY ); ?>[client_secret]"
								value="<?php echo esc_attr( $opts['client_secret'] ); ?>"
								class="regular-text code"
								placeholder="GOCSPX-xxxxxxxxxxxxxxxxxxxxxxxx"
								autocomplete="new-password"
							/>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Authorized redirect URI', 'dyna-google-login' ); ?></th>
						<td>
							<code style="background:#f0f0f1;padding:8px 12px;display:inline-block;max-width:100%;word-break:break-all;"><?php echo esc_html( $redirect_uri ); ?></code>
							<p class="description">
								<?php esc_html_e( 'Copy this EXACTLY into Google Cloud Console → APIs &amp; Services → Credentials → your OAuth client → Authorized redirect URIs. Even a trailing-slash difference will break the flow.', 'dyna-google-login' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="dyna_gl_button_text"><?php esc_html_e( 'Button text', 'dyna-google-login' ); ?></label></th>
						<td>
							<input
								type="text"
								id="dyna_gl_button_text"
								name="<?php echo esc_attr( self::OPTION_KEY ); ?>[button_text]"
								value="<?php echo esc_attr( $opts['button_text'] ); ?>"
								class="regular-text"
							/>
							<p class="description"><?php esc_html_e( 'Default: "Continue with Google".', 'dyna-google-login' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Placement', 'dyna-google-login' ); ?></th>
						<td>
							<label for="dyna_gl_show_on_checkout">
								<input
									type="checkbox"
									id="dyna_gl_show_on_checkout"
									name="<?php echo esc_attr( self::OPTION_KEY ); ?>[show_on_checkout]"
									value="1"
									<?php checked( $opts['show_on_checkout'], 1 ); ?>
								/>
								<?php esc_html_e( 'Also show the button on the WooCommerce Checkout page (guest checkout).', 'dyna-google-login' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'When enabled, logged-out visitors see the Google button at the top of the checkout form. After login, they are returned to the checkout page and their cart is preserved. Always shown on the My Account login/register form regardless of this setting.', 'dyna-google-login' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Account linking', 'dyna-google-login' ); ?></th>
						<td>
							<label for="dyna_gl_auto_link">
								<input
									type="checkbox"
									id="dyna_gl_auto_link"
									name="<?php echo esc_attr( self::OPTION_KEY ); ?>[auto_link]"
									value="1"
									<?php checked( $opts['auto_link'], 1 ); ?>
								/>
								<?php esc_html_e( 'If a Google account email matches an existing WordPress user, log them in as that user silently.', 'dyna-google-login' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Recommended. Disable only if you want users to claim existing accounts with a password first.', 'dyna-google-login' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="dyna_gl_default_role"><?php esc_html_e( 'Default role for new users', 'dyna-google-login' ); ?></label></th>
						<td>
							<select id="dyna_gl_default_role" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[default_role]">
								<option value="customer" <?php selected( $opts['default_role'], 'customer' ); ?>><?php esc_html_e( 'Customer (WooCommerce)', 'dyna-google-login' ); ?></option>
								<option value="subscriber" <?php selected( $opts['default_role'], 'subscriber' ); ?>><?php esc_html_e( 'Subscriber', 'dyna-google-login' ); ?></option>
							</select>
						</td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>

			<hr/>

			<h2><?php esc_html_e( 'Status', 'dyna-google-login' ); ?></h2>
			<?php if ( $is_configured ) : ?>
				<p style="color:#1a7f37;">
					✓ <?php esc_html_e( 'Plugin is configured. The Google button should appear on the', 'dyna-google-login' ); ?>
					<a href="<?php echo esc_url( $myaccount_url ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'My Account page', 'dyna-google-login' ); ?></a>.
				</p>
			<?php else : ?>
				<p style="color:#b35900;">
					⚠ <?php esc_html_e( 'Plugin is NOT configured yet. Fill in your Client ID and Client Secret above to enable the button.', 'dyna-google-login' ); ?>
				</p>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Setup checklist', 'dyna-google-login' ); ?></h2>
			<ol style="list-style:decimal;padding-left:24px;line-height:1.8;">
				<li><?php esc_html_e( 'In Google Cloud Console → APIs &amp; Services → Credentials, create (or use) an OAuth 2.0 Client of type "Web application".', 'dyna-google-login' ); ?></li>
				<li><?php esc_html_e( 'Add the Authorized redirect URI shown above to that client.', 'dyna-google-login' ); ?></li>
				<li><?php esc_html_e( 'Configure the OAuth consent screen (External user type, support email, app domain, scopes: openid + email + profile).', 'dyna-google-login' ); ?></li>
				<li><?php esc_html_e( 'If your app is in "Testing" mode, add your test Gmail addresses under "Test users" — otherwise Google will block them with a 403.', 'dyna-google-login' ); ?></li>
				<li><?php esc_html_e( 'Paste Client ID and Client Secret above, save, and test in an incognito window.', 'dyna-google-login' ); ?></li>
			</ol>
		</div>
		<?php
	}
}
