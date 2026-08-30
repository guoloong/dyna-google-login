<?php
namespace DynaGoogleLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the "Continue with Google" button in two places:
 *
 *   1. Auto-injection on the default WooCommerce login/register form
 *      (hooks: woocommerce_login_form_start, woocommerce_register_form_start).
 *      Works when the theme uses the standard WC form.
 *
 *   2. Auto-injection on the WooCommerce Checkout page
 *      (hook: woocommerce_checkout_before_customer_details).
 *      Shown for guest checkout; disabled via admin setting if needed.
 *      After login, the user is returned to the same checkout page so the
 *      cart is preserved.
 *
 *   3. Shortcode [dyna_google_login] for Divi / custom themes that override
 *      the WC form and break auto-injection. Drop a Text or Code module
 *      into the Divi My Account page and paste the shortcode.
 *
 * Also renders a generic error notice when the OAuth flow redirects back
 * with ?dyna_google_error=1.
 */
class Button_Renderer {

	/** @var Settings */
	private $settings;

	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	public function register_hooks() {
		add_action( 'wp_enqueue_scripts', [ $this, 'register_assets' ] );
		add_shortcode( 'dyna_google_login', [ $this, 'shortcode' ] );

		// Default WC form hooks — fires when the theme doesn't replace the form.
		add_action( 'woocommerce_login_form_start', [ $this, 'render' ] );
		add_action( 'woocommerce_register_form_start', [ $this, 'render' ] );

		// Checkout — guest checkout flow. Toggled by the admin setting.
		add_action( 'woocommerce_checkout_before_customer_details', [ $this, 'render_on_checkout' ] );

		// Error notice after a failed Google callback.
		add_action( 'woocommerce_login_form_start', [ $this, 'maybe_render_error' ], 5 );
		add_action( 'woocommerce_register_form_start', [ $this, 'maybe_render_error' ], 5 );
	}

	public function register_assets() {
		wp_register_style(
			'dyna-google-login',
			DYNA_GOOGLE_LOGIN_URL . 'assets/css/button.css',
			[],
			DYNA_GOOGLE_LOGIN_VERSION
		);
	}

	public function shortcode( $atts = [] ) {
		return $this->get_html();
	}

	public function render() {
		echo $this->get_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped — html is escaped inside.
	}

	/**
	 * Render the Google button at the top of the WooCommerce checkout form,
	 * unless the admin has disabled it.
	 *
	 * Filter `dyna_google_login_show_on_checkout` lets themes/plugins force-hide
	 * it (e.g. on a custom checkout page) without touching the admin setting.
	 */
	public function render_on_checkout() {
		if ( ! $this->settings->is_show_on_checkout() ) {
			return;
		}
		/**
		 * Filter whether the Google button is rendered on the WooCommerce checkout page.
		 *
		 * @param bool $show Whether to show the button. Default: the admin setting value.
		 */
		if ( ! apply_filters( 'dyna_google_login_show_on_checkout', true ) ) {
			return;
		}
		echo $this->get_html( 'checkout' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	public function maybe_render_error() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- informational query var, not a state change.
		if ( empty( $_GET[ OAuth::ERROR_QUERY ] ) ) {
			return;
		}
		echo '<div class="dyna-google-login-error" role="alert">'
			. esc_html__( 'Sign-in with Google failed. Please try again, or use your email and password below.', 'dyna-google-login' )
			. '</div>';
	}

	/**
	 * Build the button HTML. Returns '' if not configured, user is logged in, etc.
	 *
	 * @param string $context Where the button is being rendered.
	 *                        '' (default) → My Account login/register form.
	 *                        'checkout'  → WooCommerce checkout page. Adds a wrapper
	 *                                      modifier class and a small "or continue
	 *                                      as guest" divider below the button.
	 */
	private function get_html( $context = '' ) {
		if ( ! $this->settings->is_configured() ) {
			return '';
		}
		if ( is_user_logged_in() ) {
			return '';
		}

		wp_enqueue_style( 'dyna-google-login' );

		$url  = Plugin::instance()->oauth->get_authorize_url( $this->get_current_url() );
		if ( '' === $url ) {
			return '';
		}
		$text = $this->settings->get( 'button_text', 'Continue with Google' );

		$wrapper_class = 'dyna-google-login-wrapper';
		if ( 'checkout' === $context ) {
			$wrapper_class .= ' dyna-google-login-wrapper--checkout';
		}

		ob_start();
		?>
		<div class="<?php echo esc_attr( $wrapper_class ); ?>">
			<a class="dyna-google-login-button" href="<?php echo esc_url( $url ); ?>" rel="nofollow">
				<span class="dyna-google-login-icon" aria-hidden="true">
					<svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg" focusable="false">
						<path d="M17.64 9.205c0-.639-.057-1.252-.164-1.841H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615z" fill="#4285F4"/>
						<path d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z" fill="#34A853"/>
						<path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z" fill="#FBBC05"/>
						<path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/>
					</svg>
				</span>
				<span class="dyna-google-login-text"><?php echo esc_html( $text ); ?></span>
			</a>
			<?php if ( 'checkout' === $context ) : ?>
				<div class="dyna-google-login-divider" aria-hidden="true">
					<span><?php esc_html_e( 'or continue as guest', 'dyna-google-login' ); ?></span>
				</div>
			<?php endif; ?>
		</div>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Get the current URL for return-to after login.
	 */
	private function get_current_url() {
		global $wp;
		$url = home_url( add_query_arg( [], $wp->request ) );
		// Strip the error flag if present.
		$url = remove_query_arg( OAuth::ERROR_QUERY, $url );
		return $url;
	}
}
