<?php
/**
 * Plugin Name: Dyna Google Login
 * Plugin URI:  https://www.dyna-nutrition.com
 * Description: Adds a "Continue with Google" button to the WooCommerce My Account page. Server-side OAuth 2.0, no JavaScript SDK, no external dependencies.
 * Version:     1.1.0
 * Author:      dyna-nutrition.com
 * License:     GPL-2.0-or-later
 * Requires PHP: 7.4
 * Requires at least: 5.8
 * WC requires at least: 5.0
 * Text Domain: dyna-google-login
 *
 * @package DynaGoogleLogin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Bail if OpenSSL is missing (JWT signature verification needs it).
if ( ! extension_loaded( 'openssl' ) ) {
	add_action( 'admin_notices', function () {
		echo '<div class="notice notice-error"><p><strong>Dyna Google Login</strong> requires the OpenSSL PHP extension. Please enable it on your server.</p></div>';
	} );
	return;
}

define( 'DYNA_GOOGLE_LOGIN_VERSION', '1.1.0' );
define( 'DYNA_GOOGLE_LOGIN_FILE', __FILE__ );
define( 'DYNA_GOOGLE_LOGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'DYNA_GOOGLE_LOGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'DYNA_GOOGLE_LOGIN_OPTION_KEY', 'dyna_google_login_options' );

require_once DYNA_GOOGLE_LOGIN_DIR . 'includes/class-settings.php';
require_once DYNA_GOOGLE_LOGIN_DIR . 'includes/class-token-verifier.php';
require_once DYNA_GOOGLE_LOGIN_DIR . 'includes/class-oauth.php';
require_once DYNA_GOOGLE_LOGIN_DIR . 'includes/class-user-handler.php';
require_once DYNA_GOOGLE_LOGIN_DIR . 'includes/class-button-renderer.php';
require_once DYNA_GOOGLE_LOGIN_DIR . 'includes/class-plugin.php';

add_action( 'plugins_loaded', function () {
	\DynaGoogleLogin\Plugin::instance()->init();
} );

register_activation_hook( __FILE__, [ '\DynaGoogleLogin\Plugin', 'on_activate' ] );
register_deactivation_hook( __FILE__, [ '\DynaGoogleLogin\Plugin', 'on_deactivate' ] );
