<?php
namespace DynaGoogleLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Main plugin orchestrator. Singleton — instantiates the rest of the components
 * and wires their hooks once WordPress has loaded.
 */
class Plugin {

	/** @var Plugin|null */
	private static $instance = null;

	/** @var Settings */
	public $settings;

	/** @var OAuth */
	public $oauth;

	/** @var User_Handler */
	public $user_handler;

	/** @var Button_Renderer */
	public $button_renderer;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->settings         = new Settings();
		$this->oauth            = new OAuth( $this->settings );
		$this->user_handler     = new User_Handler( $this->settings );
		$this->button_renderer  = new Button_Renderer( $this->settings );
	}

	public function init() {
		$this->settings->register_hooks();
		$this->oauth->register_hooks();
		$this->button_renderer->register_hooks();

		load_plugin_textdomain( 'dyna-google-login', false, dirname( plugin_basename( DYNA_GOOGLE_LOGIN_FILE ) ) . '/languages' );

		add_action( 'admin_init', [ $this, 'check_conflicts' ] );
	}

	/**
	 * Soft warning (not a hard block) if another Google login plugin is active.
	 * Functionality will still work; the user can choose to deactivate the other one.
	 */
	public function check_conflicts() {
		$conflicting = [
			'nextend-facebook-connect/nextend-facebook-connect.php' => 'Nextend Social Login',
			'woocommerce-social-login/woocommerce-social-login.php' => 'WooCommerce Social Login',
			'social-login-widget/social-login-widget.php'          => 'Social Login Widget',
		];

		if ( ! function_exists( 'is_plugin_active' ) ) {
			include_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$active_conflicts = [];
		foreach ( $conflicting as $file => $name ) {
			if ( is_plugin_active( $file ) ) {
				$active_conflicts[] = $name;
			}
		}

		if ( ! empty( $active_conflicts ) ) {
			$list = implode( ', ', $active_conflicts );
			add_action( 'admin_notices', function () use ( $list ) {
				echo '<div class="notice notice-warning is-dismissible"><p><strong>Dyna Google Login:</strong> the following conflicting plugin(s) are also active: <em>' . esc_html( $list ) . '</em>. You can keep both running, but consider deactivating one to avoid duplicate buttons on wp-login.php.</p></div>';
			} );
		}
	}

	public static function on_activate() {
		// Set defaults so the admin page renders sensibly on first open.
		if ( false === get_option( DYNA_GOOGLE_LOGIN_OPTION_KEY ) ) {
			add_option( DYNA_GOOGLE_LOGIN_OPTION_KEY, [
				'client_id'     => '',
				'client_secret' => '',
				'default_role'  => 'customer',
				'auto_link'     => 1,
				'button_text'   => 'Continue with Google',
			] );
		}
	}

	public static function on_deactivate() {
		// No-op: keep options so re-activation is seamless.
		// uninstall.php handles full removal.
	}
}
