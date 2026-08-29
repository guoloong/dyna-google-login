<?php
/**
 * Uninstall — drop plugin options and transients.
 *
 * Runs only when the user deletes the plugin from WP Admin (not on deactivation).
 * We keep the plugin's user_meta (`dyna_google_sub`, etc.) on user accounts, since
 * those users may have been created via Google login and the meta is harmless
 * if the plugin is re-installed.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'dyna_google_login_options' );

// Clean up our transients. Direct DB query is the standard pattern for uninstall.
global $wpdb;
// phpcs:disable WordPress.DB.DirectDatabaseQuery
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '_transient_dyna_gl_state\\_%'
	    OR option_name LIKE '_transient_timeout_dyna_gl_state\\_%'
	    OR option_name LIKE '_transient_dyna_gl_jwks_cache'
	    OR option_name LIKE '_transient_timeout_dyna_gl_jwks_cache'"
);
// phpcs:enable WordPress.DB.DirectDatabaseQuery
