<?php
/**
 * Dyna Google Login — full test suite (v1.0.2).
 *
 * Run:  php tests/run-tests.php
 *
 * Tests are self-contained: they stub the WordPress functions we use, then
 * exercise the security-critical paths and the user/login flow.
 *
 * Coverage:
 *   1-6:  JWT verification (sign roundtrip, tamper, wrong aud, expired, alg=none)
 *   7-13: User creation, auto-link, auto-link-disabled, username collision, button render, second-time login regression
 *   14-20: HTTPS detection in login_user (is_ssl, X-Forwarded-Proto, CF-Visitor)
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/../' );
}

// ---- Minimal WP stubs ----

$GLOBALS['_options']              = [];
$GLOBALS['_transients']           = [];
$GLOBALS['_users_by_id']          = [];
$GLOBALS['_users_by_email']       = [];
$GLOBALS['_next_user_id']         = 1;
$GLOBALS['_is_ssl']               = false;
$GLOBALS['_auth_cookie_calls']    = [];
$GLOBALS['_cleared_cookies']      = 0;

function get_option( $k, $d = false )              { return $GLOBALS['_options'][ $k ] ?? $d; }
function update_option( $k, $v )                   { $GLOBALS['_options'][ $k ] = $v; return true; }
function add_option( $k, $v )                      { if ( ! isset( $GLOBALS['_options'][ $k ] ) ) { $GLOBALS['_options'][ $k ] = $v; return true; } return false; }
function delete_option( $k )                       { unset( $GLOBALS['_options'][ $k ] ); return true; }
function get_transient( $k )                       { $e = $GLOBALS['_transients'][ $k ] ?? null; if ( ! $e ) return false; if ( $e['expires'] < time() ) { unset( $GLOBALS['_transients'][ $k ] ); return false; } return $e['value']; }
function set_transient( $k, $v, $t )               { $GLOBALS['_transients'][ $k ] = [ 'value' => $v, 'expires' => time() + $t ]; return true; }
function delete_transient( $k )                    { unset( $GLOBALS['_transients'][ $k ] ); return true; }
function wp_parse_args( $a, $d )                   { if ( is_object( $a ) ) $a = (array) $a; if ( ! is_array( $a ) ) $a = []; return array_merge( $d, $a ); }
function sanitize_text_field( $s )                 { return is_string( $s ) ? trim( $s ) : ''; }
function sanitize_key( $s )                        { return is_string( $s ) ? preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $s ) ) : ''; }
function sanitize_user( $u, $strict = false )      { return strtolower( preg_replace( '/[^a-z0-9_\-]/', '', $u ) ); }
function esc_url( $u )                             { return $u; }
function esc_url_raw( $u )                         { return $u; }
function esc_html( $s )                            { return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $s )                            { return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' ); }
function esc_html__( $s, $d = '' )                 { return esc_html( $s ); }
function esc_html_e( $s, $d = '' )                 { echo esc_html( $s ); }
function __( $s, $d = '' )                         { return $s; }
function _e( $s, $d = '' )                         { echo $s; }
function home_url( $p = '/' )                      { return 'https://example.com' . ( str_starts_with( $p, '/' ) ? $p : '/' . $p ); }
function add_query_arg( $a, $u = null )            { if ( is_array( $a ) ) { $s = str_contains( $u, '?' ) ? '&' : '?'; return $u . $s . http_build_query( $a ); } return $u; }
function remove_query_arg( $k, $u )                { return preg_replace( '/([?&])' . preg_quote( $k, '/' ) . '=[^&]*&?/', '', $u ); }
function wp_generate_password( $l = 12, $s = true, $e = true ) { $c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; if ( $s ) $c .= '!@#$%^&*()'; if ( $e ) $c .= '-_ []{}<>~`+=,.;:/?|'; $o = ''; for ( $i = 0; $i < $l; $i++ ) $o .= $c[ random_int( 0, strlen( $c ) - 1 ) ]; return $o; }
function wp_unslash( $v )                          { return is_string( $v ) ? stripslashes( $v ) : $v; }
function wp_remote_get( $u, $a = [] )              { return [ 'response' => [ 'code' => 200 ], 'body' => '' ]; }
function wp_remote_post( $u, $a = [] )             { return [ 'response' => [ 'code' => 200 ], 'body' => '{}' ]; }
function wp_remote_retrieve_response_code( $r )    { return $r['response']['code'] ?? 0; }
function wp_remote_retrieve_body( $r )             { return $r['body'] ?? ''; }
function status_header( $c )                       { /* noop */ }
function nocache_headers()                         { /* noop */ }
function is_wp_error( $x )                         { return $x instanceof WP_Error; }
function do_action( $n, ...$a )                    { /* noop */ }
function apply_filters( $n, $v, ...$a )            { return $v; }
function add_action( ...$a )                       { /* noop */ }
function add_filter( ...$a )                       { /* noop */ }
function add_shortcode( ...$a )                    { /* noop */ }
function load_plugin_textdomain( ...$a )           { /* noop */ }
function plugin_dir_path( $f )                     { return dirname( $f ) . '/'; }
function plugin_dir_url( $f )                      { return 'https://example.com/wp-content/plugins/x/'; }
function plugin_basename( $f )                     { return basename( $f ); }
function register_setting( ...$a )                 { /* noop */ }
function add_options_page( ...$a )                 { /* noop */ }
function settings_fields( ...$a )                  { /* noop */ }
function submit_button()                           { /* noop */ }
function checked( $a, $b )                         { echo $a === $b ? ' checked="checked"' : ''; }
function selected( $a, $b )                        { echo $a === $b ? ' selected="selected"' : ''; }
function current_user_can( $c )                    { return true; }
function is_user_logged_in()                       { return false; }
function is_plugin_active( $f )                    { return false; }
function wp_set_current_user( $i, $n = '' )        { /* noop */ }
function wp_register_style( ...$a )                { /* noop */ }
function wp_enqueue_style( ...$a )                 { /* noop */ }
function wp_safe_redirect( $u, $s = 302 )          { throw new class( $u, $s ) extends RuntimeException { public $url; public $status; public function __construct( $u, $s ) { $this->url = $u; $this->status = $s; parent::__construct( "redirect: $u" ); } }; }
function is_ssl()                                  { return $GLOBALS['_is_ssl']; }
function wp_set_auth_cookie( $user_id, $remember = false, $secure = '', $token = '' ) {
	$GLOBALS['_auth_cookie_calls'][] = [ 'user_id' => $user_id, 'remember' => $remember, 'secure' => $secure, 'token' => $token ];
}
function wp_clear_auth_cookie() { $GLOBALS['_cleared_cookies']++; }

class WP_Error {
	private $code; private $message;
	public function __construct( $c = '', $m = '' ) { $this->code = $c; $this->message = $m; }
	public function get_error_code()    { return $this->code; }
	public function get_error_message() { return $this->message; }
}

class WP_User {
	public $ID; public $user_login; public $user_email; public $user_pass; public $display_name; public $meta = [];
	public function __construct( $data ) { foreach ( (array) $data as $k => $v ) $this->$k = $v; }
}

function get_user_by( $field, $value ) {
	if ( $field === 'email' ) return isset( $GLOBALS['_users_by_email'][ strtolower( $value ) ] ) ? new WP_User( $GLOBALS['_users_by_email'][ strtolower( $value ) ] ) : null;
	if ( $field === 'id' || $field === 'ID' ) return isset( $GLOBALS['_users_by_id'][ (int) $value ] ) ? new WP_User( $GLOBALS['_users_by_id'][ (int) $value ] ) : null;
	if ( $field === 'login' ) { foreach ( $GLOBALS['_users_by_id'] as $u ) if ( $u['user_login'] === $value ) return new WP_User( $u ); }
	return null;
}

function get_users( $args ) {
	$results = [];
	$meta_key = $args['meta_key']   ?? null;
	$meta_val = $args['meta_value'] ?? null;
	$fields   = $args['fields']     ?? 'all';
	$matches = [];
	foreach ( $GLOBALS['_users_by_id'] as $u ) {
		if ( $meta_key && ( $u['meta'][ $meta_key ] ?? null ) === $meta_val ) $matches[] = $u;
	}
	if ( is_array( $fields ) ) {
		foreach ( $matches as $u ) { $obj = new stdClass(); foreach ( $fields as $f ) $obj->$f = $u[ $f ] ?? null; $results[] = $obj; }
	} elseif ( 'all' === $fields || 'all_with_meta' === $fields ) {
		foreach ( $matches as $u ) $results[] = new WP_User( $u );
	} else {
		foreach ( $matches as $u ) $results[] = $u[ $fields ] ?? null;
	}
	if ( isset( $args['number'] ) && count( $results ) > $args['number'] ) $results = array_slice( $results, 0, $args['number'] );
	return $results;
}

function username_exists( $u ) { foreach ( $GLOBALS['_users_by_id'] as $x ) if ( $x['user_login'] === $u ) return true; return false; }
function wp_insert_user( $data ) {
	$id = $GLOBALS['_next_user_id']++;
	$user = [ 'ID' => $id, 'user_login' => $data['user_login'], 'user_email' => $data['user_email'], 'user_pass' => $data['user_pass'] ?? '', 'display_name' => $data['display_name'] ?? $data['user_email'], 'meta' => [] ];
	$GLOBALS['_users_by_id'][ $id ] = $user;
	$GLOBALS['_users_by_email'][ strtolower( $data['user_email'] ) ] = $user;
	return $id;
}
function update_user_meta( $id, $k, $v ) { if ( ! isset( $GLOBALS['_users_by_id'][ $id ] ) ) return false; $GLOBALS['_users_by_id'][ $id ]['meta'][ $k ] = $v; return true; }

const HOUR_IN_SECONDS = 3600;
$wp = new class { public $request = 'my-account/'; };

require __DIR__ . '/../includes/class-settings.php';
require __DIR__ . '/../includes/class-token-verifier.php';
require __DIR__ . '/../includes/class-oauth.php';
require __DIR__ . '/../includes/class-user-handler.php';
require __DIR__ . '/../includes/class-button-renderer.php';
require __DIR__ . '/../includes/class-plugin.php';

function reset_state() {
	$GLOBALS['_options']           = [];
	$GLOBALS['_transients']        = [];
	$GLOBALS['_users_by_id']       = [];
	$GLOBALS['_users_by_email']    = [];
	$GLOBALS['_next_user_id']      = 1;
	$GLOBALS['_is_ssl']            = false;
	$GLOBALS['_auth_cookie_calls'] = [];
	$GLOBALS['_cleared_cookies']   = 0;
	unset( $_SERVER['HTTP_X_FORWARDED_PROTO'] );
	unset( $_SERVER['HTTP_CF_VISITOR'] );
	update_option( 'dyna_google_login_options', [
		'client_id'     => 'test-client-id-12345.apps.googleusercontent.com',
		'client_secret' => 'GOCSPX-test-secret',
		'default_role'  => 'customer',
		'auto_link'     => 1,
		'button_text'   => 'Continue with Google',
	] );
	$ref = new ReflectionClass( \DynaGoogleLogin\Plugin::class );
	$prop = $ref->getProperty( 'instance' );
	$prop->setAccessible( true );
	$prop->setValue( null, null );
}
function get_plugin() { return \DynaGoogleLogin\Plugin::instance(); }

$pass = 0; $fail = 0;
function ok( $msg ) { global $pass, $fail; $pass++; echo "  PASS $msg\n"; }
function bad( $msg ) { global $pass, $fail; $fail++; echo "  FAIL $msg\n"; }

echo "=== JWT verifier (tests 1-6) ===\n";

// Test 1: JWK -> PEM
reset_state();
$res = openssl_pkey_new([ 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ]);
openssl_pkey_export( $res, $priv );
$det = openssl_pkey_get_details( $res );
$n = rtrim( strtr( base64_encode( $det['rsa']['n'] ), '+/', '-_' ), '=' );
$e = rtrim( strtr( base64_encode( $det['rsa']['e'] ), '+/', '-_' ), '=' );
$verifier = new \DynaGoogleLogin\Token_Verifier();
$ref = new ReflectionClass( $verifier );
$m = $ref->getMethod( 'jwk_to_pem' );
$m->setAccessible( true );
$pem = $m->invoke( $verifier, [ 'kty' => 'RSA', 'alg' => 'RS256', 'kid' => 'k1', 'n' => $n, 'e' => $e ] );
$loaded = openssl_pkey_get_public( $pem );
echo "Test 1: JWK->PEM conversion\n";
if ( $loaded && openssl_pkey_get_details( $loaded )['rsa']['n'] === $det['rsa']['n'] ) ok( 'reconstructed modulus matches' );
else bad( 'PEM reconstruction failed' );

// Tests 2-6
$header = [ 'alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'k1' ];
$payload = [ 'iss' => 'https://accounts.google.com', 'aud' => 'test-client-id-12345.apps.googleusercontent.com', 'sub' => '1234', 'email' => 'a@b.com', 'email_verified' => true, 'iat' => time(), 'exp' => time() + 3600 ];
$hb = rtrim( strtr( base64_encode( json_encode( $header ) ), '+/', '-_' ), '=' );
$pb = rtrim( strtr( base64_encode( json_encode( $payload ) ), '+/', '-_' ), '=' );
openssl_sign( "$hb.$pb", $sig, $priv, OPENSSL_ALGO_SHA256 );
$sb = rtrim( strtr( base64_encode( $sig ), '+/', '-_' ), '=' );
$GLOBALS['_transients']['dyna_gl_jwks_cache'] = [ 'value' => [ [ 'kty' => 'RSA', 'alg' => 'RS256', 'kid' => 'k1', 'n' => $n, 'e' => $e ] ], 'expires' => time() + 3600 ];
$jwt = "$hb.$pb.$sb";

echo "Test 2: JWT roundtrip\n";
$res = $verifier->verify( $jwt, 'test-client-id-12345.apps.googleusercontent.com' );
if ( ! is_wp_error( $res ) && $res['sub'] === '1234' ) ok( 'valid JWT verified' ); else bad( 'verify failed' );

echo "Test 3: tampered signature\n";
$bad = "$hb.$pb." . rtrim( strtr( base64_encode( 'fake' ), '+/', '-_' ), '=' );
$res = $verifier->verify( $bad, 'test-client-id-12345.apps.googleusercontent.com' );
if ( is_wp_error( $res ) && $res->get_error_code() === 'invalid_signature' ) ok( 'rejected' ); else bad( 'should have rejected' );

echo "Test 4: wrong audience\n";
$bp = $payload; $bp['aud'] = 'other-id';
$bp_b = rtrim( strtr( base64_encode( json_encode( $bp ) ), '+/', '-_' ), '=' );
openssl_sign( "$hb.$bp_b", $sig2, $priv, OPENSSL_ALGO_SHA256 );
$res = $verifier->verify( "$hb.$bp_b." . rtrim( strtr( base64_encode( $sig2 ), '+/', '-_' ), '=' ), 'test-client-id-12345.apps.googleusercontent.com' );
if ( is_wp_error( $res ) && $res->get_error_code() === 'invalid_aud' ) ok( 'rejected' ); else bad( 'should have rejected' );

echo "Test 5: expired token\n";
$bp = $payload; $bp['exp'] = time() - 7200; $bp['iat'] = time() - 10800;
$bp_b = rtrim( strtr( base64_encode( json_encode( $bp ) ), '+/', '-_' ), '=' );
openssl_sign( "$hb.$bp_b", $sig3, $priv, OPENSSL_ALGO_SHA256 );
$res = $verifier->verify( "$hb.$bp_b." . rtrim( strtr( base64_encode( $sig3 ), '+/', '-_' ), '=' ), 'test-client-id-12345.apps.googleusercontent.com' );
if ( is_wp_error( $res ) && $res->get_error_code() === 'token_expired' ) ok( 'rejected' ); else bad( 'should have rejected' );

echo "Test 6: alg=none\n";
$nh = rtrim( strtr( base64_encode( json_encode( [ 'alg' => 'none', 'typ' => 'JWT', 'kid' => 'k1' ] ) ), '+/', '-_' ), '=' );
$res = $verifier->verify( "$nh.$pb.", 'test-client-id-12345.apps.googleusercontent.com' );
if ( is_wp_error( $res ) && $res->get_error_code() === 'invalid_alg' ) ok( 'rejected' ); else bad( 'should have rejected' );

echo "\n=== User handler + auth (tests 7-13) ===\n";

echo "Test 7: OAuth URL generation\n";
reset_state();
$p = get_plugin();
$url = $p->oauth->get_authorize_url( 'https://example.com/my-account/' );
if ( str_contains( $url, 'accounts.google.com/o/oauth2/v2/auth' ) && str_contains( $url, 'state=' ) && str_contains( $url, 'scope=openid' ) ) ok( 'URL has all required params' );
else bad( "URL missing params" );

echo "Test 8: New user creation\n";
reset_state();
$claims = [ 'sub' => 's1', 'email' => 'new@gmail.com', 'email_verified' => true, 'name' => 'New' ];
$res = $p->user_handler->handle( $claims, 'https://example.com/my-account/' );
$u = get_user_by( 'email', 'new@gmail.com' );
if ( ! is_wp_error( $res ) && $u && $GLOBALS['_users_by_id'][ $u->ID ]['meta']['dyna_google_sub'] === 's1' ) ok( 'user created, sub stored' );
else bad( 'user not created correctly' );

echo "Test 9: Auto-link by email\n";
reset_state();
wp_insert_user([ 'user_login' => 'exist', 'user_email' => 'exist@gmail.com', 'user_pass' => 'x', 'role' => 'customer' ]);
$claims = [ 'sub' => 'different-sub', 'email' => 'exist@gmail.com', 'email_verified' => true ];
$res = $p->user_handler->handle( $claims, '' );
$u = get_user_by( 'email', 'exist@gmail.com' );
if ( ! is_wp_error( $res ) && $GLOBALS['_users_by_id'][ $u->ID ]['meta']['dyna_google_sub'] === 'different-sub' ) ok( 'auto-linked, sub updated' );
else bad( 'auto-link failed' );

echo "Test 10: Auto-link disabled\n";
reset_state();
update_option( 'dyna_google_login_options', [ 'client_id' => 'test-client-id-12345.apps.googleusercontent.com', 'client_secret' => 'GOCSPX-x', 'default_role' => 'customer', 'auto_link' => 0, 'button_text' => 'X' ] );
wp_insert_user([ 'user_login' => 'exist2', 'user_email' => 'exist@gmail.com', 'user_pass' => 'x', 'role' => 'customer' ]);
$res = $p->user_handler->handle( [ 'sub' => 's2', 'email' => 'exist@gmail.com', 'email_verified' => true ], '' );
if ( is_wp_error( $res ) && $res->get_error_code() === 'auto_link_disabled' ) ok( 'blocked correctly' );
else bad( 'should have blocked' );

echo "Test 11: Username collision\n";
reset_state();
update_option( 'dyna_google_login_options', [ 'client_id' => 'test-client-id-12345.apps.googleusercontent.com', 'client_secret' => 'GOCSPX-x', 'default_role' => 'customer', 'auto_link' => 1, 'button_text' => 'Continue with Google' ] );
wp_insert_user([ 'user_login' => 'collision', 'user_email' => 'first@x.com', 'user_pass' => 'x', 'role' => 'customer' ]);
$res = $p->user_handler->handle( [ 'sub' => 's3', 'email' => 'collision@gmail.com', 'email_verified' => true, 'name' => 'C' ], '' );
$u = get_user_by( 'email', 'collision@gmail.com' );
if ( ! is_wp_error( $res ) && $u->user_login === 'collision1' ) ok( 'suffixed to collision1' ); else bad( 'expected collision1' );

echo "Test 12: Button rendering\n";
reset_state();
$html = $p->button_renderer->shortcode();
if ( str_contains( $html, 'Continue with Google' ) && str_contains( $html, 'accounts.google.com' ) && str_contains( $html, '<svg' ) ) ok( 'has text, URL, icon' );
else bad( 'rendering incomplete' );

echo "Test 13: Second-time login via sub (v1.0.1 regression)\n";
reset_state();
update_option( 'dyna_google_login_options', [ 'client_id' => 'test-client-id-12345.apps.googleusercontent.com', 'client_secret' => 'GOCSPX-x', 'default_role' => 'customer', 'auto_link' => 1, 'button_text' => 'Continue with Google' ] );
$uid = wp_insert_user([ 'user_login' => 'returning', 'user_email' => 'returning@gmail.com', 'user_pass' => 'x', 'role' => 'customer' ]);
update_user_meta( $uid, 'dyna_google_sub', 'stable-sub-999' );
try {
	$res = $p->user_handler->handle( [ 'sub' => 'stable-sub-999', 'email' => 'returning@gmail.com', 'email_verified' => true, 'name' => 'Returning' ], 'https://example.com/my-account/' );
	if ( is_wp_error( $res ) ) bad( 'WP_Error' ); else ok( 'second-time login works' );
} catch ( TypeError $e ) { bad( 'TypeError: ' . $e->getMessage() ); }

echo "\n=== HTTPS detection in login_user (tests 14-20, v1.0.2) ===\n";

function last_auth_call() { return end( $GLOBALS['_auth_cookie_calls'] ) ?: null; }

echo "Test 14: wp_clear_auth_cookie is called\n";
reset_state();
get_plugin()->user_handler->handle( [ 'sub' => 's1', 'email' => 'a@b.com', 'email_verified' => true ], '' );
if ( $GLOBALS['_cleared_cookies'] >= 1 ) ok( 'cleared ' . $GLOBALS['_cleared_cookies'] . ' time(s)' ); else bad( 'NOT called' );

echo "Test 15: is_ssl()=true → secure=true\n";
reset_state();
$GLOBALS['_is_ssl'] = true;
get_plugin()->user_handler->handle( [ 'sub' => 's1', 'email' => 'a@b.com', 'email_verified' => true ], '' );
$call = last_auth_call();
if ( $call && $call['secure'] === true ) ok( 'secure=true' ); else bad( 'expected true' );

echo "Test 16: is_ssl()=false, no proxy headers → secure=false\n";
reset_state();
$GLOBALS['_is_ssl'] = false;
get_plugin()->user_handler->handle( [ 'sub' => 's1', 'email' => 'a@b.com', 'email_verified' => true ], '' );
$call = last_auth_call();
if ( $call && $call['secure'] === false ) ok( 'secure=false' ); else bad( 'expected false' );

echo "Test 17: X-Forwarded-Proto: https → secure=true (Cloudflare case)\n";
reset_state();
$GLOBALS['_is_ssl'] = false;
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
get_plugin()->user_handler->handle( [ 'sub' => 's1', 'email' => 'a@b.com', 'email_verified' => true ], '' );
$call = last_auth_call();
if ( $call && $call['secure'] === true ) ok( 'X-Forwarded-Proto detected' ); else bad( 'expected true' );

echo "Test 18: CF-Visitor JSON https → secure=true\n";
reset_state();
$GLOBALS['_is_ssl'] = false;
$_SERVER['HTTP_CF_VISITOR'] = '{"scheme":"https"}';
get_plugin()->user_handler->handle( [ 'sub' => 's1', 'email' => 'a@b.com', 'email_verified' => true ], '' );
$call = last_auth_call();
if ( $call && $call['secure'] === true ) ok( 'CF-Visitor detected' ); else bad( 'expected true' );

echo "Test 19: remember=true (long-lived cookie)\n";
reset_state();
get_plugin()->user_handler->handle( [ 'sub' => 's1', 'email' => 'a@b.com', 'email_verified' => true ], '' );
$call = last_auth_call();
if ( $call && $call['remember'] === true ) ok( 'remember=true' ); else bad( 'expected true' );

echo "Test 20: X-Forwarded-Proto: http → secure=false\n";
reset_state();
$GLOBALS['_is_ssl'] = false;
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'http';
get_plugin()->user_handler->handle( [ 'sub' => 's1', 'email' => 'a@b.com', 'email_verified' => true ], '' );
$call = last_auth_call();
if ( $call && $call['secure'] === false ) ok( 'http correctly detected' ); else bad( 'expected false' );

echo "\n=== TOTAL: $pass passed, $fail failed ===\n";
exit( $fail > 0 ? 1 : 0 );
