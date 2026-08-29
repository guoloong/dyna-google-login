<?php
namespace DynaGoogleLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Verifies Google-issued id_token JWTs against Google's published JWKS.
 *
 * Security model:
 *   - Reject any alg other than RS256 (no alg=none, no HS256 confusion).
 *   - Verify the signature using the JWK whose `kid` matches the JWT header.
 *   - Verify `aud` matches our stored Client ID exactly.
 *   - Verify `iss` is one of Google's known issuers.
 *   - Verify `exp` is in the future and `iat` is not in the future (with 5 min clock skew).
 *   - Verify `email_verified` is true.
 *
 * JWKS is cached in a transient for 1 hour to avoid hammering Google on every login.
 * On a kid miss, the cache is flushed and a fresh JWKS is fetched once (key rotation).
 */
class Token_Verifier {

	const JWKS_URL              = 'https://www.googleapis.com/oauth2/v3/certs';
	const JWKS_CACHE_KEY        = 'dyna_gl_jwks_cache';
	const JWKS_CACHE_TTL        = HOUR_IN_SECONDS;
	const GOOGLE_ISSUERS        = [
		'https://accounts.google.com',
		'accounts.google.com',
	];
	const CLOCK_SKEW_SECONDS    = 300;

	/**
	 * @param string $id_token         Raw JWT from Google's token endpoint.
	 * @param string $expected_audience Our Client ID — must match the `aud` claim.
	 * @return array|\WP_Error         Decoded claims on success, WP_Error on any failure.
	 */
	public function verify( $id_token, $expected_audience ) {
		if ( empty( $id_token ) || empty( $expected_audience ) ) {
			return new \WP_Error( 'invalid_input', 'Empty id_token or audience.' );
		}

		$parts = explode( '.', $id_token );
		if ( count( $parts ) !== 3 ) {
			return new \WP_Error( 'invalid_jwt', 'Malformed JWT: expected 3 segments.' );
		}
		list( $header_b64, $payload_b64, $signature_b64 ) = $parts;

		$header = json_decode( $this->base64url_decode( $header_b64 ), true );
		if ( ! is_array( $header ) || empty( $header['kid'] ) || empty( $header['alg'] ) ) {
			return new \WP_Error( 'invalid_jwt_header', 'JWT header missing kid or alg.' );
		}

		// Reject anything other than RS256. Critical: prevents alg=none and HS256 confusion attacks.
		if ( 'RS256' !== $header['alg'] ) {
			return new \WP_Error( 'invalid_alg', 'Unsupported JWT alg: ' . $header['alg'] );
		}

		$claims = json_decode( $this->base64url_decode( $payload_b64 ), true );
		if ( ! is_array( $claims ) ) {
			return new \WP_Error( 'invalid_jwt_payload', 'Could not decode JWT payload.' );
		}

		// Resolve the signing key (with one auto-retry on kid miss in case of rotation).
		$pem = $this->get_key_for_kid( $header['kid'] );
		if ( is_wp_error( $pem ) && 'kid_not_found' === $pem->get_error_code() ) {
			$this->flush_jwks_cache();
			$pem = $this->get_key_for_kid( $header['kid'] );
		}
		if ( is_wp_error( $pem ) ) {
			return $pem;
		}

		// Verify signature.
		$signing_input = $header_b64 . '.' . $payload_b64;
		$signature     = $this->base64url_decode( $signature_b64 );
		if ( false === $signature || '' === $signature ) {
			return new \WP_Error( 'invalid_signature_encoding', 'Could not decode JWT signature.' );
		}

		$verified = openssl_verify( $signing_input, $signature, $pem, OPENSSL_ALGO_SHA256 );
		if ( 1 !== $verified ) {
			return new \WP_Error( 'invalid_signature', 'JWT signature verification failed (openssl code: ' . var_export( $verified, true ) . ').' );
		}

		// Verify claims. Do this AFTER signature — never trust unverified claims.
		$now = time();

		if ( empty( $claims['exp'] ) || ! is_numeric( $claims['exp'] ) ) {
			return new \WP_Error( 'missing_exp', 'JWT missing exp claim.' );
		}
		if ( (int) $claims['exp'] + self::CLOCK_SKEW_SECONDS < $now ) {
			return new \WP_Error( 'token_expired', 'JWT has expired.' );
		}

		if ( empty( $claims['iat'] ) || ! is_numeric( $claims['iat'] ) ) {
			return new \WP_Error( 'missing_iat', 'JWT missing iat claim.' );
		}
		if ( (int) $claims['iat'] > $now + self::CLOCK_SKEW_SECONDS ) {
			return new \WP_Error( 'iat_in_future', 'JWT iat is too far in the future.' );
		}

		if ( empty( $claims['aud'] ) || $claims['aud'] !== $expected_audience ) {
			return new \WP_Error( 'invalid_aud', 'JWT audience does not match Client ID.' );
		}

		if ( empty( $claims['iss'] ) || ! in_array( $claims['iss'], self::GOOGLE_ISSUERS, true ) ) {
			return new \WP_Error( 'invalid_iss', 'JWT issuer is not Google: ' . ( $claims['iss'] ?? '(empty)' ) );
		}

		if ( empty( $claims['sub'] ) || ! is_string( $claims['sub'] ) ) {
			return new \WP_Error( 'missing_sub', 'JWT missing sub claim.' );
		}

		if ( empty( $claims['email'] ) || ! is_string( $claims['email'] ) ) {
			return new \WP_Error( 'missing_email', 'JWT missing email claim.' );
		}

		if ( empty( $claims['email_verified'] ) || true !== $claims['email_verified'] ) {
			return new \WP_Error( 'email_unverified', 'Google email is not verified.' );
		}

		return $claims;
	}

	/**
	 * Fetch the PEM public key for a given `kid`. Returns string or WP_Error.
	 */
	private function get_key_for_kid( $kid ) {
		$jwks = $this->get_jwks();
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}
		foreach ( $jwks as $key ) {
			if ( isset( $key['kid'] ) && $key['kid'] === $kid ) {
				return $this->jwk_to_pem( $key );
			}
		}
		return new \WP_Error( 'kid_not_found', 'No JWKS key matches kid: ' . $kid );
	}

	/**
	 * Get the JWKS key set, with transient cache.
	 *
	 * @return array|\WP_Error  Array of JWK dicts on success.
	 */
	private function get_jwks() {
		$cached = get_transient( self::JWKS_CACHE_KEY );
		if ( is_array( $cached ) && ! empty( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get( self::JWKS_URL, [
			'timeout' => 10,
			'headers' => [ 'Accept' => 'application/json' ],
		] );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code || ! is_array( $body ) || empty( $body['keys'] ) || ! is_array( $body['keys'] ) ) {
			return new \WP_Error( 'jwks_fetch_failed', 'Could not fetch Google JWKS (HTTP ' . $code . ').' );
		}

		set_transient( self::JWKS_CACHE_KEY, $body['keys'], self::JWKS_CACHE_TTL );
		return $body['keys'];
	}

	private function flush_jwks_cache() {
		delete_transient( self::JWKS_CACHE_KEY );
	}

	/**
	 * Convert a JWK (RSA) to a PEM-encoded SubjectPublicKeyInfo.
	 *
	 * Pure-PHP implementation — no Composer deps, no phpseclib.
	 * Builds the DER encoding by hand for the public key wrapper.
	 *
	 * @param array $jwk A single JWK dict from Google's JWKS.
	 * @return string|\WP_Error PEM string on success.
	 */
	private function jwk_to_pem( $jwk ) {
		if ( empty( $jwk['kty'] ) || 'RSA' !== $jwk['kty'] || empty( $jwk['n'] ) || empty( $jwk['e'] ) ) {
			return new \WP_Error( 'invalid_jwk', 'JWK is missing RSA components.' );
		}

		$modulus  = $this->base64url_decode( $jwk['n'] );
		$exponent = $this->base64url_decode( $jwk['e'] );
		if ( false === $modulus || false === $exponent || '' === $modulus || '' === $exponent ) {
			return new \WP_Error( 'invalid_jwk_encoding', 'Could not base64url-decode JWK n/e.' );
		}

		// Add leading 0x00 if high bit is set, so the INTEGER is interpreted as positive.
		$modulus  = ( ord( $modulus[0] ) & 0x80 ) ? ( "\x00" . $modulus ) : $modulus;
		$exponent = ( ord( $exponent[0] ) & 0x80 ) ? ( "\x00" . $exponent ) : $exponent;

		$mod_int = $this->der_integer( $modulus );
		$exp_int = $this->der_integer( $exponent );

		// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
		$rsa_pub_key = $this->der_sequence( $mod_int . $exp_int );

		// AlgorithmIdentifier for RSA-OAEP/RSA: OID 1.2.840.113549.1.1.1 + NULL
		$alg_id_oid = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
		$alg_id_seq = $this->der_sequence( $alg_id_oid );

		// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
		// BIT STRING content starts with the "unused bits" count (0x00), then the key.
		$bit_string = $this->der_bit_string( "\x00" . $rsa_pub_key );
		$spki       = $this->der_sequence( $alg_id_seq . $bit_string );

		$pem  = "-----BEGIN PUBLIC KEY-----\n";
		$pem .= chunk_split( base64_encode( $spki ), 64, "\n" );
		$pem .= "-----END PUBLIC KEY-----\n";

		return $pem;
	}

	private function der_length( $len ) {
		if ( $len < 0x80 ) {
			return chr( $len );
		}
		$bytes = '';
		while ( $len > 0 ) {
			$bytes = chr( $len & 0xff ) . $bytes;
			$len >>= 8;
		}
		return chr( 0x80 | strlen( $bytes ) ) . $bytes;
	}

	private function der_integer( $content ) {
		return "\x02" . $this->der_length( strlen( $content ) ) . $content;
	}

	private function der_sequence( $content ) {
		return "\x30" . $this->der_length( strlen( $content ) ) . $content;
	}

	private function der_bit_string( $content ) {
		return "\x03" . $this->der_length( strlen( $content ) ) . $content;
	}

	private function base64url_decode( $data ) {
		$remainder = strlen( $data ) % 4;
		if ( $remainder ) {
			$data .= str_repeat( '=', 4 - $remainder );
		}
		$decoded = base64_decode( strtr( $data, '-_', '+/' ), true );
		return false === $decoded ? '' : $decoded;
	}
}
