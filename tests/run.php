<?php
/**
 * Minimal deterministic security tests without a WordPress test installation.
 */

define( 'ABSPATH', __DIR__ . '/' );
define( 'MINUTE_IN_SECONDS', 60 );

class WP_Error {
	private $code;

	public function __construct( $code ) {
		$this->code = $code;
	}

	public function get_error_code() {
		return $this->code;
	}
}

function __( $message ) {
	return $message;
}

function absint( $value ) {
	return abs( (int) $value );
}

function sanitize_key( $value ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $value ) );
}

function apply_filters( $hook, $value ) {
	return $value;
}

function is_wp_error( $value ) {
	return $value instanceof WP_Error;
}

function wp_salt( $scheme = 'auth' ) {
	return 'identity-security-kit-test-salt-' . $scheme;
}

function identity_security_kit_test_assert( $condition, $message ) {
	if ( ! $condition ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
}

require_once dirname( __DIR__ ) . '/inc/totp-algorithm.php';
require_once dirname( __DIR__ ) . '/inc/secret-storage.php';
require_once dirname( __DIR__ ) . '/inc/phone.php';

$binary_secret = '12345678901234567890';
$base32_secret = identity_security_kit_base32_encode( $binary_secret );
identity_security_kit_test_assert( $binary_secret === identity_security_kit_base32_decode( $base32_secret ), 'Base32 round trip' );
identity_security_kit_test_assert( false === identity_security_kit_base32_decode( 'INVALID0' ), 'Base32 rejects invalid alphabet' );

$vectors = array(
	59          => '94287082',
	1111111109  => '07081804',
	1111111111  => '14050471',
	1234567890  => '89005924',
	2000000000  => '69279037',
	20000000000 => '65353130',
);

foreach ( $vectors as $timestamp => $expected ) {
	$actual = identity_security_kit_totp_at( $base32_secret, $timestamp, 8, 30 );
	identity_security_kit_test_assert( $expected === $actual, 'RFC 6238 SHA-1 vector at ' . $timestamp );
	$counter = identity_security_kit_totp_verify_counter( $base32_secret, $expected, $timestamp, 0, 8, 30 );
	identity_security_kit_test_assert( intdiv( $timestamp, 30 ) === $counter, 'RFC 6238 verification counter at ' . $timestamp );
}

$phone = identity_security_kit_normalize_phone( '+229 01 23 45 67 89' );
identity_security_kit_test_assert( '+2290123456789' === $phone, 'E.164 formatting normalization' );
identity_security_kit_test_assert( is_wp_error( identity_security_kit_normalize_phone( '01 23 45 67 89' ) ), 'E.164 country prefix required' );
identity_security_kit_test_assert( is_wp_error( identity_security_kit_normalize_phone( '+00012345678' ) ), 'E.164 rejects a zero country code' );
identity_security_kit_test_assert( is_wp_error( identity_security_kit_normalize_phone( '+229123' ) ), 'E.164 rejects short numbers' );

$encrypted = identity_security_kit_encrypt_secret( $base32_secret );
identity_security_kit_test_assert( ! is_wp_error( $encrypted ), 'Secret encryption provider available' );
identity_security_kit_test_assert( $base32_secret === identity_security_kit_decrypt_secret( $encrypted ), 'Secret encryption round trip' );
$tampered = substr( $encrypted, 0, -1 ) . ( 'A' === substr( $encrypted, -1 ) ? 'B' : 'A' );
identity_security_kit_test_assert( is_wp_error( identity_security_kit_decrypt_secret( $tampered ) ), 'Authenticated encryption rejects tampering' );

fwrite( STDOUT, "Identity Security Kit tests passed.\n" );
