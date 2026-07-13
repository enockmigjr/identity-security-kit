<?php
/**
 * Authenticated encryption for Identity Security Kit secrets.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Derive a site-specific encryption key from WordPress salts.
 *
 * @return string Binary key.
 */
function identity_security_kit_secret_key() {
	return hash_hmac( 'sha256', 'identity-security-kit:secret-storage:v1', wp_salt( 'secure_auth' ), true );
}

/**
 * Encode binary data for storage.
 *
 * @param string $value Binary value.
 * @return string
 */
function identity_security_kit_base64url_encode( $value ) {
	return rtrim( strtr( base64_encode( $value ), '+/', '-_' ), '=' );
}

/**
 * Decode stored binary data.
 *
 * @param string $value Encoded value.
 * @return string|false
 */
function identity_security_kit_base64url_decode( $value ) {
	$value   = strtr( (string) $value, '-_', '+/' );
	$padding = strlen( $value ) % 4;
	if ( $padding ) {
		$value .= str_repeat( '=', 4 - $padding );
	}

	return base64_decode( $value, true );
}

/**
 * Encrypt a secret with authentication and fail closed when unavailable.
 *
 * @param string $plaintext Secret value.
 * @return string|WP_Error
 */
function identity_security_kit_encrypt_secret( $plaintext ) {
	$plaintext = (string) $plaintext;
	$key       = identity_security_kit_secret_key();

	try {
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce      = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $key );

			return 's1.' . identity_security_kit_base64url_encode( $nonce . $ciphertext );
		}

		if ( function_exists( 'openssl_encrypt' ) ) {
			$nonce      = random_bytes( 12 );
			$tag        = '';
			$ciphertext = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, 'identity-security-kit', 16 );
			if ( false !== $ciphertext ) {
				return 'o1.' . identity_security_kit_base64url_encode( $nonce . $tag . $ciphertext );
			}
		}
	} catch ( Exception $exception ) {
		return new WP_Error( 'secret_encryption_failed', __( 'The security secret could not be encrypted.', 'identity-security-kit' ) );
	}

	return new WP_Error( 'secret_encryption_unavailable', __( 'No supported authenticated encryption provider is available.', 'identity-security-kit' ) );
}

/**
 * Decrypt a stored secret.
 *
 * @param string $stored Encrypted envelope.
 * @return string|WP_Error
 */
function identity_security_kit_decrypt_secret( $stored ) {
	$stored = (string) $stored;
	$key    = identity_security_kit_secret_key();

	if ( 0 === strpos( $stored, 's1.' ) && function_exists( 'sodium_crypto_secretbox_open' ) ) {
		$payload = identity_security_kit_base64url_decode( substr( $stored, 3 ) );
		if ( false !== $payload && strlen( $payload ) > SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			$nonce      = substr( $payload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$ciphertext = substr( $payload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$plaintext  = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );
			if ( false !== $plaintext ) {
				return $plaintext;
			}
		}
	}

	if ( 0 === strpos( $stored, 'o1.' ) && function_exists( 'openssl_decrypt' ) ) {
		$payload = identity_security_kit_base64url_decode( substr( $stored, 3 ) );
		if ( false !== $payload && strlen( $payload ) > 28 ) {
			$nonce      = substr( $payload, 0, 12 );
			$tag        = substr( $payload, 12, 16 );
			$ciphertext = substr( $payload, 28 );
			$plaintext  = openssl_decrypt( $ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, 'identity-security-kit' );
			if ( false !== $plaintext ) {
				return $plaintext;
			}
		}
	}

	return new WP_Error( 'secret_decryption_failed', __( 'The security secret is unavailable or has been altered.', 'identity-security-kit' ) );
}
