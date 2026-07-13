<?php
/**
 * TOTP enrollment and recovery codes for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Return the active TOTP secret meta key.
 *
 * @return string
 */
function identity_security_kit_totp_secret_meta_key() {
	return 'identity_mfa_totp_secret';
}

/**
 * Return whether authenticated encryption is available.
 *
 * @return bool
 */
function identity_security_kit_mfa_runtime_supported() {
	return function_exists( 'sodium_crypto_secretbox' ) || function_exists( 'openssl_encrypt' );
}

/**
 * Generate a 160-bit Base32 TOTP secret.
 *
 * @return string|WP_Error
 */
function identity_security_kit_generate_totp_secret() {
	try {
		return identity_security_kit_base32_encode( random_bytes( 20 ) );
	} catch ( Exception $exception ) {
		return new WP_Error( 'totp_random_failed', __( 'The authenticator secret could not be generated.', 'identity-security-kit' ) );
	}
}

/**
 * Return an active decrypted TOTP secret.
 *
 * @param int $user_id User ID.
 * @return string|WP_Error
 */
function identity_security_kit_get_totp_secret( $user_id ) {
	$stored = (string) get_user_meta( absint( $user_id ), identity_security_kit_totp_secret_meta_key(), true );
	if ( '' === $stored ) {
		return new WP_Error( 'totp_not_enabled', __( 'Authenticator verification is not enabled.', 'identity-security-kit' ) );
	}

	return identity_security_kit_decrypt_secret( $stored );
}

/**
 * Return whether TOTP is enabled for a user.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function identity_security_kit_is_totp_enabled( $user_id ) {
	return '' !== (string) get_user_meta( absint( $user_id ), identity_security_kit_totp_secret_meta_key(), true );
}

/**
 * Begin a short-lived TOTP enrollment.
 *
 * @param int $user_id User ID.
 * @return string|WP_Error Base32 secret.
 */
function identity_security_kit_begin_totp_enrollment( $user_id ) {
	$user_id = absint( $user_id );
	if ( ! get_userdata( $user_id ) ) {
		return new WP_Error( 'invalid_user', __( 'The account is unavailable.', 'identity-security-kit' ) );
	}
	if ( ! identity_security_kit_mfa_runtime_supported() ) {
		return new WP_Error( 'mfa_runtime_unavailable', __( 'Authenticated encryption is unavailable on this server.', 'identity-security-kit' ) );
	}

	$secret = identity_security_kit_generate_totp_secret();
	if ( is_wp_error( $secret ) ) {
		return $secret;
	}
	identity_security_kit_mfa_clear_failures( $user_id, 'totp_enrollment' );
	$encrypted = identity_security_kit_encrypt_secret( $secret );
	if ( is_wp_error( $encrypted ) ) {
		return $encrypted;
	}

	update_user_meta(
		$user_id,
		'identity_mfa_totp_pending',
		array(
			'secret'     => $encrypted,
			'expires_at' => time() + ( 15 * MINUTE_IN_SECONDS ),
		)
	);
	identity_security_kit_log_event( 'totp_enrollment_started', 'info', $user_id );

	return $secret;
}

/**
 * Return a valid pending enrollment secret.
 *
 * @param int $user_id User ID.
 * @return string|WP_Error
 */
function identity_security_kit_get_pending_totp_secret( $user_id ) {
	$user_id = absint( $user_id );
	$pending = get_user_meta( $user_id, 'identity_mfa_totp_pending', true );
	if ( ! is_array( $pending ) || empty( $pending['secret'] ) || empty( $pending['expires_at'] ) ) {
		return new WP_Error( 'totp_enrollment_missing', __( 'Start authenticator enrollment again.', 'identity-security-kit' ) );
	}
	if ( absint( $pending['expires_at'] ) < time() ) {
		delete_user_meta( $user_id, 'identity_mfa_totp_pending' );
		return new WP_Error( 'totp_enrollment_expired', __( 'The authenticator enrollment expired.', 'identity-security-kit' ) );
	}

	return identity_security_kit_decrypt_secret( (string) $pending['secret'] );
}

/**
 * Build a standard otpauth URI for authenticator applications.
 *
 * @param int    $user_id User ID.
 * @param string $secret  Base32 secret.
 * @return string|WP_Error
 */
function identity_security_kit_get_totp_uri( $user_id, $secret ) {
	$user = get_userdata( absint( $user_id ) );
	if ( ! $user ) {
		return new WP_Error( 'invalid_user', __( 'The account is unavailable.', 'identity-security-kit' ) );
	}

	$issuer  = wp_strip_all_tags( wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) );
	$issuer  = '' !== trim( $issuer ) ? trim( $issuer ) : wp_parse_url( home_url( '/' ), PHP_URL_HOST );
	$account = is_email( $user->user_email ) ? $user->user_email : $user->user_login;

	return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $account ) . '?' . http_build_query(
		array(
			'secret'    => $secret,
			'issuer'    => $issuer,
			'algorithm' => 'SHA1',
			'digits'    => 6,
			'period'    => 30,
		),
		'',
		'&',
		PHP_QUERY_RFC3986
	);
}

/**
 * Apply the non-bypassable MFA verification rate limit.
 *
 * @param int    $user_id User ID.
 * @param string $method  Factor method.
 * @return bool
 */
function identity_security_kit_mfa_rate_limit( $user_id, $method ) {
	$settings = identity_security_kit_get_settings();
	$limit    = isset( $settings['mfa_attempts_per_window'] ) ? absint( $settings['mfa_attempts_per_window'] ) : 5;
	$key      = identity_security_kit_mfa_failure_key( $user_id, $method );

	return absint( get_transient( $key ) ) < $limit;
}

/** Return the privacy-preserving MFA failure bucket key. */
function identity_security_kit_mfa_failure_key( $user_id, $method ) {
	return 'isk_mfa_' . md5( absint( $user_id ) . '|' . sanitize_key( $method ) . '|' . identity_security_kit_get_rate_limit_fingerprint() );
}

/** Record one failed MFA verification. */
function identity_security_kit_mfa_record_failure( $user_id, $method ) {
	$settings = identity_security_kit_get_settings();
	$window   = isset( $settings['rate_limit_window_minutes'] ) ? absint( $settings['rate_limit_window_minutes'] ) * MINUTE_IN_SECONDS : 15 * MINUTE_IN_SECONDS;
	$key      = identity_security_kit_mfa_failure_key( $user_id, $method );
	set_transient( $key, absint( get_transient( $key ) ) + 1, max( MINUTE_IN_SECONDS, $window ) );
}

/** Clear failed MFA attempts after successful verification. */
function identity_security_kit_mfa_clear_failures( $user_id, $method ) {
	delete_transient( identity_security_kit_mfa_failure_key( $user_id, $method ) );
}

/**
 * Verify a TOTP code with replay prevention.
 *
 * @param int    $user_id User ID.
 * @param string $code    Submitted code.
 * @param int    $now     Optional Unix timestamp for deterministic integrations.
 * @return true|WP_Error
 */
function identity_security_kit_verify_totp_for_user( $user_id, $code, $now = 0 ) {
	$user_id = absint( $user_id );
	if ( ! identity_security_kit_mfa_rate_limit( $user_id, 'totp' ) ) {
		identity_security_kit_log_event( 'totp_rate_limited', 'warning', $user_id );
		return new WP_Error( 'mfa_rate_limited', __( 'Too many verification attempts. Try again later.', 'identity-security-kit' ) );
	}

	$secret = identity_security_kit_get_totp_secret( $user_id );
	if ( is_wp_error( $secret ) ) {
		return $secret;
	}
	$counter = identity_security_kit_totp_verify_counter( $secret, $code, $now ? absint( $now ) : time(), 1, 6, 30 );
	if ( false === $counter ) {
		identity_security_kit_mfa_record_failure( $user_id, 'totp' );
		identity_security_kit_log_event( 'totp_rejected', 'warning', $user_id, array( 'reason' => 'invalid' ) );
		return new WP_Error( 'totp_invalid', __( 'The authenticator code is invalid.', 'identity-security-kit' ) );
	}

	$meta_key = 'identity_mfa_totp_last_counter';
	$previous = get_user_meta( $user_id, $meta_key, true );
	if ( '' !== (string) $previous && $counter <= (int) $previous ) {
		identity_security_kit_mfa_record_failure( $user_id, 'totp' );
		identity_security_kit_log_event( 'totp_rejected', 'warning', $user_id, array( 'reason' => 'replayed' ) );
		return new WP_Error( 'totp_replayed', __( 'This authenticator code was already used.', 'identity-security-kit' ) );
	}

	$stored = '' === (string) $previous
		? add_user_meta( $user_id, $meta_key, $counter, true )
		: update_user_meta( $user_id, $meta_key, $counter, $previous );
	if ( false === $stored ) {
		return new WP_Error( 'totp_replayed', __( 'This authenticator code was already used.', 'identity-security-kit' ) );
	}

	identity_security_kit_mfa_clear_failures( $user_id, 'totp' );
	identity_security_kit_log_event( 'totp_verified', 'success', $user_id );

	return true;
}

/**
 * Generate and replace saved recovery codes.
 *
 * @param int $user_id User ID.
 * @param int $count   Number of codes.
 * @return string[]|WP_Error Raw codes, shown once.
 */
function identity_security_kit_generate_recovery_codes( $user_id, $count = 10 ) {
	$user_id = absint( $user_id );
	$count   = max( 5, min( 12, absint( $count ) ) );
	$raw     = array();
	$hashes  = array();

	try {
		for ( $index = 0; $index < $count; $index++ ) {
			$compact  = identity_security_kit_base32_encode( random_bytes( 10 ) );
			$raw[]    = implode( '-', str_split( $compact, 4 ) );
			$hashes[] = wp_hash_password( $compact );
		}
	} catch ( Exception $exception ) {
		return new WP_Error( 'recovery_random_failed', __( 'Recovery codes could not be generated.', 'identity-security-kit' ) );
	}

	update_user_meta( $user_id, 'identity_mfa_recovery_codes', $hashes );
	identity_security_kit_log_event( 'recovery_codes_generated', 'success', $user_id, array( 'count' => count( $hashes ) ) );

	return $raw;
}

/**
 * Verify and consume a saved recovery code.
 *
 * @param int    $user_id User ID.
 * @param string $code    Submitted code.
 * @return true|WP_Error
 */
function identity_security_kit_verify_recovery_code( $user_id, $code ) {
	$user_id = absint( $user_id );
	if ( ! identity_security_kit_mfa_rate_limit( $user_id, 'recovery' ) ) {
		return new WP_Error( 'mfa_rate_limited', __( 'Too many verification attempts. Try again later.', 'identity-security-kit' ) );
	}

	$code   = strtoupper( preg_replace( '/[^A-Z0-9]/i', '', (string) $code ) );
	$hashes = get_user_meta( $user_id, 'identity_mfa_recovery_codes', true );
	$hashes = is_array( $hashes ) ? array_values( $hashes ) : array();
	if ( ! preg_match( '/^[A-Z2-7]{16}$/', $code ) ) {
		return new WP_Error( 'recovery_code_invalid', __( 'The recovery code is invalid.', 'identity-security-kit' ) );
	}

	foreach ( $hashes as $index => $hash ) {
		if ( is_string( $hash ) && wp_check_password( $code, $hash ) ) {
			$updated = $hashes;
			unset( $updated[ $index ] );
			$updated = array_values( $updated );
			if ( false === update_user_meta( $user_id, 'identity_mfa_recovery_codes', $updated, $hashes ) ) {
				return new WP_Error( 'recovery_code_replayed', __( 'This recovery code was already used.', 'identity-security-kit' ) );
			}
			identity_security_kit_mfa_clear_failures( $user_id, 'recovery' );
			identity_security_kit_log_event( 'recovery_code_used', 'success', $user_id, array( 'remaining' => count( $updated ) ) );

			return true;
		}
	}

	identity_security_kit_mfa_record_failure( $user_id, 'recovery' );
	identity_security_kit_log_event( 'recovery_code_rejected', 'warning', $user_id );
	return new WP_Error( 'recovery_code_invalid', __( 'The recovery code is invalid.', 'identity-security-kit' ) );
}

/**
 * Verify either an authenticator or recovery code.
 *
 * @param int    $user_id User ID.
 * @param string $code    Submitted factor.
 * @return true|WP_Error
 */
function identity_security_kit_verify_totp_or_recovery( $user_id, $code ) {
	$compact = strtoupper( preg_replace( '/[^A-Z0-9]/i', '', (string) $code ) );
	if ( preg_match( '/^[A-Z2-7]{16}$/', $compact ) ) {
		return identity_security_kit_verify_recovery_code( $user_id, $compact );
	}

	return identity_security_kit_verify_totp_for_user( $user_id, $code );
}

/**
 * Confirm enrollment and return one-time recovery codes.
 *
 * @param int    $user_id User ID.
 * @param string $code    TOTP code.
 * @return string[]|WP_Error
 */
function identity_security_kit_confirm_totp_enrollment( $user_id, $code ) {
	$user_id = absint( $user_id );
	$secret  = identity_security_kit_get_pending_totp_secret( $user_id );
	if ( is_wp_error( $secret ) ) {
		return $secret;
	}
	if ( ! identity_security_kit_mfa_rate_limit( $user_id, 'totp_enrollment' ) ) {
		return new WP_Error( 'mfa_rate_limited', __( 'Too many verification attempts. Try again later.', 'identity-security-kit' ) );
	}
	$counter = identity_security_kit_totp_verify_counter( $secret, $code, time(), 1, 6, 30 );
	if ( false === $counter ) {
		identity_security_kit_mfa_record_failure( $user_id, 'totp_enrollment' );
		identity_security_kit_log_event( 'totp_enrollment_rejected', 'warning', $user_id );
		return new WP_Error( 'totp_invalid', __( 'The authenticator code is invalid.', 'identity-security-kit' ) );
	}

	identity_security_kit_mfa_clear_failures( $user_id, 'totp_enrollment' );
	$encrypted = identity_security_kit_encrypt_secret( $secret );
	if ( is_wp_error( $encrypted ) ) {
		return $encrypted;
	}
	update_user_meta( $user_id, identity_security_kit_totp_secret_meta_key(), $encrypted );
	update_user_meta( $user_id, 'identity_mfa_totp_last_counter', $counter );
	update_user_meta( $user_id, 'identity_mfa_enabled_at', gmdate( 'Y-m-d H:i:s' ) );
	delete_user_meta( $user_id, 'identity_mfa_totp_pending' );
	identity_security_kit_clear_mfa_grace_state( $user_id );

	$codes = identity_security_kit_generate_recovery_codes( $user_id );
	if ( is_wp_error( $codes ) ) {
		delete_user_meta( $user_id, identity_security_kit_totp_secret_meta_key() );
		delete_user_meta( $user_id, 'identity_mfa_totp_last_counter' );
		delete_user_meta( $user_id, 'identity_mfa_enabled_at' );
		return $codes;
	}

	identity_security_kit_destroy_other_sessions( $user_id );
	identity_security_kit_send_security_notification( $user_id, __( 'Authenticator verification was enabled on your account.', 'identity-security-kit' ) );
	identity_security_kit_log_event( 'totp_enabled', 'success', $user_id );
	do_action( 'identity_security_kit_mfa_enabled', $user_id, 'totp' );

	return $codes;
}

/**
 * Invalidate all other sessions after a sensitive security change.
 *
 * @param int $user_id User ID.
 */
function identity_security_kit_destroy_other_sessions( $user_id ) {
	if ( ! class_exists( 'WP_Session_Tokens' ) ) {
		return;
	}
	$manager = WP_Session_Tokens::get_instance( absint( $user_id ) );
	if ( get_current_user_id() === absint( $user_id ) && wp_get_session_token() ) {
		$manager->destroy_others( wp_get_session_token() );
	} else {
		$manager->destroy_all();
	}
}

/**
 * Notify the account email after a sensitive MFA change.
 *
 * @param int    $user_id User ID.
 * @param string $message Notification body.
 */
function identity_security_kit_send_security_notification( $user_id, $message ) {
	$user = get_userdata( absint( $user_id ) );
	if ( $user && is_email( $user->user_email ) ) {
		wp_mail(
			$user->user_email,
			sprintf( __( '[%s] Security change', 'identity-security-kit' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) ),
			$message . "\n\n" . __( 'If you did not make this change, reset your password and contact the site administrator.', 'identity-security-kit' )
		);
	}
}

/**
 * Temporarily store encrypted recovery codes for one-time display.
 *
 * @param int      $user_id User ID.
 * @param string[] $codes   Raw recovery codes.
 * @return string|WP_Error Display token.
 */
function identity_security_kit_store_recovery_display( $user_id, $codes ) {
	try {
		$token = identity_security_kit_base64url_encode( random_bytes( 18 ) );
	} catch ( Exception $exception ) {
		return new WP_Error( 'recovery_display_failed', __( 'Recovery codes could not be prepared for display.', 'identity-security-kit' ) );
	}
	$encrypted = identity_security_kit_encrypt_secret( wp_json_encode( array_values( $codes ) ) );
	if ( is_wp_error( $encrypted ) ) {
		return $encrypted;
	}
	set_transient( 'isk_recovery_' . absint( $user_id ) . '_' . hash( 'sha256', $token ), $encrypted, 10 * MINUTE_IN_SECONDS );

	return $token;
}

/**
 * Read and immediately delete one-time recovery display data.
 *
 * @param int    $user_id User ID.
 * @param string $token   Display token.
 * @return string[]
 */
function identity_security_kit_take_recovery_display( $user_id, $token ) {
	$token = preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $token );
	if ( strlen( $token ) < 20 ) {
		return array();
	}
	$key       = 'isk_recovery_' . absint( $user_id ) . '_' . hash( 'sha256', $token );
	$encrypted = get_transient( $key );
	delete_transient( $key );
	if ( ! is_string( $encrypted ) ) {
		return array();
	}
	$payload = identity_security_kit_decrypt_secret( $encrypted );
	$codes   = is_wp_error( $payload ) ? array() : json_decode( $payload, true );

	return is_array( $codes ) ? array_values( array_filter( $codes, 'is_string' ) ) : array();
}
