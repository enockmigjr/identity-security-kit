<?php
/**
 * Channel-independent one-time password challenges.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return the shared OTP challenge table name. */
function identity_security_kit_get_otp_table() {
	global $wpdb;

	return $wpdb->prefix . 'identity_security_otp_challenges';
}

/** Normalize a public OTP purpose. */
function identity_security_kit_normalize_otp_purpose( $purpose ) {
	$purpose = sanitize_key( $purpose );

	return '' !== $purpose ? substr( $purpose, 0, 64 ) : 'account_verification';
}

/** Normalize a supported OTP channel. */
function identity_security_kit_normalize_otp_channel( $channel ) {
	$channel = sanitize_key( $channel );

	return in_array( $channel, array( 'email', 'sms' ), true ) ? $channel : '';
}

/** Hash a destination without storing the email address or phone in the challenge. */
function identity_security_kit_hash_otp_destination( $destination ) {
	return hash_hmac( 'sha256', strtolower( trim( (string) $destination ) ), wp_salt( 'auth' ) );
}

/** Return bounded OTP policy values for a channel. */
function identity_security_kit_get_otp_policy( $channel ) {
	$settings = identity_security_kit_get_settings();
	$prefix   = 'sms' === $channel ? 'sms_otp_' : 'email_otp_';

	return array(
		'ttl_minutes'   => max( 2, min( 30, absint( $settings[ $prefix . 'ttl_minutes' ] ?? 10 ) ) ),
		'length'        => max( 6, min( 8, absint( $settings[ $prefix . 'length' ] ?? 6 ) ) ),
		'max_attempts'  => max( 3, min( 10, absint( $settings[ $prefix . 'max_attempts' ] ?? 5 ) ) ),
		'resend_minutes' => max( 1, min( 30, absint( $settings[ $prefix . 'resend_minutes' ] ?? 2 ) ) ),
	);
}

/**
 * Create, store and deliver an OTP challenge.
 *
 * The delivery callback receives destination, raw code and a metadata array. The
 * raw code is never persisted or passed to hooks after delivery.
 *
 * @param int      $user_id    User ID.
 * @param string   $purpose    Purpose isolated from every other flow.
 * @param string   $channel    email or sms.
 * @param string   $destination Current canonical destination.
 * @param callable $deliver    Delivery callback.
 * @return int|WP_Error
 */
function identity_security_kit_create_otp_challenge( $user_id, $purpose, $channel, $destination, $deliver ) {
	global $wpdb;

	$user_id    = absint( $user_id );
	$purpose    = identity_security_kit_normalize_otp_purpose( $purpose );
	$channel    = identity_security_kit_normalize_otp_channel( $channel );
	$destination = trim( (string) $destination );
	if ( ! $user_id || ! get_userdata( $user_id ) || '' === $channel || '' === $destination || ! is_callable( $deliver ) ) {
		return new WP_Error( 'invalid_otp_challenge', __( 'The verification challenge is invalid.', 'identity-security-kit' ) );
	}

	$policy           = identity_security_kit_get_otp_policy( $channel );
	$table            = identity_security_kit_get_otp_table();
	$destination_hash = identity_security_kit_hash_otp_destination( $destination );
	$latest_created   = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT created_at FROM {$table} WHERE user_id = %d AND purpose = %s AND channel = %s AND status <> %s ORDER BY id DESC LIMIT 1",
			$user_id,
			$purpose,
			$channel,
			'delivery_failed'
		)
	);
	if ( $latest_created ) {
		$latest_timestamp = strtotime( $latest_created . ' UTC' );
		if ( $latest_timestamp && ( time() - $latest_timestamp ) < ( $policy['resend_minutes'] * MINUTE_IN_SECONDS ) ) {
			return new WP_Error( 'otp_rate_limited', __( 'Please wait before requesting another code.', 'identity-security-kit' ) );
		}
	}

	try {
		$minimum        = 10 ** ( $policy['length'] - 1 );
		$maximum        = ( 10 ** $policy['length'] ) - 1;
		$code           = (string) random_int( $minimum, $maximum );
		$correlation_id = wp_generate_uuid4();
		$idempotency_key = hash_hmac( 'sha256', $correlation_id . '|' . $user_id . '|' . $purpose . '|' . $channel, wp_salt( 'nonce' ) );
	} catch ( Exception $exception ) {
		identity_security_kit_log_event( 'otp_random_failed', 'failure', $user_id, array( 'channel' => $channel, 'purpose' => $purpose ) );
		return new WP_Error( 'otp_generation_failed', __( 'The verification code could not be prepared.', 'identity-security-kit' ) );
	}

	$now     = gmdate( 'Y-m-d H:i:s' );
	$expires = gmdate( 'Y-m-d H:i:s', time() + ( $policy['ttl_minutes'] * MINUTE_IN_SECONDS ) );
	$inserted = $wpdb->insert(
		$table,
		array(
			'user_id'          => $user_id,
			'purpose'          => $purpose,
			'channel'          => $channel,
			'destination_hash' => $destination_hash,
			'code_hash'        => wp_hash_password( $code ),
			'status'           => 'pending',
			'attempts'         => 0,
			'max_attempts'     => $policy['max_attempts'],
			'expires_at'       => $expires,
			'created_at'       => $now,
			'correlation_id'   => $correlation_id,
			'idempotency_key'  => $idempotency_key,
		),
		array( '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s' )
	);
	if ( false === $inserted ) {
		identity_security_kit_log_event( 'otp_create_failed', 'failure', $user_id, array( 'channel' => $channel, 'purpose' => $purpose ) );
		return new WP_Error( 'otp_storage_failed', __( 'The verification code could not be prepared.', 'identity-security-kit' ) );
	}

	$challenge_id = absint( $wpdb->insert_id );
	$delivery = call_user_func(
		$deliver,
		$destination,
		$code,
		array(
			'challenge_id'   => $challenge_id,
			'user_id'        => $user_id,
			'purpose'        => $purpose,
			'channel'        => $channel,
			'ttl_minutes'    => $policy['ttl_minutes'],
			'correlation_id' => $correlation_id,
			'idempotency_key' => $idempotency_key,
		)
	);
	unset( $code );
	if ( is_wp_error( $delivery ) || true !== $delivery ) {
		$wpdb->update( $table, array( 'status' => 'delivery_failed', 'code_hash' => '' ), array( 'id' => $challenge_id ), array( '%s', '%s' ), array( '%d' ) );
		identity_security_kit_log_event( 'otp_delivery_failed', 'failure', $user_id, array( 'channel' => $channel, 'purpose' => $purpose, 'correlation_id' => $correlation_id ) );
		return is_wp_error( $delivery ) ? $delivery : new WP_Error( 'otp_delivery_failed', __( 'The verification code could not be sent.', 'identity-security-kit' ) );
	}

	$wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table} SET status = %s, code_hash = %s WHERE user_id = %d AND purpose = %s AND channel = %s AND status = %s AND id <> %d",
			'superseded',
			'',
			$user_id,
			$purpose,
			$channel,
			'pending',
			$challenge_id
		)
	);
	identity_security_kit_log_event( 'otp_created', 'info', $user_id, array( 'channel' => $channel, 'purpose' => $purpose, 'correlation_id' => $correlation_id ) );
	do_action( 'identity_security_kit_otp_created', $challenge_id, $user_id, $purpose, $channel );

	return $challenge_id;
}

/** Verify and atomically consume an OTP challenge. */
function identity_security_kit_verify_otp_challenge( $challenge_id, $user_id, $code, $purpose, $channel, $destination ) {
	global $wpdb;

	$challenge_id = absint( $challenge_id );
	$user_id      = absint( $user_id );
	$purpose      = identity_security_kit_normalize_otp_purpose( $purpose );
	$channel      = identity_security_kit_normalize_otp_channel( $channel );
	$code         = preg_replace( '/\D+/', '', (string) $code );
	$table        = identity_security_kit_get_otp_table();
	$now          = gmdate( 'Y-m-d H:i:s' );
	$challenge    = $wpdb->get_row(
		$wpdb->prepare(
			"SELECT id, destination_hash, code_hash, status, attempts, max_attempts, expires_at, correlation_id FROM {$table} WHERE id = %d AND user_id = %d AND purpose = %s AND channel = %s LIMIT 1",
			$challenge_id,
			$user_id,
			$purpose,
			$channel
		),
		ARRAY_A
	);
	if ( ! $challenge || 'pending' !== $challenge['status'] ) {
		identity_security_kit_log_event( 'otp_rejected', 'warning', $user_id, array( 'channel' => $channel, 'purpose' => $purpose, 'reason' => 'invalid_or_replayed' ) );
		return new WP_Error( 'otp_invalid', __( 'The verification code is invalid or no longer available.', 'identity-security-kit' ) );
	}
	if ( ! hash_equals( $challenge['destination_hash'], identity_security_kit_hash_otp_destination( $destination ) ) ) {
		$wpdb->update( $table, array( 'status' => 'superseded', 'code_hash' => '' ), array( 'id' => $challenge_id ), array( '%s', '%s' ), array( '%d' ) );
		return new WP_Error( 'otp_destination_changed', __( 'The destination changed. Request a new code.', 'identity-security-kit' ) );
	}
	if ( $challenge['expires_at'] < $now ) {
		$wpdb->update( $table, array( 'status' => 'expired', 'code_hash' => '' ), array( 'id' => $challenge_id ), array( '%s', '%s' ), array( '%d' ) );
		return new WP_Error( 'otp_expired', __( 'The verification code has expired.', 'identity-security-kit' ) );
	}

	$attempts     = absint( $challenge['attempts'] );
	$max_attempts = absint( $challenge['max_attempts'] );
	if ( $attempts >= $max_attempts ) {
		return new WP_Error( 'otp_locked', __( 'Too many incorrect attempts. Request a new code.', 'identity-security-kit' ) );
	}
	if ( ! preg_match( '/^[0-9]{6,8}$/', $code ) || ! wp_check_password( $code, $challenge['code_hash'] ) ) {
		$new_attempts = $attempts + 1;
		$new_status   = $new_attempts >= $max_attempts ? 'locked' : 'pending';
		$new_hash     = 'locked' === $new_status ? '' : $challenge['code_hash'];
		$wpdb->update( $table, array( 'attempts' => $new_attempts, 'status' => $new_status, 'code_hash' => $new_hash ), array( 'id' => $challenge_id, 'status' => 'pending' ), array( '%d', '%s', '%s' ), array( '%d', '%s' ) );
		identity_security_kit_log_event( 'otp_rejected', 'warning', $user_id, array( 'channel' => $channel, 'purpose' => $purpose, 'reason' => 'incorrect', 'attempts' => $new_attempts ) );
		return new WP_Error( 'otp_incorrect', __( 'The verification code is incorrect.', 'identity-security-kit' ) );
	}

	$consumed = $wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table} SET status = %s, consumed_at = %s, code_hash = %s WHERE id = %d AND user_id = %d AND purpose = %s AND channel = %s AND status = %s AND expires_at >= %s AND attempts < max_attempts",
			'consumed',
			$now,
			'',
			$challenge_id,
			$user_id,
			$purpose,
			$channel,
			'pending',
			$now
		)
	);
	if ( 1 !== $consumed ) {
		return new WP_Error( 'otp_replayed', __( 'The verification code was already used or expired.', 'identity-security-kit' ) );
	}

	identity_security_kit_log_event( 'otp_verified', 'success', $user_id, array( 'channel' => $channel, 'purpose' => $purpose, 'correlation_id' => $challenge['correlation_id'] ) );
	do_action( 'identity_security_kit_otp_verified', $user_id, $purpose, $channel, $challenge_id );

	return true;
}
