<?php
/**
 * Email verification challenge handling for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Return the user meta key used for email verification status.
 *
 * @return string
 */
function identity_security_kit_email_verified_meta_key() {
	return sanitize_key( apply_filters( 'identity_security_kit_email_verified_meta_key', 'identity_email_verified' ) );
}

/**
 * Return the user meta key used for pending verification status.
 *
 * @return string
 */
function identity_security_kit_email_pending_meta_key() {
	return sanitize_key( apply_filters( 'identity_security_kit_email_pending_meta_key', 'identity_email_verification_pending' ) );
}

/**
 * Hash a verification token or email without storing the raw value.
 *
 * @param string $value Raw value.
 * @return string
 */
function identity_security_kit_hash_email_challenge_value( $value ) {
	return hash_hmac( 'sha256', strtolower( trim( $value ) ), wp_salt( 'auth' ) );
}

/**
 * Check whether a user's current email has been verified.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function identity_security_kit_is_email_verified( $user_id ) {
	return '1' === (string) get_user_meta( absint( $user_id ), identity_security_kit_email_verified_meta_key(), true );
}

/**
 * Build a public verification URL for an email challenge.
 *
 * @param int    $user_id User ID.
 * @param string $token   Raw one-time token.
 * @return string
 */
function identity_security_kit_get_email_verification_url( $user_id, $token ) {
	return add_query_arg(
		array(
			'action' => 'identity_security_kit_verify_email',
			'uid'    => absint( $user_id ),
			'token'  => rawurlencode( $token ),
		),
		admin_url( 'admin-post.php' )
	);
}

/**
 * Return the number of minutes a user must wait before requesting another link.
 *
 * @return int
 */
function identity_security_kit_get_email_verification_resend_minutes() {
	$settings = identity_security_kit_get_settings();

	return max( 1, min( 1440, absint( $settings['email_verification_resend_minutes'] ) ) );
}

/**
 * Check whether a user may request a new verification challenge now.
 *
 * @param int    $user_id User ID.
 * @param string $email   Email address.
 * @return true|WP_Error
 */
function identity_security_kit_can_request_email_verification( $user_id, $email ) {
	global $wpdb;

	$user_id = absint( $user_id );
	$email   = sanitize_email( $email );

	if ( ! $user_id || ! is_email( $email ) ) {
		return new WP_Error( 'invalid_email_challenge', __( 'Invalid email verification request.', 'identity-security-kit' ) );
	}

	if ( identity_security_kit_is_email_verified( $user_id ) ) {
		return new WP_Error( 'already_verified', __( 'This email address is already verified.', 'identity-security-kit' ) );
	}

	$table       = identity_security_kit_get_email_verification_table();
	$email_hash  = identity_security_kit_hash_email_challenge_value( $email );
	$latest_date = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT created_at FROM {$table} WHERE user_id = %d AND email_hash = %s AND status = %s ORDER BY created_at DESC LIMIT 1",
			$user_id,
			$email_hash,
			'pending'
		)
	);

	if ( $latest_date ) {
		$cooldown_seconds = identity_security_kit_get_email_verification_resend_minutes() * MINUTE_IN_SECONDS;
		$latest_ts        = strtotime( $latest_date . ' UTC' );
		if ( $latest_ts && ( time() - $latest_ts ) < $cooldown_seconds ) {
			return new WP_Error( 'rate_limited', __( 'Please wait before requesting another verification email.', 'identity-security-kit' ) );
		}
	}

	return true;
}

/**
 * Create and send a verification challenge for a user's email address.
 *
 * @param int    $user_id User ID.
 * @param string $email   Email address to verify.
 * @return true|WP_Error
 */
function identity_security_kit_create_email_verification_challenge( $user_id, $email ) {
	global $wpdb;

	$user_id = absint( $user_id );
	$email   = sanitize_email( $email );

	if ( ! $user_id || ! is_email( $email ) ) {
		return new WP_Error( 'invalid_email_challenge', __( 'Invalid email verification request.', 'identity-security-kit' ) );
	}
	$user = get_userdata( $user_id );
	if ( ! $user || strtolower( $user->user_email ) !== strtolower( $email ) ) {
		return new WP_Error( 'email_challenge_mismatch', __( 'The email verification request does not match the account.', 'identity-security-kit' ) );
	}

	$settings   = identity_security_kit_get_settings();
	$ttl_hours  = max( 1, min( 168, absint( $settings['email_verification_ttl_hours'] ) ) );
	$token      = wp_generate_password( 43, false, false );
	$now        = gmdate( 'Y-m-d H:i:s' );
	$expires    = gmdate( 'Y-m-d H:i:s', time() + ( HOUR_IN_SECONDS * $ttl_hours ) );
	$table      = identity_security_kit_get_email_verification_table();
	$email_hash = identity_security_kit_hash_email_challenge_value( $email );


	$inserted = $wpdb->insert(
		$table,
		array(
			'user_id'    => $user_id,
			'email_hash' => $email_hash,
			'token_hash' => identity_security_kit_hash_email_challenge_value( $token ),
			'status'     => 'pending',
			'expires_at' => $expires,
			'created_at' => $now,
		),
		array( '%d', '%s', '%s', '%s', '%s', '%s' )
	);

	if ( false === $inserted ) {
		identity_security_kit_log_event( 'email_verification_challenge_failed', 'failure', $user_id, array( 'reason' => 'db_insert_failed' ) );
		return new WP_Error( 'email_challenge_insert_failed', __( 'Email verification could not be prepared.', 'identity-security-kit' ) );
	}
	$challenge_id = absint( $wpdb->insert_id );

	update_user_meta( $user_id, identity_security_kit_email_verified_meta_key(), '0' );
	update_user_meta( $user_id, identity_security_kit_email_pending_meta_key(), '1' );

	$verify_url = identity_security_kit_get_email_verification_url( $user_id, $token );
	$subject    = sprintf( __( '[%s] Verify your email address', 'identity-security-kit' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) );
	$name       = $user && $user->display_name ? $user->display_name : __( 'there', 'identity-security-kit' );
	if ( ! identity_security_kit_send_transactional_email(
		$email,
		$subject,
		array(
			'preheader'    => __( 'Verify your email address to activate account security.', 'identity-security-kit' ),
			'title'        => __( 'Verify your email address', 'identity-security-kit' ),
			'greeting'     => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $name ),
			'intro'        => __( 'Please verify your email address to secure your account.', 'identity-security-kit' ),
			'details'      => array( sprintf( __( 'This link remains valid for %d hour(s).', 'identity-security-kit' ), $ttl_hours ) ),
			'action_url'   => $verify_url,
			'action_label' => __( 'Verify email address', 'identity-security-kit' ),
			'notice'       => __( 'If you did not request this, ignore this email.', 'identity-security-kit' ),
		)
	) ) {
		$wpdb->update(
			$table,
			array( 'status' => 'delivery_failed', 'token_hash' => '' ),
			array( 'id' => $challenge_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);
		identity_security_kit_log_event( 'email_verification_mail_failed', 'warning', $user_id );
		return new WP_Error( 'email_verification_mail_failed', __( 'Email verification message could not be sent.', 'identity-security-kit' ) );
	}

	$wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table} SET status = %s WHERE user_id = %d AND email_hash = %s AND status = %s AND id <> %d",
			'superseded',
			$user_id,
			$email_hash,
			'pending',
			$challenge_id
		)
	);

	identity_security_kit_log_event( 'email_verification_challenge_created', 'info', $user_id, array( 'expires_hours' => $ttl_hours ) );

	return true;
}

/**
 * Verify and atomically consume an email verification challenge.
 *
 * @param int    $user_id User ID.
 * @param string $token   Raw one-time token.
 * @return true|WP_Error
 */
function identity_security_kit_verify_email_challenge( $user_id, $token ) {
	global $wpdb;

	$user_id = absint( $user_id );
	$token   = sanitize_text_field( $token );
	if ( ! $user_id || ! preg_match( '/^[A-Za-z0-9]{20,128}$/', $token ) ) {
		return new WP_Error( 'email_challenge_invalid', __( 'The email verification request is invalid or expired.', 'identity-security-kit' ) );
	}

	$table      = identity_security_kit_get_email_verification_table();
	$token_hash = identity_security_kit_hash_email_challenge_value( $token );
	$now        = gmdate( 'Y-m-d H:i:s' );
	$challenge  = $wpdb->get_row(
		$wpdb->prepare(
			"SELECT id, user_id, email_hash, expires_at FROM {$table} WHERE user_id = %d AND token_hash = %s AND status = %s LIMIT 1",
			$user_id,
			$token_hash,
			'pending'
		),
		ARRAY_A
	);

	if ( ! $challenge ) {
		return new WP_Error( 'email_challenge_invalid', __( 'The email verification request is invalid or expired.', 'identity-security-kit' ) );
	}

	$user = get_userdata( $user_id );
	if ( ! $user || ! hash_equals( $challenge['email_hash'], identity_security_kit_hash_email_challenge_value( $user->user_email ) ) ) {
		$wpdb->update(
			$table,
			array( 'status' => 'superseded', 'token_hash' => '' ),
			array( 'id' => absint( $challenge['id'] ) ),
			array( '%s', '%s' ),
			array( '%d' )
		);
		return new WP_Error( 'email_challenge_email_changed', __( 'The account email changed. Request a new verification link.', 'identity-security-kit' ) );
	}

	if ( $challenge['expires_at'] < $now ) {
		$wpdb->update(
			$table,
			array( 'status' => 'expired', 'token_hash' => '' ),
			array( 'id' => absint( $challenge['id'] ) ),
			array( '%s', '%s' ),
			array( '%d' )
		);
		return new WP_Error( 'email_challenge_expired', __( 'The email verification request has expired.', 'identity-security-kit' ) );
	}

	$consumed = $wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table} SET status = %s, verified_at = %s, token_hash = %s WHERE id = %d AND user_id = %d AND status = %s AND expires_at >= %s",
			'verified',
			$now,
			'',
			absint( $challenge['id'] ),
			$user_id,
			'pending',
			$now
		)
	);
	if ( 1 !== $consumed ) {
		return new WP_Error( 'email_challenge_replayed', __( 'The email verification request was already used.', 'identity-security-kit' ) );
	}

	update_user_meta( $user_id, identity_security_kit_email_verified_meta_key(), '1' );
	update_user_meta( $user_id, identity_security_kit_email_pending_meta_key(), '0' );
	identity_security_kit_log_event( 'email_verification_success', 'success', $user_id );

	return true;
}

/**
 * Handle public email verification links.
 */
function identity_security_kit_handle_email_verification() {
	$user_id = isset( $_GET['uid'] ) ? absint( $_GET['uid'] ) : 0;
	$token   = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';
	$result  = identity_security_kit_verify_email_challenge( $user_id, $token );
	if ( is_wp_error( $result ) ) {
		identity_security_kit_log_event( 'email_verification_invalid', 'warning', $user_id );
		$status = 'email_challenge_expired' === $result->get_error_code() ? 'expired' : 'invalid';
		identity_security_kit_redirect( 'login', array( 'verify' => $status ) );
	}

	$target = is_user_logged_in() && (int) get_current_user_id() === (int) $user_id ? 'profile' : 'login';
	identity_security_kit_redirect( $target, array( 'verify' => 'success' ) );
}
add_action( 'admin_post_nopriv_identity_security_kit_verify_email', 'identity_security_kit_handle_email_verification' );
add_action( 'admin_post_identity_security_kit_verify_email', 'identity_security_kit_handle_email_verification' );

/**
 * Handle authenticated requests to resend the verification email.
 */
function identity_security_kit_handle_resend_email_verification() {
	if ( ! is_user_logged_in() ) {
		identity_security_kit_redirect( 'login' );
	}

	check_admin_referer( 'identity_security_kit_resend_email_verification' );

	$user_id = get_current_user_id();
	$user    = wp_get_current_user();
	if ( ! identity_security_kit_rate_limit_by_setting( 'email_verification_resend', 'email_resend_attempts_per_window' ) ) {
		identity_security_kit_log_event( 'email_verification_resend_rate_limited', 'warning', $user_id );
		identity_security_kit_redirect( 'profile', array( 'verify' => 'rate_limited' ) );
	}

	if ( ! $user || ! is_email( $user->user_email ) ) {
		identity_security_kit_log_event( 'email_verification_resend_rejected', 'warning', $user_id, array( 'reason' => 'invalid_email' ) );
		identity_security_kit_redirect( 'profile', array( 'verify' => 'invalid' ) );
	}

	$allowed = identity_security_kit_can_request_email_verification( $user_id, $user->user_email );
	if ( is_wp_error( $allowed ) ) {
		identity_security_kit_log_event( 'email_verification_resend_rejected', 'warning', $user_id, array( 'reason' => $allowed->get_error_code() ) );
		identity_security_kit_redirect( 'profile', array( 'verify' => sanitize_key( $allowed->get_error_code() ) ) );
	}

	$result = identity_security_kit_create_email_verification_challenge( $user_id, $user->user_email );
	if ( is_wp_error( $result ) ) {
		identity_security_kit_log_event( 'email_verification_resend_failed', 'warning', $user_id, array( 'reason' => $result->get_error_code() ) );
		identity_security_kit_redirect( 'profile', array( 'verify' => 'deferred' ) );
	}

	identity_security_kit_log_event( 'email_verification_resend_success', 'info', $user_id );
	identity_security_kit_redirect( 'profile', array( 'verify' => 'resent' ) );
}
add_action( 'admin_post_identity_security_kit_resend_email_verification', 'identity_security_kit_handle_resend_email_verification' );
