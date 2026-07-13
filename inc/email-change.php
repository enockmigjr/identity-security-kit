<?php
/**
 * Confirmed email change workflow for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return the private user-meta key for a pending email change. */
function identity_security_kit_pending_email_change_meta_key() {
	return 'identity_pending_email_change';
}

/** Track the plugin's own confirmed update so the generic profile hook can ignore it. */
function identity_security_kit_is_confirming_email_change( $state = null ) {
	static $confirming = false;

	if ( is_bool( $state ) ) {
		$confirming = $state;
	}

	return $confirming;
}

/** Build the public capability URL used to confirm a pending address. */
function identity_security_kit_get_email_change_url( $user_id, $token ) {
	return add_query_arg(
		array(
			'action' => 'identity_security_kit_confirm_email_change',
			'uid'    => absint( $user_id ),
			'token'  => rawurlencode( $token ),
		),
		admin_url( 'admin-post.php' )
	);
}

/** Read and decrypt the current user's pending change for account UI. */
function identity_security_kit_get_pending_email_change( $user_id ) {
	$pending = get_user_meta( absint( $user_id ), identity_security_kit_pending_email_change_meta_key(), true );
	if ( ! is_array( $pending ) || 'pending' !== ( $pending['status'] ?? '' ) || empty( $pending['email'] ) || empty( $pending['expires_at'] ) ) {
		return null;
	}
	if ( absint( $pending['expires_at'] ) < time() ) {
		delete_user_meta( absint( $user_id ), identity_security_kit_pending_email_change_meta_key(), $pending );
		return null;
	}

	$email = identity_security_kit_decrypt_secret( $pending['email'] );
	if ( is_wp_error( $email ) || ! is_email( $email ) ) {
		delete_user_meta( absint( $user_id ), identity_security_kit_pending_email_change_meta_key(), $pending );
		return null;
	}

	return array(
		'email'      => sanitize_email( $email ),
		'expires_at' => absint( $pending['expires_at'] ),
	);
}

/** Invalidate challenges and factors that were bound to the previous email. */
function identity_security_kit_invalidate_email_bound_proofs( $user_id, $mark_unverified = true ) {
	global $wpdb;

	$user_id = absint( $user_id );
	if ( $mark_unverified ) {
		update_user_meta( $user_id, identity_security_kit_email_verified_meta_key(), '0' );
		update_user_meta( $user_id, identity_security_kit_email_pending_meta_key(), '1' );
	}
	delete_user_meta( $user_id, 'identity_mfa_email_enabled' );
	delete_user_meta( $user_id, 'identity_mfa_preferred_method', 'email' );

	$login_hash = (string) get_user_meta( $user_id, 'identity_mfa_login_challenge', true );
	if ( preg_match( '/^[a-f0-9]{64}$/', $login_hash ) ) {
		delete_transient( 'isk_login_' . $login_hash );
	}
	delete_user_meta( $user_id, 'identity_mfa_login_challenge' );

	$verification_table = identity_security_kit_get_email_verification_table();
	$wpdb->query(
		$wpdb->prepare(
			"UPDATE {$verification_table} SET status = %s, token_hash = %s WHERE user_id = %d AND status = %s",
			'superseded',
			'',
			$user_id,
			'pending'
		)
	);

	$otp_table = identity_security_kit_get_otp_table();
	$wpdb->query(
		$wpdb->prepare(
			"UPDATE {$otp_table} SET status = %s, code_hash = %s WHERE user_id = %d AND channel = %s AND status = %s",
			'superseded',
			'',
			$user_id,
			'email',
			'pending'
		)
	);
}

/**
 * Create a password-authenticated email change request.
 *
 * @return true|WP_Error
 */
function identity_security_kit_request_email_change( $user_id, $new_email, $current_password ) {
	$user_id  = absint( $user_id );
	$new_email = sanitize_email( $new_email );
	$user      = get_userdata( $user_id );
	if ( ! $user || ! is_email( $new_email ) ) {
		return new WP_Error( 'email_change_invalid', __( 'Enter a valid new email address.', 'identity-security-kit' ) );
	}
	if ( strtolower( $new_email ) === strtolower( $user->user_email ) ) {
		return new WP_Error( 'email_change_unchanged', __( 'The new email address is identical to the current address.', 'identity-security-kit' ) );
	}
	$owner = email_exists( $new_email );
	if ( $owner && (int) $owner !== $user_id ) {
		return new WP_Error( 'email_exists', __( 'This email address is already used.', 'identity-security-kit' ) );
	}
	if ( '' === (string) $current_password || ! wp_check_password( (string) $current_password, $user->user_pass, $user_id ) ) {
		return new WP_Error( 'current_password_invalid', __( 'The current password is incorrect.', 'identity-security-kit' ) );
	}
	if ( ! identity_security_kit_rate_limit_by_setting( 'email_change_request', 'email_resend_attempts_per_window' ) ) {
		return new WP_Error( 'email_change_rate_limited', __( 'Please wait before requesting another email change.', 'identity-security-kit' ) );
	}

	try {
		$token = identity_security_kit_base64url_encode( random_bytes( 32 ) );
	} catch ( Exception $exception ) {
		return new WP_Error( 'email_change_random_failed', __( 'The email change request could not be created.', 'identity-security-kit' ) );
	}
	$encrypted_email = identity_security_kit_encrypt_secret( $new_email );
	if ( is_wp_error( $encrypted_email ) ) {
		return $encrypted_email;
	}

	$settings = identity_security_kit_get_settings();
	$ttl      = max( 1, min( 168, absint( $settings['email_verification_ttl_hours'] ?? 24 ) ) ) * HOUR_IN_SECONDS;
	$pending  = array(
		'status'             => 'pending',
		'token_hash'         => hash( 'sha256', $token ),
		'email'              => $encrypted_email,
		'current_email_hash' => identity_security_kit_hash_email_challenge_value( $user->user_email ),
		'requested_at'       => time(),
		'expires_at'         => time() + $ttl,
	);
	if ( false === update_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key(), $pending ) ) {
		return new WP_Error( 'email_change_storage_failed', __( 'The email change request could not be saved.', 'identity-security-kit' ) );
	}

	$site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
	$subject   = sprintf( __( '[%s] Confirm your new email address', 'identity-security-kit' ), $site_name );
	$name       = $user->display_name ? $user->display_name : $user->user_login;
	$change_url = identity_security_kit_get_email_change_url( $user_id, $token );
	if ( ! identity_security_kit_send_transactional_email(
		$new_email,
		$subject,
		array(
			'preheader'    => __( 'Confirm this address before it is attached to your account.', 'identity-security-kit' ),
			'title'        => __( 'Confirm your new email address', 'identity-security-kit' ),
			'greeting'     => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $name ),
			'intro'        => __( 'Confirm this new email address for your account.', 'identity-security-kit' ),
			'details'      => array( sprintf( __( 'This secure link expires in %d hour(s).', 'identity-security-kit' ), (int) ( $ttl / HOUR_IN_SECONDS ) ) ),
			'action_url'   => $change_url,
			'action_label' => __( 'Confirm new email address', 'identity-security-kit' ),
			'notice'       => __( 'If you did not request this change, ignore this message.', 'identity-security-kit' ),
		)
	) ) {
		delete_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key(), $pending );
		identity_security_kit_log_event( 'email_change_delivery_failed', 'failure', $user_id );
		return new WP_Error( 'email_change_delivery_failed', __( 'The confirmation email could not be sent.', 'identity-security-kit' ) );
	}

	identity_security_kit_send_transactional_email(
		$user->user_email,
		sprintf( __( '[%s] Email change requested', 'identity-security-kit' ), $site_name ),
		array(
			'preheader' => __( 'A new email address is awaiting confirmation.', 'identity-security-kit' ),
			'title'     => __( 'Email change requested', 'identity-security-kit' ),
			'greeting'  => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $name ),
			'intro'     => __( 'A request was made to change the email address on your account. Your current address remains active until the new one is confirmed.', 'identity-security-kit' ),
			'notice'    => __( 'If you did not request this, change your password and contact the site administrator.', 'identity-security-kit' ),
		)
	);
	identity_security_kit_log_event( 'email_change_requested', 'info', $user_id, array( 'expires_hours' => (int) ( $ttl / HOUR_IN_SECONDS ) ) );

	return true;
}

/** Confirm and atomically apply a pending email change. */
function identity_security_kit_confirm_email_change( $user_id, $token ) {
	$user_id = absint( $user_id );
	$token   = preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $token );
	$meta_key = identity_security_kit_pending_email_change_meta_key();
	$pending  = get_user_meta( $user_id, $meta_key, true );
	if ( ! $user_id || strlen( $token ) < 40 || ! is_array( $pending ) || 'pending' !== ( $pending['status'] ?? '' ) ) {
		return new WP_Error( 'email_change_invalid', __( 'The email change request is invalid or expired.', 'identity-security-kit' ) );
	}
	if ( absint( $pending['expires_at'] ?? 0 ) < time() ) {
		delete_user_meta( $user_id, $meta_key, $pending );
		return new WP_Error( 'email_change_expired', __( 'The email change request has expired.', 'identity-security-kit' ) );
	}
	if ( empty( $pending['token_hash'] ) || ! hash_equals( $pending['token_hash'], hash( 'sha256', $token ) ) ) {
		return new WP_Error( 'email_change_invalid', __( 'The email change request is invalid or expired.', 'identity-security-kit' ) );
	}

	$user = get_userdata( $user_id );
	if ( ! $user || empty( $pending['current_email_hash'] ) || ! hash_equals( $pending['current_email_hash'], identity_security_kit_hash_email_challenge_value( $user->user_email ) ) ) {
		delete_user_meta( $user_id, $meta_key, $pending );
		return new WP_Error( 'email_change_account_changed', __( 'The account changed after this request. Start again.', 'identity-security-kit' ) );
	}
	$new_email = identity_security_kit_decrypt_secret( $pending['email'] ?? '' );
	if ( is_wp_error( $new_email ) || ! is_email( $new_email ) ) {
		delete_user_meta( $user_id, $meta_key, $pending );
		return new WP_Error( 'email_change_invalid', __( 'The email change request is invalid or expired.', 'identity-security-kit' ) );
	}
	$owner = email_exists( $new_email );
	if ( $owner && (int) $owner !== $user_id ) {
		return new WP_Error( 'email_exists', __( 'This email address is already used.', 'identity-security-kit' ) );
	}

	$processing           = $pending;
	$processing['status'] = 'processing';
	if ( false === update_user_meta( $user_id, $meta_key, $processing, $pending ) ) {
		return new WP_Error( 'email_change_replayed', __( 'The email change request was already used.', 'identity-security-kit' ) );
	}

	identity_security_kit_is_confirming_email_change( true );
	$result = wp_update_user( array( 'ID' => $user_id, 'user_email' => sanitize_email( $new_email ) ) );
	identity_security_kit_is_confirming_email_change( false );
	if ( is_wp_error( $result ) ) {
		update_user_meta( $user_id, $meta_key, $pending, $processing );
		return $result;
	}

	identity_security_kit_invalidate_email_bound_proofs( $user_id, false );
	update_user_meta( $user_id, identity_security_kit_email_verified_meta_key(), '1' );
	update_user_meta( $user_id, identity_security_kit_email_pending_meta_key(), '0' );
	delete_user_meta( $user_id, $meta_key, $processing );
	identity_security_kit_destroy_other_sessions( $user_id );
	identity_security_kit_log_event( 'email_change_confirmed', 'success', $user_id );

	return true;
}

/** Invalidate plugin proofs when another WordPress flow changes an email directly. */
function identity_security_kit_handle_direct_email_change( $user_id, $old_user_data ) {
	if ( identity_security_kit_is_confirming_email_change() || ! $old_user_data instanceof WP_User ) {
		return;
	}
	$user = get_userdata( absint( $user_id ) );
	if ( $user && strtolower( $old_user_data->user_email ) !== strtolower( $user->user_email ) ) {
		delete_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key() );
		identity_security_kit_invalidate_email_bound_proofs( $user_id, true );
		identity_security_kit_destroy_other_sessions( $user_id );
		identity_security_kit_log_event( 'email_changed_outside_confirmed_flow', 'warning', $user_id );
	}
}
add_action( 'profile_update', 'identity_security_kit_handle_direct_email_change', 20, 2 );

/** Process a public confirmation capability link. */
function identity_security_kit_handle_confirm_email_change() {
	$user_id = isset( $_GET['uid'] ) ? absint( $_GET['uid'] ) : 0;
	$token   = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';
	$result  = identity_security_kit_confirm_email_change( $user_id, $token );
	$status  = is_wp_error( $result ) ? sanitize_key( $result->get_error_code() ) : 'confirmed';
	$target  = is_user_logged_in() && get_current_user_id() === $user_id ? 'profile' : 'login';
	identity_security_kit_redirect( $target, array( 'email_change' => $status ) );
}
add_action( 'admin_post_nopriv_identity_security_kit_confirm_email_change', 'identity_security_kit_handle_confirm_email_change' );
add_action( 'admin_post_identity_security_kit_confirm_email_change', 'identity_security_kit_handle_confirm_email_change' );

/** Cancel the authenticated user's pending email change. */
function identity_security_kit_handle_cancel_email_change() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_cancel_email_change' );
	delete_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key() );
	identity_security_kit_log_event( 'email_change_cancelled', 'info', $user_id );
	identity_security_kit_redirect( 'profile', array( 'email_change' => 'cancelled' ) );
}
add_action( 'admin_post_identity_security_kit_cancel_email_change', 'identity_security_kit_handle_cancel_email_change' );
