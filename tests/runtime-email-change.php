<?php
/**
 * WordPress runtime verification for confirmed email changes.
 *
 * Run with: wp eval-file tests/runtime-email-change.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

function identity_email_change_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

function identity_email_change_code( $value ) {
	return is_wp_error( $value ) ? $value->get_error_code() : '';
}

global $wpdb;

$messages        = array();
$user_ids        = array();
$old_email       = 'identity-email-old@photovault.test';
$new_email       = 'identity-email-new@photovault.test';
$direct_email    = 'identity-email-direct@photovault.test';
$duplicate_email = 'identity-email-used@photovault.test';
$password        = 'Runtime-email-change-42!';
$email_table     = identity_security_kit_get_email_verification_table();
$otp_table       = identity_security_kit_get_otp_table();
$audit_table     = identity_security_kit_get_audit_table();
$rate_limit_key  = 'isk_rl_' . md5( 'email_change_request|' . identity_security_kit_get_rate_limit_fingerprint() );

add_filter(
	'wp_mail',
	static function ( $attributes ) use ( &$messages ) {
		$messages[] = $attributes;

		return $attributes;
	}
);

try {
	delete_transient( $rate_limit_key );
	foreach ( array( $old_email, $new_email, $direct_email, $duplicate_email ) as $email ) {
		$existing = get_user_by( 'email', $email );
		if ( $existing ) {
			$user_ids[] = (int) $existing->ID;
		}
	}
	if ( ! empty( $user_ids ) ) {
		require_once ABSPATH . 'wp-admin/includes/user.php';
		foreach ( array_unique( $user_ids ) as $old_user_id ) {
			wp_delete_user( $old_user_id );
		}
		$user_ids = array();
	}

	$user_id = wp_insert_user(
		array(
			'user_login' => 'identity_email_' . wp_generate_password( 6, false, false ),
			'user_email' => $old_email,
			'user_pass'  => $password,
			'role'       => 'subscriber',
		)
	);
	identity_email_change_assert( ! is_wp_error( $user_id ), 'Email-change user creation failed.' );
	$user_ids[] = (int) $user_id;
	$duplicate_id = wp_insert_user(
		array(
			'user_login' => 'identity_used_' . wp_generate_password( 6, false, false ),
			'user_email' => $duplicate_email,
			'user_pass'  => wp_generate_password( 24, true, true ),
			'role'       => 'subscriber',
		)
	);
	identity_email_change_assert( ! is_wp_error( $duplicate_id ), 'Duplicate-address user creation failed.' );
	$user_ids[] = (int) $duplicate_id;

	update_user_meta( $user_id, identity_security_kit_email_verified_meta_key(), '1' );
	update_user_meta( $user_id, identity_security_kit_email_pending_meta_key(), '0' );
	update_user_meta( $user_id, 'identity_mfa_email_enabled', '1' );
	update_user_meta( $user_id, 'identity_mfa_preferred_method', 'email' );

	$result = identity_security_kit_request_email_change( $user_id, $new_email, 'wrong-password' );
	identity_email_change_assert( 'current_password_invalid' === identity_email_change_code( $result ), 'Wrong password was accepted for an email change.' );
	identity_email_change_assert( '' === (string) get_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key(), true ), 'A rejected request left pending state.' );
	$result = identity_security_kit_request_email_change( $user_id, $duplicate_email, $password );
	identity_email_change_assert( 'email_exists' === identity_email_change_code( $result ), 'An email owned by another account was accepted.' );

	$messages = array();
	$result   = identity_security_kit_request_email_change( $user_id, $new_email, $password );
	identity_email_change_assert( true === $result, 'Valid email change request failed.' );
	identity_email_change_assert( $old_email === get_userdata( $user_id )->user_email, 'The account email changed before confirmation.' );
	$pending = get_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key(), true );
	identity_email_change_assert( is_array( $pending ) && false === strpos( maybe_serialize( $pending ), $new_email ), 'The pending email was stored in plaintext.' );
	$confirmation = null;
	foreach ( $messages as $message ) {
		if ( $new_email === $message['to'] && false !== strpos( $message['subject'], 'Confirm your new email address' ) ) {
			$confirmation = $message;
			break;
		}
	}
	identity_email_change_assert( is_array( $confirmation ), 'Confirmation was not sent to the new email.' );
	preg_match( '/[?&]token=([A-Za-z0-9_-]+)/', $confirmation['message'], $matches );
	$token = $matches[1] ?? '';
	identity_email_change_assert( strlen( $token ) >= 40, 'Confirmation capability token is missing.' );
	identity_email_change_assert( 'email_change_invalid' === identity_email_change_code( identity_security_kit_confirm_email_change( $user_id, str_repeat( 'a', 43 ) ) ), 'An incorrect token was accepted.' );

	$expired               = $pending;
	$expired['expires_at'] = time() - 60;
	update_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key(), $expired, $pending );
	identity_email_change_assert( 'email_change_expired' === identity_email_change_code( identity_security_kit_confirm_email_change( $user_id, $token ) ), 'An expired request was accepted.' );
	identity_email_change_assert( $old_email === get_userdata( $user_id )->user_email, 'Expired request changed the account email.' );

	$messages = array();
	identity_email_change_assert( true === identity_security_kit_request_email_change( $user_id, $new_email, $password ), 'Replacement email change request failed.' );
	foreach ( $messages as $message ) {
		if ( $new_email === $message['to'] && false !== strpos( $message['subject'], 'Confirm your new email address' ) ) {
			$confirmation = $message;
			break;
		}
	}
	preg_match( '/[?&]token=([A-Za-z0-9_-]+)/', $confirmation['message'], $matches );
	$token = $matches[1] ?? '';

	$messages     = array();
	$otp_id       = identity_security_kit_create_email_otp_challenge( $user_id, 'runtime_old_email' );
	$old_otp_code = '';
	foreach ( $messages as $message ) {
		if ( false !== strpos( $message['subject'], 'Your security code' ) ) {
			preg_match( '/code is: ([0-9]{6,8})/', $message['message'], $matches );
			$old_otp_code = $matches[1] ?? '';
		}
	}
	identity_email_change_assert( ! is_wp_error( $otp_id ) && '' !== $old_otp_code, 'Old-address OTP setup failed.' );

	$result = identity_security_kit_confirm_email_change( $user_id, $token );
	identity_email_change_assert( true === $result, 'Valid email change confirmation failed.' );
	$user = get_userdata( $user_id );
	identity_email_change_assert( $new_email === $user->user_email, 'Confirmed email was not applied.' );
	identity_email_change_assert( identity_security_kit_is_email_verified( $user_id ), 'Confirmed new email was not marked verified.' );
	identity_email_change_assert( '' === (string) get_user_meta( $user_id, 'identity_mfa_email_enabled', true ), 'Old email MFA factor remained enabled.' );
	identity_email_change_assert( '' === (string) get_user_meta( $user_id, 'identity_mfa_preferred_method', true ), 'Old email remained the preferred MFA factor.' );
	identity_email_change_assert( '' === (string) get_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key(), true ), 'Confirmed pending state was not deleted.' );
	identity_email_change_assert( 'superseded' === $wpdb->get_var( $wpdb->prepare( "SELECT status FROM {$otp_table} WHERE id = %d", $otp_id ) ), 'Pending OTP for the old email was not revoked.' );
	identity_email_change_assert( 'email_change_invalid' === identity_email_change_code( identity_security_kit_confirm_email_change( $user_id, $token ) ), 'Confirmed token replay was accepted.' );

	update_user_meta( $user_id, 'identity_mfa_email_enabled', '1' );
	update_user_meta( $user_id, identity_security_kit_email_verified_meta_key(), '1' );
	wp_update_user( array( 'ID' => $user_id, 'user_email' => $direct_email ) );
	identity_email_change_assert( ! identity_security_kit_is_email_verified( $user_id ), 'A direct external email change remained verified.' );
	identity_email_change_assert( '' === (string) get_user_meta( $user_id, 'identity_mfa_email_enabled', true ), 'A direct external change kept the old email factor.' );

	echo wp_json_encode(
		array(
			'password_reauthentication' => 'required',
			'pending_storage'           => 'encrypted',
			'email_before_confirmation' => 'unchanged',
			'confirmation'              => 'single_use_and_expiring',
			'old_email_proofs'          => 'revoked',
			'direct_change'             => 'marked_unverified',
		)
	);
} finally {
	delete_transient( $rate_limit_key );
	require_once ABSPATH . 'wp-admin/includes/user.php';
	foreach ( array_unique( array_filter( array_map( 'absint', $user_ids ) ) ) as $cleanup_user_id ) {
		$wpdb->delete( $email_table, array( 'user_id' => $cleanup_user_id ), array( '%d' ) );
		$wpdb->delete( $otp_table, array( 'user_id' => $cleanup_user_id ), array( '%d' ) );
		$wpdb->delete( $audit_table, array( 'user_id' => $cleanup_user_id ), array( '%d' ) );
		wp_delete_user( $cleanup_user_id );
	}
}
