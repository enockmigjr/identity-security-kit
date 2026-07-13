<?php
/**
 * WordPress runtime verification for Identity Security Kit.
 *
 * Run with: wp eval-file tests/runtime-identity.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

function identity_runtime_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

function identity_runtime_error_code( $value ) {
	return is_wp_error( $value ) ? $value->get_error_code() : '';
}

global $wpdb;

$email_messages = array();
$sms_messages   = array();
$user_ids       = array();
$old_settings   = get_option( 'identity_security_kit_settings', array() );
$email_table    = identity_security_kit_get_email_verification_table();
$otp_table      = identity_security_kit_get_otp_table();
$audit_table    = identity_security_kit_get_audit_table();
$primary_email  = 'identity-runtime@photovault.test';
$primary_phone  = '+22997000034';

add_filter(
	'wp_mail',
	static function ( $attributes ) use ( &$email_messages ) {
		$email_messages[] = $attributes;

		return $attributes;
	},
	10
);
add_filter(
	'identity_security_kit_sms_provider',
	static function () {
		return 'runtime_test';
	}
);
add_filter(
	'identity_security_kit_sms_provider_available',
	static function () {
		return true;
	},
	10,
	2
);
add_filter(
	'identity_security_kit_sms_delivery',
	static function ( $result, $phone, $message, $context, $provider ) use ( &$sms_messages ) {
		$sms_messages[] = compact( 'phone', 'message', 'context', 'provider' );

		return true;
	},
	10,
	5
);

try {
	foreach ( array( $primary_email, 'identity-runtime-changed@photovault.test', 'identity-runtime-duplicate@photovault.test', 'identity-runtime-grace@photovault.test' ) as $email ) {
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

	$settings                              = identity_security_kit_get_default_settings();
	$settings['phone_required']            = 1;
	$settings['mfa_grace_days']            = 15;
	$settings['mfa_enforcement_enabled']   = 1;
	$settings['mfa_required_capabilities'] = array( 'edit_posts' );
	update_option( 'identity_security_kit_settings', $settings, false );

	$user_id = wp_insert_user(
		array(
			'user_login' => 'identity_runtime_' . wp_generate_password( 6, false, false ),
			'user_email' => $primary_email,
			'user_pass'  => wp_generate_password( 24, true, true ),
			'role'       => 'author',
		)
	);
	identity_runtime_assert( ! is_wp_error( $user_id ), 'Runtime user creation failed.' );
	$user_ids[] = (int) $user_id;
	identity_runtime_assert( identity_security_kit_user_requires_mfa( $user_id ), 'The privileged test role is not subject to MFA policy.' );
	$deadline = identity_security_kit_get_mfa_deadline( $user_id );
	identity_runtime_assert( $deadline >= time() + ( 14 * DAY_IN_SECONDS ) && $deadline <= time() + ( 16 * DAY_IN_SECONDS ), 'The configured 15-day grace deadline is invalid.' );

	$email_messages = array();
	$result         = identity_security_kit_create_email_verification_challenge( $user_id, 'other-address@photovault.test' );
	identity_runtime_assert( 'email_challenge_mismatch' === identity_runtime_error_code( $result ), 'A challenge was created for an email not owned by the account.' );
	$result = identity_security_kit_create_email_verification_challenge( $user_id, $primary_email );
	identity_runtime_assert( true === $result && 1 === count( $email_messages ), 'Email verification challenge was not delivered.' );
	preg_match( '/[?&]token=([A-Za-z0-9]+)/', $email_messages[0]['message'], $matches );
	$old_token = $matches[1] ?? '';
	identity_runtime_assert( '' !== $old_token, 'The verification token was not present in the captured message.' );

	wp_update_user( array( 'ID' => $user_id, 'user_email' => 'identity-runtime-changed@photovault.test' ) );
	$result = identity_security_kit_verify_email_challenge( $user_id, $old_token );
	identity_runtime_assert( 'email_challenge_email_changed' === identity_runtime_error_code( $result ), 'An old link verified a changed email address.' );
	wp_update_user( array( 'ID' => $user_id, 'user_email' => $primary_email ) );

	$email_messages = array();
	$result         = identity_security_kit_create_email_verification_challenge( $user_id, $primary_email );
	identity_runtime_assert( true === $result, 'Replacement email verification challenge failed.' );
	preg_match( '/[?&]token=([A-Za-z0-9]+)/', $email_messages[0]['message'], $matches );
	$token  = $matches[1] ?? '';
	$result = identity_security_kit_verify_email_challenge( $user_id, $token );
	identity_runtime_assert( true === $result && identity_security_kit_is_email_verified( $user_id ), 'The current email could not be verified.' );
	identity_runtime_assert( 'email_challenge_invalid' === identity_runtime_error_code( identity_security_kit_verify_email_challenge( $user_id, $token ) ), 'Email verification token replay was accepted.' );

	$result = identity_security_kit_set_user_phone( $user_id, '+229 97 00 00 34' );
	identity_runtime_assert( true === $result && $primary_phone === get_user_meta( $user_id, identity_security_kit_phone_meta_key(), true ), 'E.164 phone normalization or storage failed.' );
	$duplicate_id = wp_insert_user(
		array(
			'user_login' => 'identity_duplicate_' . wp_generate_password( 6, false, false ),
			'user_email' => 'identity-runtime-duplicate@photovault.test',
			'user_pass'  => wp_generate_password( 24, true, true ),
			'role'       => 'subscriber',
		)
	);
	identity_runtime_assert( ! is_wp_error( $duplicate_id ), 'Duplicate test user creation failed.' );
	$user_ids[] = (int) $duplicate_id;
	identity_runtime_assert( 'phone_exists' === identity_runtime_error_code( identity_security_kit_set_user_phone( $duplicate_id, $primary_phone ) ), 'Duplicate phone ownership was accepted.' );

	$email_messages = array();
	$email_challenge = identity_security_kit_create_email_otp_challenge( $user_id, 'runtime_email' );
	identity_runtime_assert( ! is_wp_error( $email_challenge ), 'Email OTP creation failed.' );
	preg_match( '/code is: ([0-9]{6,8})/', $email_messages[0]['message'], $matches );
	$email_code = $matches[1] ?? '';
	identity_runtime_assert( 'otp_invalid' === identity_runtime_error_code( identity_security_kit_verify_email_otp_challenge( $email_challenge, $user_id, $email_code, 'wrong_purpose' ) ), 'OTP purpose isolation failed.' );
	identity_runtime_assert( 'otp_incorrect' === identity_runtime_error_code( identity_security_kit_verify_email_otp_challenge( $email_challenge, $user_id, '000000', 'runtime_email' ) ), 'Incorrect OTP was not rejected.' );
	identity_runtime_assert( true === identity_security_kit_verify_email_otp_challenge( $email_challenge, $user_id, $email_code, 'runtime_email' ), 'Correct email OTP was not consumed.' );
	identity_runtime_assert( 'otp_invalid' === identity_runtime_error_code( identity_security_kit_verify_email_otp_challenge( $email_challenge, $user_id, $email_code, 'runtime_email' ) ), 'Consumed email OTP was replayed.' );

	$email_messages  = array();
	$expired_id      = identity_security_kit_create_email_otp_challenge( $user_id, 'runtime_expired' );
	preg_match( '/code is: ([0-9]{6,8})/', $email_messages[0]['message'], $matches );
	$wpdb->update( $otp_table, array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ) ), array( 'id' => $expired_id ), array( '%s' ), array( '%d' ) );
	identity_runtime_assert( 'otp_expired' === identity_runtime_error_code( identity_security_kit_verify_email_otp_challenge( $expired_id, $user_id, $matches[1] ?? '', 'runtime_expired' ) ), 'Expired OTP was accepted.' );

	$email_messages = array();
	$locked_id      = identity_security_kit_create_email_otp_challenge( $user_id, 'runtime_locked' );
	$policy         = identity_security_kit_get_otp_policy( 'email' );
	for ( $attempt = 0; $attempt < $policy['max_attempts']; $attempt++ ) {
		identity_security_kit_verify_email_otp_challenge( $locked_id, $user_id, '000000', 'runtime_locked' );
	}
	identity_runtime_assert( 'locked' === $wpdb->get_var( $wpdb->prepare( "SELECT status FROM {$otp_table} WHERE id = %d", $locked_id ) ), 'OTP attempt limit did not lock the challenge.' );

	$sms_messages    = array();
	$phone_challenge = identity_security_kit_create_phone_otp_challenge( $user_id, 'verify_phone' );
	identity_runtime_assert( ! is_wp_error( $phone_challenge ) && 1 === count( $sms_messages ), 'SMS OTP creation or provider adapter failed.' );
	preg_match( '/code: ([0-9]{6,8})/', $sms_messages[0]['message'], $matches );
	$sms_code = $matches[1] ?? '';
	identity_runtime_assert( true === identity_security_kit_verify_phone_otp_challenge( $phone_challenge, $user_id, $sms_code, 'verify_phone' ), 'Phone OTP verification failed.' );
	identity_runtime_assert( identity_security_kit_is_phone_verified( $user_id ), 'Verified phone proof was not bound to the canonical number.' );

	$email_messages  = array();
	$enrollment_id   = identity_security_kit_create_email_otp_challenge( $user_id, 'mfa_enrollment_email' );
	preg_match( '/code is: ([0-9]{6,8})/', $email_messages[0]['message'], $matches );
	$enabled = identity_security_kit_enable_channel_mfa( $user_id, 'email', $enrollment_id, $matches[1] ?? '' );
	identity_runtime_assert( ! is_wp_error( $enabled ) && identity_security_kit_is_mfa_method_enabled( $user_id, 'email' ), 'Email MFA enrollment failed.' );

	$sms_messages     = array();
	$sms_enrollment   = identity_security_kit_create_phone_otp_challenge( $user_id, 'mfa_enrollment_sms' );
	preg_match( '/code: ([0-9]{6,8})/', $sms_messages[0]['message'], $matches );
	$enabled = identity_security_kit_enable_channel_mfa( $user_id, 'sms', $sms_enrollment, $matches[1] ?? '' );
	identity_runtime_assert( ! is_wp_error( $enabled ) && identity_security_kit_is_mfa_method_enabled( $user_id, 'sms' ), 'SMS MFA enrollment failed.' );

	$secret = identity_security_kit_begin_totp_enrollment( $user_id );
	identity_runtime_assert( ! is_wp_error( $secret ), 'TOTP enrollment could not start.' );
	$totp_code = identity_security_kit_totp_at( $secret, time(), 6, 30 );
	$recovery  = identity_security_kit_confirm_totp_enrollment( $user_id, $totp_code );
	identity_runtime_assert( is_array( $recovery ) && count( $recovery ) >= 5 && identity_security_kit_is_totp_enabled( $user_id ), 'TOTP enrollment or recovery generation failed.' );
	identity_runtime_assert( 'totp_replayed' === identity_runtime_error_code( identity_security_kit_verify_totp_for_user( $user_id, $totp_code ) ), 'TOTP replay was accepted.' );
	$recovery_code = $recovery[0];
	identity_runtime_assert( true === identity_security_kit_verify_recovery_code( $user_id, $recovery_code ), 'Recovery code could not be consumed.' );
	identity_runtime_assert( 'recovery_code_invalid' === identity_runtime_error_code( identity_security_kit_verify_recovery_code( $user_id, $recovery_code ) ), 'Recovery code replay was accepted.' );

	update_user_meta( $user_id, 'identity_mfa_preferred_method', 'email' );
	$email_messages = array();
	$login_url      = identity_security_kit_create_login_challenge( $user_id, false, home_url( '/runtime-target/' ) );
	parse_str( (string) wp_parse_url( $login_url, PHP_URL_QUERY ), $login_query );
	$login_token = $login_query['token'] ?? '';
	$prepared    = identity_security_kit_prepare_login_method( $login_token, 'email' );
	preg_match( '/code is: ([0-9]{6,8})/', end( $email_messages )['message'], $matches );
	$consumed = identity_security_kit_consume_login_challenge( $login_token, $matches[1] ?? '', 'email' );
	identity_runtime_assert( ! is_wp_error( $prepared ) && ! is_wp_error( $consumed ), 'Email MFA login challenge failed.' );
	identity_runtime_assert( 'mfa_challenge_invalid' === identity_runtime_error_code( identity_security_kit_consume_login_challenge( $login_token, $matches[1] ?? '', 'email' ) ), 'MFA browser challenge replay was accepted.' );

	update_user_meta( $user_id, 'identity_mfa_preferred_method', 'sms' );
	$sms_messages = array();
	$login_url    = identity_security_kit_create_login_challenge( $user_id, false, home_url( '/runtime-target/' ) );
	parse_str( (string) wp_parse_url( $login_url, PHP_URL_QUERY ), $login_query );
	$login_token = $login_query['token'] ?? '';
	$prepared    = identity_security_kit_prepare_login_method( $login_token, 'sms' );
	preg_match( '/code: ([0-9]{6,8})/', end( $sms_messages )['message'], $matches );
	$consumed = identity_security_kit_consume_login_challenge( $login_token, $matches[1] ?? '', 'sms' );
	identity_runtime_assert( ! is_wp_error( $prepared ) && ! is_wp_error( $consumed ), 'SMS MFA login challenge failed.' );

	update_user_meta( $user_id, 'identity_mfa_preferred_method', 'totp' );
	$login_url = identity_security_kit_create_login_challenge( $user_id, false, home_url( '/runtime-target/' ) );
	parse_str( (string) wp_parse_url( $login_url, PHP_URL_QUERY ), $login_query );
	$login_token = $login_query['token'] ?? '';
	$future_code = identity_security_kit_totp_at( $secret, time() + 30, 6, 30 );
	$consumed    = identity_security_kit_consume_login_challenge( $login_token, $future_code, 'totp' );
	identity_runtime_assert( ! is_wp_error( $consumed ), 'TOTP MFA login challenge failed.' );

	$grace_id = wp_insert_user(
		array(
			'user_login' => 'identity_grace_' . wp_generate_password( 6, false, false ),
			'user_email' => 'identity-runtime-grace@photovault.test',
			'user_pass'  => wp_generate_password( 24, true, true ),
			'role'       => 'author',
		)
	);
	identity_runtime_assert( ! is_wp_error( $grace_id ), 'Grace-period test user creation failed.' );
	$user_ids[] = (int) $grace_id;
	update_user_meta( $grace_id, 'identity_mfa_grace_started_at', time() - ( 16 * DAY_IN_SECONDS ) );
	identity_runtime_assert( identity_security_kit_is_mfa_grace_expired( $grace_id ), 'MFA access was not considered expired after day 15.' );
	identity_runtime_assert( ! identity_security_kit_is_mfa_grace_expired( $user_id ), 'An enrolled account was incorrectly considered beyond grace.' );

	echo wp_json_encode(
		array(
			'email_verification' => 'verified_bound_and_single_use',
			'phone'              => 'e164_unique_and_verified',
			'otp_email'          => 'purpose_expiry_attempts_replay_validated',
			'otp_sms'            => 'provider_and_verification_validated',
			'mfa_methods'        => identity_security_kit_get_user_mfa_methods( $user_id ),
			'mfa_login'          => array( 'email', 'sms', 'totp', 'recovery' ),
			'mfa_grace_days'     => 15,
		)
	);
} finally {
	update_option( 'identity_security_kit_settings', $old_settings, false );
	require_once ABSPATH . 'wp-admin/includes/user.php';
	foreach ( array_unique( array_filter( array_map( 'absint', $user_ids ) ) ) as $cleanup_user_id ) {
		$challenge_hash = (string) get_user_meta( $cleanup_user_id, 'identity_mfa_login_challenge', true );
		if ( preg_match( '/^[a-f0-9]{64}$/', $challenge_hash ) ) {
			delete_transient( 'isk_login_' . $challenge_hash );
		}
		$wpdb->delete( $email_table, array( 'user_id' => $cleanup_user_id ), array( '%d' ) );
		$wpdb->delete( $otp_table, array( 'user_id' => $cleanup_user_id ), array( '%d' ) );
		$wpdb->delete( $audit_table, array( 'user_id' => $cleanup_user_id ), array( '%d' ) );
		wp_delete_user( $cleanup_user_id );
	}
}
