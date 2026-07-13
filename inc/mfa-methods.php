<?php
/**
 * MFA method enrollment, discovery and preferences.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return MFA methods allowed by policy. */
function identity_security_kit_get_allowed_mfa_methods( $user_id ) {
	$settings = identity_security_kit_get_settings();
	$methods  = is_array( $settings['mfa_allowed_methods'] ?? null ) ? $settings['mfa_allowed_methods'] : array( 'totp', 'email', 'sms' );
	$methods  = array_values( array_intersect( array( 'totp', 'email', 'sms' ), array_map( 'sanitize_key', $methods ) ) );

	return array_values( array_unique( apply_filters( 'identity_security_kit_allowed_mfa_methods', $methods, absint( $user_id ) ) ) );
}

/** Return whether one method is explicitly enrolled and still usable. */
function identity_security_kit_is_mfa_method_enabled( $user_id, $method ) {
	$user_id = absint( $user_id );
	$method  = sanitize_key( $method );
	$user    = get_userdata( $user_id );
	if ( ! $user || ! in_array( $method, identity_security_kit_get_allowed_mfa_methods( $user_id ), true ) ) {
		return false;
	}
	if ( 'totp' === $method ) {
		return identity_security_kit_is_totp_enabled( $user_id );
	}
	if ( 'email' === $method ) {
		return '1' === (string) get_user_meta( $user_id, 'identity_mfa_email_enabled', true )
			&& function_exists( 'identity_security_kit_is_email_verified' )
			&& identity_security_kit_is_email_verified( $user_id );
	}
	if ( 'sms' === $method ) {
		return '1' === (string) get_user_meta( $user_id, 'identity_mfa_sms_enabled', true )
			&& identity_security_kit_is_phone_verified( $user_id );
	}

	return false;
}

/** Return methods currently usable for a user. */
function identity_security_kit_get_user_mfa_methods( $user_id ) {
	$methods = array();
	foreach ( identity_security_kit_get_allowed_mfa_methods( $user_id ) as $method ) {
		if ( identity_security_kit_is_mfa_method_enabled( $user_id, $method ) ) {
			$methods[] = $method;
		}
	}

	return array_values( array_unique( apply_filters( 'identity_security_kit_user_mfa_methods', $methods, absint( $user_id ) ) ) );
}

/** Return whether the user has at least one usable MFA method. */
function identity_security_kit_user_has_mfa_method( $user_id ) {
	return array() !== identity_security_kit_get_user_mfa_methods( $user_id );
}

/** Return a preferred available method, favoring TOTP by default. */
function identity_security_kit_get_preferred_mfa_method( $user_id ) {
	$methods   = identity_security_kit_get_user_mfa_methods( $user_id );
	$preferred = sanitize_key( get_user_meta( absint( $user_id ), 'identity_mfa_preferred_method', true ) );
	if ( in_array( $preferred, $methods, true ) ) {
		return $preferred;
	}
	foreach ( array( 'totp', 'email', 'sms' ) as $method ) {
		if ( in_array( $method, $methods, true ) ) {
			return $method;
		}
	}

	return '';
}

/** Return a translated factor label. */
function identity_security_kit_get_mfa_method_label( $method ) {
	$labels = array(
		'totp'     => __( 'Authenticator application', 'identity-security-kit' ),
		'email'    => __( 'Email security code', 'identity-security-kit' ),
		'sms'      => __( 'SMS security code', 'identity-security-kit' ),
		'recovery' => __( 'Recovery code', 'identity-security-kit' ),
	);

	return $labels[ $method ] ?? __( 'Security code', 'identity-security-kit' );
}

/** Mask the destination used by a remote MFA method. */
function identity_security_kit_get_masked_mfa_destination( $user_id, $method ) {
	$user = get_userdata( absint( $user_id ) );
	if ( ! $user ) {
		return '';
	}
	if ( 'sms' === $method ) {
		return identity_security_kit_mask_phone( get_user_meta( $user->ID, identity_security_kit_phone_meta_key(), true ) );
	}
	if ( 'email' === $method ) {
		$parts = explode( '@', $user->user_email, 2 );
		if ( 2 === count( $parts ) ) {
			return substr( $parts[0], 0, 1 ) . str_repeat( '*', max( 3, strlen( $parts[0] ) - 1 ) ) . '@' . $parts[1];
		}

	}
	return '';
}

/** Start email or SMS factor enrollment after password re-authentication. */
function identity_security_kit_handle_channel_mfa_start() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_channel_mfa_start' );
	$method   = isset( $_POST['mfa_method'] ) ? sanitize_key( wp_unslash( $_POST['mfa_method'] ) ) : '';
	$password = isset( $_POST['current_password'] ) ? (string) wp_unslash( $_POST['current_password'] ) : '';
	$user     = get_userdata( $user_id );
	if ( ! in_array( $method, array( 'email', 'sms' ), true ) || ! $user || ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'password_invalid' ) );
	}
	if ( ! in_array( $method, identity_security_kit_get_allowed_mfa_methods( $user_id ), true ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'method_not_allowed' ) );
	}
	if ( 'email' === $method && ( ! function_exists( 'identity_security_kit_is_email_verified' ) || ! identity_security_kit_is_email_verified( $user_id ) ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'email_not_verified' ) );
	}
	if ( 'sms' === $method && ! identity_security_kit_is_phone_verified( $user_id ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'phone_not_verified' ) );
	}

	$purpose = 'mfa_enrollment_' . $method;
	$result  = 'email' === $method
		? identity_security_kit_create_email_otp_challenge( $user_id, $purpose )
		: identity_security_kit_create_phone_otp_challenge( $user_id, $purpose );
	identity_security_kit_mfa_redirect(
		array(
			'mfa'                  => is_wp_error( $result ) ? sanitize_key( $result->get_error_code() ) : 'channel_code_sent',
			'mfa_enroll_method'    => $method,
			'mfa_enroll_challenge' => is_wp_error( $result ) ? 0 : absint( $result ),
		)
	);
}
add_action( 'admin_post_identity_security_kit_channel_mfa_start', 'identity_security_kit_handle_channel_mfa_start' );

/** Confirm email or SMS factor enrollment. */
function identity_security_kit_handle_channel_mfa_confirm() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_channel_mfa_confirm' );
	$method       = isset( $_POST['mfa_method'] ) ? sanitize_key( wp_unslash( $_POST['mfa_method'] ) ) : '';
	$challenge_id = isset( $_POST['challenge_id'] ) ? absint( $_POST['challenge_id'] ) : 0;
	$code         = isset( $_POST['otp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['otp_code'] ) ) : '';
	$purpose      = 'mfa_enrollment_' . $method;
	if ( 'email' === $method ) {
		$result = identity_security_kit_verify_email_otp_challenge( $challenge_id, $user_id, $code, $purpose );
	} elseif ( 'sms' === $method ) {
		$result = identity_security_kit_verify_phone_otp_challenge( $challenge_id, $user_id, $code, $purpose );
	} else {
		$result = new WP_Error( 'method_not_allowed', __( 'This verification method is not available.', 'identity-security-kit' ) );
	}
	if ( is_wp_error( $result ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => sanitize_key( $result->get_error_code() ), 'mfa_enroll_method' => $method, 'mfa_enroll_challenge' => $challenge_id ) );
	}

	update_user_meta( $user_id, 'identity_mfa_' . $method . '_enabled', '1' );
	update_user_meta( $user_id, 'identity_mfa_enabled_at', gmdate( 'Y-m-d H:i:s' ) );
	delete_user_meta( $user_id, 'identity_mfa_grace_started_at' );
	if ( '' === (string) get_user_meta( $user_id, 'identity_mfa_preferred_method', true ) ) {
		update_user_meta( $user_id, 'identity_mfa_preferred_method', $method );
	}
	$recovery = get_user_meta( $user_id, 'identity_mfa_recovery_codes', true );
	$token    = '';
	if ( ! is_array( $recovery ) || empty( $recovery ) ) {
		$codes = identity_security_kit_generate_recovery_codes( $user_id );
		$token = is_wp_error( $codes ) ? '' : identity_security_kit_store_recovery_display( $user_id, $codes );
		$token = is_wp_error( $token ) ? '' : $token;
	}
	identity_security_kit_destroy_other_sessions( $user_id );
	identity_security_kit_send_security_notification( $user_id, sprintf( __( '%s was enabled as a two-factor authentication method.', 'identity-security-kit' ), identity_security_kit_get_mfa_method_label( $method ) ) );
	identity_security_kit_log_event( 'mfa_factor_enabled', 'success', $user_id, array( 'method' => $method ) );
	do_action( 'identity_security_kit_mfa_enabled', $user_id, $method );
	identity_security_kit_mfa_redirect( array( 'mfa' => 'enabled', 'recovery' => $token ) );
}
add_action( 'admin_post_identity_security_kit_channel_mfa_confirm', 'identity_security_kit_handle_channel_mfa_confirm' );

/** Save the preferred factor after password re-authentication. */
function identity_security_kit_handle_mfa_preference() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_mfa_preference' );
	$method   = isset( $_POST['mfa_method'] ) ? sanitize_key( wp_unslash( $_POST['mfa_method'] ) ) : '';
	$password = isset( $_POST['current_password'] ) ? (string) wp_unslash( $_POST['current_password'] ) : '';
	$user     = get_userdata( $user_id );
	if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'password_invalid' ) );
	}
	if ( ! in_array( $method, identity_security_kit_get_user_mfa_methods( $user_id ), true ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'method_not_allowed' ) );
	}
	update_user_meta( $user_id, 'identity_mfa_preferred_method', $method );
	identity_security_kit_log_event( 'mfa_preference_changed', 'success', $user_id, array( 'method' => $method ) );
	identity_security_kit_mfa_redirect( array( 'mfa' => 'preference_saved' ) );
}
add_action( 'admin_post_identity_security_kit_mfa_preference', 'identity_security_kit_handle_mfa_preference' );
