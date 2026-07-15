<?php
/**
 * International phone number handling for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return the user meta key used for normalized phone numbers. */
function identity_security_kit_phone_meta_key() {
	return sanitize_key( apply_filters( 'identity_security_kit_phone_meta_key', 'identity_phone_e164' ) );
}

/**
 * Normalize an international E.164 phone number.
 *
 * Integrations can replace the fallback validator with a numbering-plan-aware
 * implementation through identity_security_kit_normalized_phone.
 */
function identity_security_kit_normalize_phone( $phone ) {
	$phone = trim( (string) $phone );
	if ( '' === $phone ) {
		return new WP_Error( 'phone_required', __( 'An international phone number is required.', 'identity-security-kit' ) );
	}

	$filtered = apply_filters( 'identity_security_kit_normalized_phone', null, $phone );
	if ( is_string( $filtered ) || is_wp_error( $filtered ) ) {
		return $filtered;
	}
	if ( 0 !== strpos( $phone, '+' ) ) {
		return new WP_Error( 'phone_country_code_required', __( 'Include the country prefix, for example +229.', 'identity-security-kit' ) );
	}

	if ( ! class_exists( '\\libphonenumber\\PhoneNumberUtil' ) ) {
		return new WP_Error( 'phone_validation_unavailable', __( 'Phone number validation is temporarily unavailable.', 'identity-security-kit' ) );
	}

	try {
		$phone_util = \libphonenumber\PhoneNumberUtil::getInstance();
		$parsed     = $phone_util->parse( $phone, null );
		if ( ! $phone_util->isValidNumber( $parsed ) ) {
			return new WP_Error( 'phone_invalid', __( 'Enter a valid international phone number.', 'identity-security-kit' ) );
		}

		return $phone_util->format( $parsed, \libphonenumber\PhoneNumberFormat::E164 );
	} catch ( \libphonenumber\NumberParseException $exception ) {
		return new WP_Error( 'phone_invalid', __( 'Enter a valid international phone number.', 'identity-security-kit' ) );
	}
}

/** Find a user by normalized phone without exposing phone login by default. */
function identity_security_kit_get_user_by_phone( $phone ) {
	$normalized = identity_security_kit_normalize_phone( $phone );
	if ( is_wp_error( $normalized ) ) {
		return $normalized;
	}
	$users = get_users(
		array(
			'number'      => 1,
			'count_total' => false,
			'meta_key'    => identity_security_kit_phone_meta_key(),
			'meta_value'  => $normalized,
		)
	);

	return ! empty( $users ) ? $users[0] : false;
}

/** Validate that a phone number is not assigned to another account. */
function identity_security_kit_validate_unique_phone( $phone, $exclude_user_id = 0 ) {
	$normalized = identity_security_kit_normalize_phone( $phone );
	if ( is_wp_error( $normalized ) ) {
		return $normalized;
	}
	$owner = identity_security_kit_get_user_by_phone( $normalized );
	if ( $owner instanceof WP_User && (int) $owner->ID !== absint( $exclude_user_id ) ) {
		return new WP_Error( 'phone_exists', __( 'This phone number is already assigned to an account.', 'identity-security-kit' ) );
	}

	return $normalized;
}

/** Store a validated phone and invalidate every proof tied to the old number. */
function identity_security_kit_set_user_phone( $user_id, $phone ) {
	$user_id    = absint( $user_id );
	$normalized = identity_security_kit_validate_unique_phone( $phone, $user_id );
	if ( is_wp_error( $normalized ) ) {
		return $normalized;
	}
	$meta_key = identity_security_kit_phone_meta_key();
	if ( hash_equals( (string) get_user_meta( $user_id, $meta_key, true ), $normalized ) ) {
		return true;
	}
	if ( false === update_user_meta( $user_id, $meta_key, $normalized ) ) {
		return new WP_Error( 'phone_save_failed', __( 'The phone number could not be saved.', 'identity-security-kit' ) );
	}

	delete_user_meta( $user_id, 'identity_phone_verified' );
	delete_user_meta( $user_id, 'identity_phone_verified_at' );
	delete_user_meta( $user_id, 'identity_phone_verified_hash' );
	delete_user_meta( $user_id, 'identity_mfa_sms_enabled' );
	delete_user_meta( $user_id, 'identity_mfa_preferred_method', 'sms' );
	identity_security_kit_log_event( 'phone_changed', 'warning', $user_id );

	return true;
}
