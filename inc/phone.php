<?php
/**
 * International phone number handling for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Return the user meta key used for normalized phone numbers.
 *
 * @return string
 */
function identity_security_kit_phone_meta_key() {
	return sanitize_key( apply_filters( 'identity_security_kit_phone_meta_key', 'identity_phone_e164' ) );
}

/**
 * Normalize and validate an international E.164 phone number.
 *
 * Formatting characters are accepted, but a leading country prefix is mandatory.
 *
 * @param string $phone Raw phone number.
 * @return string|WP_Error
 */
function identity_security_kit_normalize_phone( $phone ) {
	$phone = trim( (string) $phone );
	if ( '' === $phone ) {
		return new WP_Error( 'phone_required', __( 'An international phone number is required.', 'identity-security-kit' ) );
	}

	if ( 0 !== strpos( $phone, '+' ) ) {
		return new WP_Error( 'phone_country_code_required', __( 'Include the country prefix, for example +229.', 'identity-security-kit' ) );
	}

	$digits = preg_replace( '/[^0-9]/', '', substr( $phone, 1 ) );
	if ( ! is_string( $digits ) || ! preg_match( '/^[1-9][0-9]{7,14}$/', $digits ) ) {
		return new WP_Error( 'phone_invalid', __( 'Enter a valid international phone number.', 'identity-security-kit' ) );
	}

	return '+' . $digits;
}

/**
 * Find a user by normalized phone without exposing phone login by default.
 *
 * @param string $phone Normalized or display phone number.
 * @return WP_User|false|WP_Error
 */
function identity_security_kit_get_user_by_phone( $phone ) {
	$normalized = identity_security_kit_normalize_phone( $phone );
	if ( is_wp_error( $normalized ) ) {
		return $normalized;
	}

	$users = get_users(
		array(
			'number'     => 1,
			'count_total' => false,
			'meta_key'   => identity_security_kit_phone_meta_key(),
			'meta_value' => $normalized,
		)
	);

	return ! empty( $users ) ? $users[0] : false;
}

/**
 * Validate that a phone number is not assigned to another account.
 *
 * @param string $phone           Phone number.
 * @param int    $exclude_user_id User allowed to own this number.
 * @return string|WP_Error Normalized number or error.
 */
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

/**
 * Store a validated phone number for a user.
 *
 * @param int    $user_id User ID.
 * @param string $phone   Phone number.
 * @return true|WP_Error
 */
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

	return true;
}
