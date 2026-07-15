<?php
/**
 * Provider-agnostic SMS delivery with an optional Twilio adapter.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Read a provider secret from a constant first, then the environment. */
function identity_security_kit_get_provider_secret( $name ) {
	if ( defined( $name ) ) {
		return trim( (string) constant( $name ) );
	}
	$value = getenv( $name );

	return false === $value ? '' : trim( (string) $value );
}

/** Return the configured SMS provider slug. */
function identity_security_kit_get_sms_provider() {
	$settings = identity_security_kit_get_settings();
	$provider = sanitize_key( $settings['sms_provider'] ?? 'disabled' );

	return sanitize_key( apply_filters( 'identity_security_kit_sms_provider', $provider ) );
}

/** Determine whether the selected SMS provider can deliver messages. */
function identity_security_kit_sms_provider_available() {
	$provider = identity_security_kit_get_sms_provider();
	if ( 'brevo' === $provider ) {
		return '' !== identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_BREVO_API_KEY' )
			&& '' !== identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_BREVO_SMS_SENDER' );
	}
	if ( 'twilio' === $provider ) {
		return '' !== identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_TWILIO_ACCOUNT_SID' )
			&& '' !== identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_TWILIO_AUTH_TOKEN' )
			&& '' !== identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_TWILIO_FROM' );
	}

	return (bool) apply_filters( 'identity_security_kit_sms_provider_available', false, $provider );
}

/** Deliver a transactional security code through Brevo's fixed endpoint. */
function identity_security_kit_send_sms_via_brevo( $phone, $message, $context ) {
	$api_key = identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_BREVO_API_KEY' );
	$sender  = identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_BREVO_SMS_SENDER' );
	if ( '' === $api_key || '' === $sender ) {
		return new WP_Error( 'sms_provider_not_configured', __( 'The SMS provider is not configured.', 'identity-security-kit' ) );
	}
	if ( ! preg_match( '/^[A-Za-z0-9]{3,11}$/', $sender ) ) {
		return new WP_Error( 'sms_provider_invalid', __( 'The SMS provider configuration is invalid.', 'identity-security-kit' ) );
	}
	$recipient = ltrim( preg_replace( '/[^+0-9]/', '', (string) $phone ), '+' );
	if ( ! preg_match( '/^[1-9][0-9]{7,14}$/', $recipient ) ) {
		return new WP_Error( 'sms_provider_invalid_recipient', __( 'The SMS recipient is invalid.', 'identity-security-kit' ) );
	}
	$payload = array(
		'sender'    => $sender,
		'recipient' => $recipient,
		'content'   => (string) $message,
		'type'      => 'transactional',
		'tag'       => substr( sanitize_key( $context['purpose'] ?? 'identity_security' ), 0, 50 ),
	);
	$response = wp_safe_remote_post(
		'https://api.brevo.com/v3/transactionalSMS/send',
		array(
			'timeout'     => 10,
			'redirection' => 0,
			'headers'     => array(
				'Accept'          => 'application/json',
				'Content-Type'    => 'application/json',
				'api-key'         => $api_key,
				'Idempotency-Key' => (string) ( $context['idempotency_key'] ?? '' ),
			),
			'body'        => wp_json_encode( $payload ),
			'data_format' => 'body',
		)
	);
	if ( is_wp_error( $response ) ) {
		return new WP_Error( 'sms_provider_unavailable', __( 'The SMS provider is temporarily unavailable.', 'identity-security-kit' ) );
	}
	$status = wp_remote_retrieve_response_code( $response );
	$body   = json_decode( wp_remote_retrieve_body( $response ), true );
	if ( $status < 200 || $status >= 300 || ! is_array( $body ) || empty( $body['messageId'] ) ) {
		return new WP_Error( 'sms_provider_rejected', __( 'The SMS provider rejected the message.', 'identity-security-kit' ) );
	}

	return true;
}

/** Mask an international phone number for UI and audit output. */
function identity_security_kit_mask_phone( $phone ) {
	$phone = preg_replace( '/[^+0-9]/', '', (string) $phone );
	if ( strlen( $phone ) < 6 ) {
		return '******';
	}

	return substr( $phone, 0, min( 4, strlen( $phone ) - 4 ) ) . str_repeat( '*', max( 4, strlen( $phone ) - 6 ) ) . substr( $phone, -2 );
}

/** Deliver a message through Twilio's fixed HTTPS endpoint. */
function identity_security_kit_send_sms_via_twilio( $phone, $message, $context ) {
	$account_sid = identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_TWILIO_ACCOUNT_SID' );
	$auth_token  = identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_TWILIO_AUTH_TOKEN' );
	$from        = identity_security_kit_get_provider_secret( 'IDENTITY_SECURITY_TWILIO_FROM' );
	if ( '' === $account_sid || '' === $auth_token || '' === $from ) {
		return new WP_Error( 'sms_provider_not_configured', __( 'The SMS provider is not configured.', 'identity-security-kit' ) );
	}
	if ( ! preg_match( '/^AC[a-f0-9]{32}$/i', $account_sid ) ) {
		return new WP_Error( 'sms_provider_invalid', __( 'The SMS provider configuration is invalid.', 'identity-security-kit' ) );
	}

	$url      = 'https://api.twilio.com/2010-04-01/Accounts/' . rawurlencode( $account_sid ) . '/Messages.json';
	$response = wp_remote_post(
		$url,
		array(
			'timeout'     => 10,
			'redirection' => 0,
			'headers'     => array(
				'Authorization'   => 'Basic ' . base64_encode( $account_sid . ':' . $auth_token ),
				'Idempotency-Key' => (string) ( $context['idempotency_key'] ?? '' ),
			),
			'body'        => array(
				'To'   => $phone,
				'From' => $from,
				'Body' => $message,
			),
		)
	);
	if ( is_wp_error( $response ) ) {
		return new WP_Error( 'sms_provider_unavailable', __( 'The SMS provider is temporarily unavailable.', 'identity-security-kit' ) );
	}
	$status = wp_remote_retrieve_response_code( $response );
	$body   = json_decode( wp_remote_retrieve_body( $response ), true );
	if ( $status < 200 || $status >= 300 || ! is_array( $body ) || empty( $body['sid'] ) ) {
		return new WP_Error( 'sms_provider_rejected', __( 'The SMS provider rejected the message.', 'identity-security-kit' ) );
	}

	return true;
}

/**
 * Deliver an SMS through the configured adapter.
 *
 * Integrations may return true or WP_Error from the filter without exposing
 * credentials to this plugin.
 */
function identity_security_kit_send_sms( $phone, $message, $context = array() ) {
	$provider = identity_security_kit_get_sms_provider();
	$filtered = apply_filters( 'identity_security_kit_sms_delivery', null, $phone, $message, $context, $provider );
	if ( true === $filtered || is_wp_error( $filtered ) ) {
		return $filtered;
	}
	if ( 'twilio' === $provider ) {
		return identity_security_kit_send_sms_via_twilio( $phone, $message, $context );
	}
	if ( 'brevo' === $provider ) {
		return identity_security_kit_send_sms_via_brevo( $phone, $message, $context );
	}

	return new WP_Error( 'sms_provider_not_configured', __( 'The SMS provider is not configured.', 'identity-security-kit' ) );
}
