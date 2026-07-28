<?php
/**
 * HTTP runtime coverage for asynchronous frontend authentication.
 *
 * Run with:
 * wp eval-file wp-content/plugins/identity-security-kit/tests/runtime-async-auth.php
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

/** Stop the runtime test on one failed expectation. */
function identity_async_auth_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

/** Resolve the Docker-internal URL for one public path. */
function identity_async_auth_url( $path ) {
	$url = home_url( $path );

	return str_replace( array( 'http://localhost:8080', 'https://localhost:8080' ), 'http://nginx', $url );
}

/** Extract a named WordPress nonce from one rendered form. */
function identity_async_auth_nonce( $path, $name, $user_agent ) {
	$response = wp_remote_get(
		identity_async_auth_url( $path ),
		array(
			'timeout'    => 15,
			'user-agent' => $user_agent,
			'headers'    => array( 'Host' => 'localhost:8080' ),
		)
	);
	identity_async_auth_assert( 200 === wp_remote_retrieve_response_code( $response ), 'Authentication page could not be loaded.' );
	preg_match( '/name="' . preg_quote( $name, '/' ) . '" value="([^"]+)"/', wp_remote_retrieve_body( $response ), $matches );
	identity_async_auth_assert( ! empty( $matches[1] ), 'Authentication form nonce is missing.' );

	return html_entity_decode( $matches[1], ENT_QUOTES, 'UTF-8' );
}

/** Submit one public authentication form as an asynchronous request. */
function identity_async_auth_post( $path, $body, $user_agent ) {
	$response = wp_remote_post(
		identity_async_auth_url( $path ),
		array(
			'timeout'     => 20,
			'redirection' => 0,
			'user-agent'  => $user_agent,
			'headers'     => array(
				'Accept'           => 'application/json',
				'Host'             => 'localhost:8080',
				'X-Requested-With' => 'XMLHttpRequest',
			),
			'body'        => $body,
		)
	);
	$decoded  = json_decode( wp_remote_retrieve_body( $response ), true );
	identity_async_auth_assert( is_array( $decoded ), 'Authentication response is not JSON.' );

	return array(
		'status' => wp_remote_retrieve_response_code( $response ),
		'body'   => $decoded,
	);
}

global $wpdb;

$suffix     = strtolower( wp_generate_password( 8, false, false ) );
$username   = 'async_auth_' . $suffix;
$email      = $username . '@photovault.test';
$phone      = '+120255501' . str_pad( (string) wp_rand( 10, 99 ), 2, '0', STR_PAD_LEFT );
$password   = 'Strong!Pass2026';
$user_agent = 'PhotoVault-Async-Auth-Test/' . $suffix;
$user_id    = 0;

try {
	$login_nonce = identity_async_auth_nonce( '/login/', 'photovault_login_nonce', $user_agent );
	$invalid     = identity_async_auth_post(
		'/login/',
		array(
			'photovault_login_nonce' => $login_nonce,
			'log'                    => $username,
			'pwd'                    => 'invalid-password',
		),
		$user_agent
	);
	identity_async_auth_assert( 422 === $invalid['status'] && empty( $invalid['body']['success'] ) && ! empty( $invalid['body']['errors']['log'] ), 'Invalid login did not return a field-level JSON error.' );

	$register_nonce = identity_async_auth_nonce( '/register/', 'photovault_register_nonce', $user_agent );
	$registration   = identity_async_auth_post(
		'/register/',
		array(
			'photovault_register_nonce' => $register_nonce,
			'first_name'                => 'Async',
			'last_name'                 => 'Runtime',
			'username'                  => $username,
			'email'                     => $email,
			'phone'                     => $phone,
			'password'                  => $password,
			'password_confirm'          => $password,
		),
		$user_agent
	);
	$user_id        = username_exists( $username );
	identity_async_auth_assert( 200 === $registration['status'] && ! empty( $registration['body']['success'] ) && $user_id, 'Asynchronous registration did not create the account.' );
	identity_async_auth_assert( false !== strpos( $registration['body']['data']['redirect_url'] ?? '', '/profile/' ), 'Registration did not return the frontend profile transition.' );

	$login_nonce = identity_async_auth_nonce( '/login/', 'photovault_login_nonce', $user_agent );
	$login       = identity_async_auth_post(
		'/login/',
		array(
			'photovault_login_nonce' => $login_nonce,
			'log'                    => $username,
			'pwd'                    => $password,
		),
		$user_agent
	);
	identity_async_auth_assert( 200 === $login['status'] && ! empty( $login['body']['success'] ) && ! empty( $login['body']['data']['redirect_url'] ), 'Valid asynchronous login did not return its transition.' );

	$forgot_nonce = identity_async_auth_nonce( '/forgot-password/', 'photovault_forgot_nonce', $user_agent );
	$forgot       = identity_async_auth_post(
		'/forgot-password/',
		array(
			'photovault_forgot_nonce' => $forgot_nonce,
			'user_login'              => 'unknown-' . $email,
		),
		$user_agent
	);
	identity_async_auth_assert( 200 === $forgot['status'] && ! empty( $forgot['body']['success'] ) && empty( $forgot['body']['data']['redirect_url'] ), 'Password request did not return the neutral inline response.' );

	$user      = get_user_by( 'id', $user_id );
	$reset_key = get_password_reset_key( $user );
	identity_async_auth_assert( ! is_wp_error( $reset_key ), 'Password reset key could not be created.' );
	$reset_path  = add_query_arg( array( 'key' => $reset_key, 'login' => $username ), '/reset-password/' );
	$reset_nonce = identity_async_auth_nonce( $reset_path, 'photovault_reset_nonce', $user_agent );
	$reset       = identity_async_auth_post(
		$reset_path,
		array(
			'photovault_reset_nonce' => $reset_nonce,
			'rp_key'                 => $reset_key,
			'rp_login'               => $username,
			'password'               => 'Changed!Pass2026',
			'password_confirm'       => 'Changed!Pass2026',
		),
		$user_agent
	);
	identity_async_auth_assert( 200 === $reset['status'] && ! empty( $reset['body']['success'] ) && false !== strpos( $reset['body']['data']['redirect_url'] ?? '', '/login/' ), 'Password reset did not return the branded login transition.' );

	echo wp_json_encode(
		array(
			'invalid_login' => 'field_error_without_reload',
			'registration'  => 'created_with_profile_transition',
			'valid_login'   => 'authenticated_with_transition',
			'forgot'        => 'neutral_inline_response',
			'reset'         => 'completed_with_login_transition',
		)
	);
} finally {
	if ( $user_id ) {
		require_once ABSPATH . 'wp-admin/includes/user.php';
		$wpdb->delete( identity_security_kit_get_email_verification_table(), array( 'user_id' => $user_id ), array( '%d' ) );
		$wpdb->delete( identity_security_kit_get_audit_table(), array( 'user_id' => $user_id ), array( '%d' ) );
		wp_delete_user( $user_id );
	}
}
