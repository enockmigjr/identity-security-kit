<?php
/**
 * Public MFA challenge screen and REST transitions.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Whether the current request targets the public MFA challenge screen. */
function identity_security_kit_is_mfa_screen_request() {
	$request_path = wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ), PHP_URL_PATH );
	$screen_path  = wp_parse_url( home_url( '/security-check/' ), PHP_URL_PATH );

	return untrailingslashit( (string) $request_path ) === untrailingslashit( (string) $screen_path );
}

/** Load the MFA challenge presentation. */
function identity_security_kit_render_mfa_screen() {
	if ( ! identity_security_kit_is_mfa_screen_request() ) {
		return;
	}

	status_header( 200 );
	nocache_headers();
	include IDENTITY_SECURITY_KIT_DIR . 'templates/mfa-screen.php';
	exit;
}
add_action( 'template_redirect', 'identity_security_kit_render_mfa_screen', 0 );

/** Enqueue the challenge assets only on its public URL. */
function identity_security_kit_enqueue_mfa_screen_assets() {
	if ( ! identity_security_kit_is_mfa_screen_request() ) {
		return;
	}

	wp_enqueue_style(
		'identity-security-kit-mfa-screen',
		IDENTITY_SECURITY_KIT_URL . 'assets/css/mfa-screen.css',
		array(),
		IDENTITY_SECURITY_KIT_VERSION
	);
	wp_enqueue_script(
		'identity-security-kit-mfa-screen',
		IDENTITY_SECURITY_KIT_URL . 'assets/js/mfa-screen.js',
		array(),
		IDENTITY_SECURITY_KIT_VERSION,
		true
	);
}
add_action( 'wp_enqueue_scripts', 'identity_security_kit_enqueue_mfa_screen_assets' );

/** Return the non-sensitive state needed by the MFA screen. */
function identity_security_kit_get_public_mfa_state( $challenge ) {
	$methods = array();
	foreach ( $challenge['methods'] as $method ) {
		$methods[] = array(
			'id'          => $method,
			'label'       => identity_security_kit_get_mfa_method_label( $method ),
			'destination' => identity_security_kit_get_masked_mfa_destination( $challenge['user']->ID, $method ),
		);
	}

	return array(
		'method'   => sanitize_key( $challenge['method'] ),
		'prepared' => ! empty( $challenge['method_prepared'] ),
		'methods'  => $methods,
	);
}

/** Validate a token-bound MFA REST request. */
function identity_security_kit_validate_mfa_rest_request( WP_REST_Request $request ) {
	$params = $request->get_json_params();
	$params = is_array( $params ) ? $params : $request->get_params();
	$token  = sanitize_text_field( $params['token'] ?? '' );
	$nonce  = sanitize_text_field( $request->get_header( 'X-Identity-Nonce' ) );

	if ( ! wp_verify_nonce( $nonce, 'identity_security_mfa_rest_' . $token ) ) {
		return new WP_Error( 'mfa_nonce_failed', __( 'Security verification failed. Start the login again.', 'identity-security-kit' ) );
	}

	$challenge = identity_security_kit_get_login_challenge( $token );
	if ( is_wp_error( $challenge ) ) {
		return $challenge;
	}

	return array(
		'token'     => $token,
		'params'    => $params,
		'challenge' => $challenge,
	);
}

/** Format a challenge response consistently. */
function identity_security_kit_mfa_rest_response( $success, $message, $data = array(), $status = 200 ) {
	return new WP_REST_Response(
		array(
			'success' => (bool) $success,
			'message' => (string) $message,
			'data'    => is_array( $data ) ? $data : array(),
			'errors'  => array(),
		),
		$status
	);
}

/** Prepare or deliver the selected login factor. */
function identity_security_kit_rest_prepare_mfa_method( WP_REST_Request $request ) {
	$context = identity_security_kit_validate_mfa_rest_request( $request );
	if ( is_wp_error( $context ) ) {
		return identity_security_kit_mfa_rest_response( false, $context->get_error_message(), array(), 403 );
	}

	$method = sanitize_key( $context['params']['method'] ?? '' );
	$result = identity_security_kit_prepare_login_method( $context['token'], $method );
	if ( is_wp_error( $result ) ) {
		return identity_security_kit_mfa_rest_response( false, $result->get_error_message(), array(), 422 );
	}

	$message = in_array( $method, array( 'email', 'sms' ), true )
		? __( 'Un code de securite vient d etre envoye.', 'identity-security-kit' )
		: __( 'Saisissez le code de votre methode de verification.', 'identity-security-kit' );

	return identity_security_kit_mfa_rest_response( true, $message, identity_security_kit_get_public_mfa_state( $result ) );
}

/** Verify and consume the selected login factor. */
function identity_security_kit_rest_verify_mfa_method( WP_REST_Request $request ) {
	$context = identity_security_kit_validate_mfa_rest_request( $request );
	if ( is_wp_error( $context ) ) {
		return identity_security_kit_mfa_rest_response( false, $context->get_error_message(), array(), 403 );
	}

	$method = sanitize_key( $context['params']['method'] ?? '' );
	$code   = sanitize_text_field( $context['params']['code'] ?? '' );
	$result = identity_security_kit_consume_login_challenge( $context['token'], $code, $method );
	if ( is_wp_error( $result ) ) {
		return identity_security_kit_mfa_rest_response( false, $result->get_error_message(), array(), 422 );
	}

	$user = $result['user'];
	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, ! empty( $result['remember'] ), is_ssl() );
	do_action( 'wp_login', $user->user_login, $user );
	$destination = identity_security_kit_get_login_redirect( $user, $result['redirect_to'] );
	identity_security_kit_log_event( 'mfa_login_redirect', 'success', $user->ID, array( 'destination_path' => (string) wp_parse_url( $destination, PHP_URL_PATH ) ) );

	return identity_security_kit_mfa_rest_response(
		true,
		__( 'Identite confirmee. Redirection en cours...', 'identity-security-kit' ),
		array( 'redirect_url' => $destination )
	);
}

/** Register token-bound MFA transitions. */
function identity_security_kit_register_mfa_rest_routes() {
	register_rest_route(
		'identity-security-kit/v1',
		'/mfa/prepare',
		array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => 'identity_security_kit_rest_prepare_mfa_method',
			'permission_callback' => '__return_true',
		)
	);
	register_rest_route(
		'identity-security-kit/v1',
		'/mfa/verify',
		array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => 'identity_security_kit_rest_verify_mfa_method',
			'permission_callback' => '__return_true',
		)
	);
}
add_action( 'rest_api_init', 'identity_security_kit_register_mfa_rest_routes' );
