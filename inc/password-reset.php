<?php
/**
 * Branded password reset URLs, emails and frontend processing.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Build the frontend password reset URL for a user and one-time key. */
function identity_security_kit_get_password_reset_url( $user, $key ) {
	if ( ! $user instanceof WP_User || '' === (string) $key ) {
		return identity_security_kit_get_route_url( 'forgot_password' );
	}

	return add_query_arg(
		array(
			'key'   => (string) $key,
			'login' => $user->user_login,
		),
		identity_security_kit_get_route_url( 'reset_password' )
	);
}

/** Render native WordPress reset notifications with the shared identity layout. */
function identity_security_kit_filter_password_reset_notification( $email, $key, $user_login, $user ) {
	if ( ! $user instanceof WP_User ) {
		return $email;
	}

	$url     = identity_security_kit_get_password_reset_url( $user, $key );
	$content = array(
		'preheader'    => __( 'A secure password reset link was requested.', 'identity-security-kit' ),
		'eyebrow'      => __( 'Account security', 'identity-security-kit' ),
		'title'        => __( 'Reset your password', 'identity-security-kit' ),
		'greeting'     => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $user->display_name ? $user->display_name : $user_login ),
		'intro'        => __( 'Use the protected link below to choose a new password for your PhotoVault account.', 'identity-security-kit' ),
		'details'      => array( __( 'The link is temporary and can be used only once.', 'identity-security-kit' ) ),
		'action_url'   => $url,
		'action_label' => __( 'Choose a new password', 'identity-security-kit' ),
		'notice'       => __( 'If you did not request this change, ignore this email. Your current password remains active.', 'identity-security-kit' ),
	);
	$brand   = identity_security_kit_get_email_brand();

	$email['subject'] = sprintf( __( '[%s] Password reset', 'identity-security-kit' ), $brand['name'] );
	$email['message'] = identity_security_kit_render_email_html( $content );
	$email['headers'] = 'Content-Type: text/html; charset=UTF-8';
	identity_security_kit_register_next_email_alt_body( identity_security_kit_render_email_text( $content ) );

	return $email;
}
add_filter( 'retrieve_password_notification_email', 'identity_security_kit_filter_password_reset_notification', 20, 4 );

/** Redirect legacy WordPress reset links to the branded frontend route. */
function identity_security_kit_redirect_native_password_reset() {
	$key   = isset( $_GET['key'] ) ? sanitize_text_field( wp_unslash( $_GET['key'] ) ) : '';
	$login = isset( $_GET['login'] ) ? sanitize_user( wp_unslash( $_GET['login'] ) ) : '';
	$user  = $login ? get_user_by( 'login', $login ) : false;

	if ( $user instanceof WP_User && '' !== $key ) {
		wp_safe_redirect( identity_security_kit_get_password_reset_url( $user, $key ), 303 );
	} else {
		wp_safe_redirect( add_query_arg( 'reset', 'invalid', identity_security_kit_get_route_url( 'forgot_password' ) ), 303 );
	}
	exit;
}
add_action( 'login_form_rp', 'identity_security_kit_redirect_native_password_reset' );
add_action( 'login_form_resetpass', 'identity_security_kit_redirect_native_password_reset' );

/** Validate and consume a password reset submission from the frontend page. */
function identity_security_kit_handle_frontend_password_reset() {
	if ( ! identity_security_kit_is_post_request() || ! isset( $_POST['photovault_reset_nonce'] ) ) {
		return;
	}

	$key      = isset( $_POST['rp_key'] ) ? sanitize_text_field( wp_unslash( $_POST['rp_key'] ) ) : '';
	$login    = isset( $_POST['rp_login'] ) ? sanitize_user( wp_unslash( $_POST['rp_login'] ) ) : '';
	$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
	$confirm  = isset( $_POST['password_confirm'] ) ? (string) wp_unslash( $_POST['password_confirm'] ) : '';
	$return   = add_query_arg( array( 'key' => $key, 'login' => $login ), identity_security_kit_get_route_url( 'reset_password' ) );

	if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['photovault_reset_nonce'] ) ), 'photovault_reset_action' ) ) {
		identity_security_kit_log_event( 'password_reset_confirmation_nonce_failed', 'failure' );
		wp_safe_redirect( add_query_arg( 'reset', 'security_failed', $return ) );
		exit;
	}

	$user = check_password_reset_key( $key, $login );
	if ( is_wp_error( $user ) ) {
		identity_security_kit_log_event( 'password_reset_confirmation_invalid', 'warning' );
		identity_security_kit_redirect( 'forgot_password', array( 'reset' => 'invalid' ) );
	}
	if ( strlen( $password ) < identity_security_kit_get_min_password_length() ) {
		wp_safe_redirect( add_query_arg( 'reset', 'weak_password', $return ) );
		exit;
	}
	if ( ! hash_equals( $password, $confirm ) ) {
		wp_safe_redirect( add_query_arg( 'reset', 'password_mismatch', $return ) );
		exit;
	}

	reset_password( $user, $password );
	identity_security_kit_log_event( 'password_reset_completed', 'success', $user->ID );
	identity_security_kit_send_transactional_email(
		$user->user_email,
		sprintf( __( '[%s] Password changed', 'identity-security-kit' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) ),
		array(
			'preheader' => __( 'Your PhotoVault password was changed.', 'identity-security-kit' ),
			'title'     => __( 'Password changed', 'identity-security-kit' ),
			'greeting'  => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $user->display_name ? $user->display_name : $user->user_login ),
			'intro'     => __( 'Your password was reset successfully. You can now sign in with the new password.', 'identity-security-kit' ),
			'notice'    => sprintf( __( 'If you did not make this change, contact the site administrator immediately at %s.', 'identity-security-kit' ), sanitize_email( get_option( 'admin_email' ) ) ),
		)
	);

	identity_security_kit_redirect( 'login', array( 'password' => 'reset' ) );
}
add_action( 'template_redirect', 'identity_security_kit_handle_frontend_password_reset', 5 );
