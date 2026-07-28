<?php
/**
 * Authenticated REST transport for account profile operations.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return a stable account API response. */
function identity_security_kit_account_rest_response( $success, $message, $data = array(), $errors = array(), $status = 200 ) {
	return new WP_REST_Response(
		array(
			'success' => (bool) $success,
			'message' => (string) $message,
			'data'    => is_array( $data ) ? $data : array(),
			'errors'  => is_array( $errors ) ? $errors : array(),
			'meta'    => array(),
		),
		absint( $status )
	);
}

/** Convert a domain error to the account API contract. */
function identity_security_kit_account_rest_error( $error, $field = '', $status = 422 ) {
	$error  = is_wp_error( $error ) ? $error : new WP_Error( 'account_update_failed', (string) $error );
	$errors = $field ? array( sanitize_key( $field ) => $error->get_error_message() ) : array();

	return identity_security_kit_account_rest_response( false, $error->get_error_message(), array(), $errors, $status );
}

/** Read JSON or multipart account request values. */
function identity_security_kit_account_rest_params( WP_REST_Request $request ) {
	$json = $request->get_json_params();
	return is_array( $json ) ? $json : $request->get_params();
}

/** Require the current password without exposing account state. */
function identity_security_kit_account_check_password( $user_id, $password ) {
	$user = get_userdata( absint( $user_id ) );
	if ( ! $user || '' === (string) $password || ! wp_check_password( (string) $password, $user->user_pass, $user_id ) ) {
		return new WP_Error( 'current_password_invalid', __( 'The current password is incorrect.', 'identity-security-kit' ) );
	}

	return $user;
}

/** Update public profile identity fields. */
function identity_security_kit_account_rest_identity( $user_id, $params ) {
	$display_name = sanitize_text_field( $params['display_name'] ?? '' );
	$bio          = sanitize_textarea_field( $params['bio'] ?? '' );
	if ( '' === $display_name ) {
		return identity_security_kit_account_rest_error( __( 'The display name is required.', 'identity-security-kit' ), 'display_name' );
	}

	$result = wp_update_user(
		array(
			'ID'           => $user_id,
			'display_name' => $display_name,
			'description'  => $bio,
		)
	);
	if ( is_wp_error( $result ) ) {
		return identity_security_kit_account_rest_error( $result );
	}

	return identity_security_kit_account_rest_response(
		true,
		__( 'Your public information was updated.', 'identity-security-kit' ),
		array(
			'display_name' => $display_name,
			'bio'          => $bio,
		)
	);
}

/** Validate and attach one avatar upload to the current account. */
function identity_security_kit_account_rest_avatar( $user_id ) {
	if ( empty( $_FILES['profile_avatar'] ) || ! is_array( $_FILES['profile_avatar'] ) ) {
		return identity_security_kit_account_rest_error( __( 'Choose an image before continuing.', 'identity-security-kit' ), 'profile_avatar' );
	}

	$file     = $_FILES['profile_avatar'];
	$settings = identity_security_kit_get_settings();
	$max_size = absint( $settings['max_avatar_size_mb'] ) * MB_IN_BYTES;
	if ( ! empty( $file['error'] ) || empty( $file['tmp_name'] ) || ! is_uploaded_file( $file['tmp_name'] ) ) {
		return identity_security_kit_account_rest_error( __( 'The uploaded file is invalid.', 'identity-security-kit' ), 'profile_avatar' );
	}
	if ( absint( $file['size'] ) > $max_size ) {
		return identity_security_kit_account_rest_error( __( 'The avatar file is too large.', 'identity-security-kit' ), 'profile_avatar', 413 );
	}

	$image = wp_getimagesize( $file['tmp_name'] );
	if ( ! is_array( $image ) || empty( $image[0] ) || empty( $image[1] ) ) {
		return identity_security_kit_account_rest_error( __( 'The uploaded file is not a valid image.', 'identity-security-kit' ), 'profile_avatar' );
	}
	if ( max( absint( $image[0] ), absint( $image[1] ) ) > absint( $settings['max_avatar_dimension'] ) ) {
		return identity_security_kit_account_rest_error( __( 'The image dimensions are too large.', 'identity-security-kit' ), 'profile_avatar' );
	}

	$allowed = array( 'image/jpeg', 'image/png', 'image/webp' );
	if ( ! in_array( sanitize_mime_type( $image['mime'] ?? '' ), $allowed, true ) ) {
		return identity_security_kit_account_rest_error( __( 'This image type is not allowed.', 'identity-security-kit' ), 'profile_avatar' );
	}

	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/image.php';
	require_once ABSPATH . 'wp-admin/includes/media.php';
	$attachment_id = media_handle_upload( 'profile_avatar', 0, array(), array( 'test_form' => false ) );
	if ( is_wp_error( $attachment_id ) ) {
		return identity_security_kit_account_rest_error( $attachment_id, 'profile_avatar' );
	}

	update_post_meta( $attachment_id, '_identity_security_avatar_owner', $user_id );
	update_user_meta( $user_id, 'photovault_avatar_id', absint( $attachment_id ) );
	identity_security_kit_log_event( 'avatar_updated', 'success', $user_id, array( 'attachment_id' => absint( $attachment_id ) ) );

	return identity_security_kit_account_rest_response(
		true,
		__( 'Your profile photo was updated.', 'identity-security-kit' ),
		array(
			'avatar_id'  => absint( $attachment_id ),
			'avatar_url' => wp_get_attachment_image_url( $attachment_id, 'thumbnail' ),
		)
	);
}

/** Update the account phone independently from every other profile field. */
function identity_security_kit_account_rest_phone( $user_id, $params ) {
	$result = identity_security_kit_set_user_phone( $user_id, $params['phone'] ?? '' );
	if ( is_wp_error( $result ) ) {
		return identity_security_kit_account_rest_error( $result, 'phone' );
	}

	return identity_security_kit_account_rest_response(
		true,
		__( 'Your phone number was saved. Verification is now required.', 'identity-security-kit' ),
		array( 'phone' => (string) get_user_meta( $user_id, identity_security_kit_phone_meta_key(), true ) )
	);
}

/** Start a confirmed account email change. */
function identity_security_kit_account_rest_email( $user_id, $params ) {
	$result = identity_security_kit_request_email_change(
		$user_id,
		$params['new_email'] ?? '',
		$params['email_current_password'] ?? ''
	);
	if ( is_wp_error( $result ) ) {
		$field = 'current_password_invalid' === $result->get_error_code() ? 'email_current_password' : 'new_email';
		return identity_security_kit_account_rest_error( $result, $field );
	}

	return identity_security_kit_account_rest_response( true, __( 'Check the new address to confirm this change.', 'identity-security-kit' ) );
}

/** Replace the account password and keep only the current browser authenticated. */
function identity_security_kit_account_rest_password( $user_id, $params ) {
	$current = (string) ( $params['current_password'] ?? '' );
	$password = (string) ( $params['password'] ?? '' );
	$confirm  = (string) ( $params['password_confirm'] ?? '' );
	$user     = identity_security_kit_account_check_password( $user_id, $current );
	if ( is_wp_error( $user ) ) {
		return identity_security_kit_account_rest_error( $user, 'current_password' );
	}
	if ( $password !== $confirm ) {
		return identity_security_kit_account_rest_error( __( 'The new passwords do not match.', 'identity-security-kit' ), 'password_confirm' );
	}
	$minimum = absint( identity_security_kit_get_settings()['min_password_length'] );
	if ( strlen( $password ) < $minimum ) {
		return identity_security_kit_account_rest_error(
			sprintf( __( 'Use at least %d characters.', 'identity-security-kit' ), $minimum ),
			'password'
		);
	}

	wp_set_password( $password, $user_id );
	wp_set_current_user( $user_id );
	wp_set_auth_cookie( $user_id, true, is_ssl() );
	identity_security_kit_send_security_notification( $user_id, __( 'Your account password was changed. Other sessions were closed.', 'identity-security-kit' ) );
	identity_security_kit_log_event( 'password_changed', 'success', $user_id );

	return identity_security_kit_account_rest_response( true, __( 'Your password was changed and other sessions were closed.', 'identity-security-kit' ) );
}

/** Dispatch one authenticated account operation. */
function identity_security_kit_account_rest_update( WP_REST_Request $request ) {
	$user_id = get_current_user_id();
	$params  = identity_security_kit_account_rest_params( $request );
	$action  = sanitize_key( $params['profile_action'] ?? $params['account_action'] ?? '' );

	if ( 'identity' === $action ) {
		return identity_security_kit_account_rest_identity( $user_id, $params );
	}
	if ( 'avatar' === $action ) {
		return identity_security_kit_account_rest_avatar( $user_id );
	}
	if ( 'phone' === $action ) {
		return identity_security_kit_account_rest_phone( $user_id, $params );
	}
	if ( 'email' === $action ) {
		return identity_security_kit_account_rest_email( $user_id, $params );
	}
	if ( 'password' === $action ) {
		return identity_security_kit_account_rest_password( $user_id, $params );
	}
	if ( 'resend_verification' === $action ) {
		$user   = get_userdata( $user_id );
		$result = $user ? identity_security_kit_create_email_verification_challenge( $user_id, $user->user_email ) : new WP_Error( 'user_not_found', __( 'User not found.', 'identity-security-kit' ) );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result );
		}
		return identity_security_kit_account_rest_response( true, __( 'A new verification link was sent.', 'identity-security-kit' ) );
	}
	if ( 'cancel_email_change' === $action ) {
		delete_user_meta( $user_id, identity_security_kit_pending_email_change_meta_key() );
		identity_security_kit_log_event( 'email_change_cancelled', 'info', $user_id );
		return identity_security_kit_account_rest_response( true, __( 'The pending email change was cancelled.', 'identity-security-kit' ) );
	}

	return identity_security_kit_account_rest_error( __( 'Choose a valid account action.', 'identity-security-kit' ) );
}

/** Register authenticated account routes. */
function identity_security_kit_register_account_rest_routes() {
	register_rest_route(
		'identity-security-kit/v1',
		'/account',
		array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => 'identity_security_kit_account_rest_update',
			'permission_callback' => 'is_user_logged_in',
		)
	);
}
add_action( 'rest_api_init', 'identity_security_kit_register_account_rest_routes' );
