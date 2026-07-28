<?php
/**
 * Authenticated REST transport for account profile operations.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return the clean fallback endpoint for authenticated account forms. */
function identity_security_kit_get_account_action_url() {
	return home_url( '/account/security-action/' );
}

/** Dispatch allowlisted no-JavaScript account actions through a clean URL. */
function identity_security_kit_dispatch_account_action_url() {
	$request_path = wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ), PHP_URL_PATH );
	$target_path  = wp_parse_url( identity_security_kit_get_account_action_url(), PHP_URL_PATH );
	if ( untrailingslashit( (string) $request_path ) !== untrailingslashit( (string) $target_path ) ) {
		return;
	}
	if ( 'POST' !== strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) ) {
		status_header( 405 );
		exit;
	}

	$action = isset( $_POST['action'] ) ? sanitize_key( wp_unslash( $_POST['action'] ) ) : '';
	$map    = array(
		'identity_security_kit_totp_start'                 => 'identity_security_kit_handle_totp_start',
		'identity_security_kit_totp_confirm'               => 'identity_security_kit_handle_totp_confirm',
		'identity_security_kit_totp_cancel'                => 'identity_security_kit_handle_totp_cancel',
		'identity_security_kit_recovery_regenerate'        => 'identity_security_kit_handle_recovery_regenerate',
		'identity_security_kit_totp_disable'               => 'identity_security_kit_handle_totp_disable',
		'identity_security_kit_channel_mfa_start'          => 'identity_security_kit_handle_channel_mfa_start',
		'identity_security_kit_channel_mfa_confirm'        => 'identity_security_kit_handle_channel_mfa_confirm',
		'identity_security_kit_channel_mfa_disable_start'  => 'identity_security_kit_handle_channel_mfa_disable_start',
		'identity_security_kit_channel_mfa_disable_confirm' => 'identity_security_kit_handle_channel_mfa_disable_confirm',
		'identity_security_kit_mfa_preference'             => 'identity_security_kit_handle_mfa_preference',
		'identity_security_kit_phone_otp_request'          => 'identity_security_kit_handle_phone_otp_request',
		'identity_security_kit_phone_otp_verify'           => 'identity_security_kit_handle_phone_otp_verify',
		'identity_security_kit_email_otp_request'          => 'identity_security_kit_handle_email_otp_request',
		'identity_security_kit_email_otp_verify'           => 'identity_security_kit_handle_email_otp_verify',
		'identity_security_kit_resend_email_verification'  => 'identity_security_kit_handle_resend_email_verification',
		'identity_security_kit_cancel_email_change'        => 'identity_security_kit_handle_cancel_email_change',
	);
	if ( ! isset( $map[ $action ] ) || ! is_callable( $map[ $action ] ) ) {
		status_header( 404 );
		exit;
	}

	call_user_func( $map[ $action ] );
	exit;
}
add_action( 'template_redirect', 'identity_security_kit_dispatch_account_action_url', 0 );

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

/** Render the refreshed MFA panel with transient flow state. */
function identity_security_kit_account_rest_mfa_success( $message, $view = array() ) {
	$previous = $_GET;
	foreach ( $view as $key => $value ) {
		$_GET[ sanitize_key( $key ) ] = $value;
	}
	$html = identity_security_kit_render_mfa_panel();
	$_GET = $previous;

	return identity_security_kit_account_rest_response( true, $message, array( 'html' => $html ) );
}

/** Verify the current account password for a protected MFA transition. */
function identity_security_kit_account_rest_mfa_password( $user_id, $params ) {
	return identity_security_kit_account_check_password( $user_id, $params['current_password'] ?? '' );
}

/** Execute one MFA account transition without a full-page redirect. */
function identity_security_kit_account_rest_mfa( WP_REST_Request $request ) {
	$user_id = get_current_user_id();
	$params  = identity_security_kit_account_rest_params( $request );
	$action  = sanitize_key( $params['action'] ?? '' );
	$method  = sanitize_key( $params['mfa_method'] ?? '' );
	$code    = sanitize_text_field( $params['otp_code'] ?? $params['mfa_code'] ?? '' );

	if ( 'identity_security_kit_totp_start' === $action ) {
		$password = identity_security_kit_account_rest_mfa_password( $user_id, $params );
		$result   = is_wp_error( $password ) ? $password : identity_security_kit_begin_totp_enrollment( $user_id );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result, 'current_password' );
		}
		return identity_security_kit_account_rest_mfa_success(
			__( 'Scan the QR code, then enter the current six-digit code.', 'identity-security-kit' ),
			array( 'mfa' => 'enrollment_started' )
		);
	}

	if ( 'identity_security_kit_totp_confirm' === $action ) {
		$codes = identity_security_kit_confirm_totp_enrollment( $user_id, $code );
		if ( is_wp_error( $codes ) ) {
			return identity_security_kit_account_rest_error( $codes, 'otp_code' );
		}
		$token = identity_security_kit_store_recovery_display( $user_id, $codes );
		return identity_security_kit_account_rest_mfa_success(
			__( 'Authenticator verification is enabled. Save the recovery codes now.', 'identity-security-kit' ),
			array(
				'mfa'      => 'enabled',
				'recovery' => is_wp_error( $token ) ? '' : $token,
			)
		);
	}

	if ( 'identity_security_kit_totp_cancel' === $action ) {
		delete_user_meta( $user_id, 'identity_mfa_totp_pending' );
		identity_security_kit_log_event( 'totp_enrollment_cancelled', 'info', $user_id );
		return identity_security_kit_account_rest_mfa_success( __( 'Authenticator enrollment was cancelled.', 'identity-security-kit' ), array( 'mfa' => 'cancelled' ) );
	}

	if ( 'identity_security_kit_recovery_regenerate' === $action ) {
		$verify = identity_security_kit_verify_totp_or_recovery( $user_id, $code );
		if ( is_wp_error( $verify ) ) {
			return identity_security_kit_account_rest_error( $verify, 'mfa_code' );
		}
		$codes = identity_security_kit_generate_recovery_codes( $user_id );
		$token = is_wp_error( $codes ) ? $codes : identity_security_kit_store_recovery_display( $user_id, $codes );
		if ( is_wp_error( $token ) ) {
			return identity_security_kit_account_rest_error( $token );
		}
		return identity_security_kit_account_rest_mfa_success(
			__( 'New recovery codes were generated. Save them now.', 'identity-security-kit' ),
			array(
				'mfa'      => 'recovery_regenerated',
				'recovery' => $token,
			)
		);
	}

	if ( 'identity_security_kit_totp_disable' === $action ) {
		$password = identity_security_kit_account_rest_mfa_password( $user_id, $params );
		if ( is_wp_error( $password ) ) {
			return identity_security_kit_account_rest_error( $password, 'current_password' );
		}
		$allowed = identity_security_kit_can_disable_mfa_method( $user_id, 'totp' );
		if ( is_wp_error( $allowed ) ) {
			return identity_security_kit_account_rest_error( $allowed );
		}
		$verify = identity_security_kit_verify_totp_or_recovery( $user_id, $code );
		if ( is_wp_error( $verify ) ) {
			return identity_security_kit_account_rest_error( $verify, 'mfa_code' );
		}
		$result = identity_security_kit_disable_mfa_method( $user_id, 'totp' );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result );
		}
		return identity_security_kit_account_rest_mfa_success( __( 'Authenticator verification was disabled.', 'identity-security-kit' ), array( 'mfa' => 'disabled' ) );
	}

	if ( 'identity_security_kit_channel_mfa_start' === $action ) {
		$password = identity_security_kit_account_rest_mfa_password( $user_id, $params );
		if ( is_wp_error( $password ) ) {
			return identity_security_kit_account_rest_error( $password, 'current_password' );
		}
		if ( ! in_array( $method, array( 'email', 'sms' ), true ) || ! in_array( $method, identity_security_kit_get_allowed_mfa_methods( $user_id ), true ) ) {
			return identity_security_kit_account_rest_error( __( 'This verification method is not available.', 'identity-security-kit' ) );
		}
		if ( 'email' === $method && ! identity_security_kit_is_email_verified( $user_id ) ) {
			return identity_security_kit_account_rest_error( __( 'Verify the account email before enabling this method.', 'identity-security-kit' ) );
		}
		if ( 'sms' === $method && ! identity_security_kit_is_phone_verified( $user_id ) ) {
			return identity_security_kit_account_rest_error( __( 'Verify the phone number before enabling this method.', 'identity-security-kit' ) );
		}
		$result = 'email' === $method
			? identity_security_kit_create_email_otp_challenge( $user_id, 'mfa_enrollment_' . $method )
			: identity_security_kit_create_phone_otp_challenge( $user_id, 'mfa_enrollment_' . $method );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result );
		}
		return identity_security_kit_account_rest_mfa_success(
			__( 'A security code was sent. Enter it to enable the method.', 'identity-security-kit' ),
			array(
				'mfa'                  => 'channel_code_sent',
				'mfa_enroll_method'    => $method,
				'mfa_enroll_challenge' => absint( $result ),
			)
		);
	}

	if ( 'identity_security_kit_channel_mfa_confirm' === $action ) {
		$challenge_id = absint( $params['challenge_id'] ?? 0 );
		$result       = identity_security_kit_enable_channel_mfa( $user_id, $method, $challenge_id, $code );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result, 'otp_code' );
		}
		return identity_security_kit_account_rest_mfa_success(
			__( 'The verification method is enabled.', 'identity-security-kit' ),
			array(
				'mfa'      => 'enabled',
				'recovery' => $result['recovery_token'] ?? '',
			)
		);
	}

	if ( 'identity_security_kit_channel_mfa_disable_start' === $action ) {
		$password = identity_security_kit_account_rest_mfa_password( $user_id, $params );
		$result   = is_wp_error( $password ) ? $password : identity_security_kit_start_channel_mfa_disable( $user_id, $method );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result, is_wp_error( $password ) ? 'current_password' : '' );
		}
		return identity_security_kit_account_rest_mfa_success(
			__( 'A security code was sent. Enter it to disable the method.', 'identity-security-kit' ),
			array(
				'mfa'                   => 'disable_code_sent',
				'mfa_disable_method'    => $method,
				'mfa_disable_challenge' => absint( $result ),
			)
		);
	}

	if ( 'identity_security_kit_channel_mfa_disable_confirm' === $action ) {
		$result = identity_security_kit_confirm_channel_mfa_disable( $user_id, $method, absint( $params['challenge_id'] ?? 0 ), $code );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result, 'otp_code' );
		}
		return identity_security_kit_account_rest_mfa_success( __( 'The verification method was disabled.', 'identity-security-kit' ), array( 'mfa' => 'disabled' ) );
	}

	if ( 'identity_security_kit_mfa_preference' === $action ) {
		$password = identity_security_kit_account_rest_mfa_password( $user_id, $params );
		if ( is_wp_error( $password ) ) {
			return identity_security_kit_account_rest_error( $password, 'current_password' );
		}
		if ( ! in_array( $method, identity_security_kit_get_user_mfa_methods( $user_id ), true ) ) {
			return identity_security_kit_account_rest_error( __( 'This verification method is not enabled.', 'identity-security-kit' ), 'mfa_method' );
		}
		update_user_meta( $user_id, 'identity_mfa_preferred_method', $method );
		identity_security_kit_log_event( 'mfa_preference_changed', 'success', $user_id, array( 'method' => $method ) );
		return identity_security_kit_account_rest_mfa_success( __( 'Preferred verification method saved.', 'identity-security-kit' ), array( 'mfa' => 'preference_saved' ) );
	}

	if ( 'identity_security_kit_phone_otp_request' === $action ) {
		$result = identity_security_kit_create_phone_otp_challenge( $user_id, 'verify_phone' );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result );
		}
		return identity_security_kit_account_rest_mfa_success(
			__( 'A verification code was sent to your phone.', 'identity-security-kit' ),
			array(
				'phone_otp'       => 'sent',
				'phone_challenge' => absint( $result ),
			)
		);
	}

	if ( 'identity_security_kit_phone_otp_verify' === $action ) {
		$result = identity_security_kit_verify_phone_otp_challenge( absint( $params['challenge_id'] ?? 0 ), $user_id, $code, 'verify_phone' );
		if ( is_wp_error( $result ) ) {
			return identity_security_kit_account_rest_error( $result, 'otp_code' );
		}
		return identity_security_kit_account_rest_mfa_success( __( 'Your phone number is verified.', 'identity-security-kit' ), array( 'phone_otp' => 'verified' ) );
	}

	return identity_security_kit_account_rest_error( __( 'Choose a valid security action.', 'identity-security-kit' ) );
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
	register_rest_route(
		'identity-security-kit/v1',
		'/account/mfa',
		array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => 'identity_security_kit_account_rest_mfa',
			'permission_callback' => 'is_user_logged_in',
		)
	);
}
add_action( 'rest_api_init', 'identity_security_kit_register_account_rest_routes' );
