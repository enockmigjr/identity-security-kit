<?php
/**
 * Authentication and profile handlers for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get configurable routes while preserving existing PhotoVault URLs by default.
 *
 * @return array<string,string>
 */
function identity_security_kit_get_routes() {
	$gallery_url = get_post_type_archive_link( 'media_item' );
	if ( ! $gallery_url ) {
		$gallery_url = home_url( '/' );
	}

	$routes = array(
		'login'           => home_url( '/login/' ),
		'register'        => home_url( '/register/' ),
		'profile'         => home_url( '/profile/' ),
		'forgot_password' => home_url( '/forgot-password/' ),
		'dashboard'       => home_url( '/dashboard/' ),
		'after_login'     => $gallery_url,
	);

	/**
	 * Filter Identity Kit route targets.
	 *
	 * @param array<string,string> $routes Route map.
	 */
	return apply_filters( 'identity_security_kit_routes', $routes );
}

/**
 * Return a route URL by key.
 *
 * @param string $key Route key.
 * @return string
 */
function identity_security_kit_get_route_url( $key ) {
	$routes = identity_security_kit_get_routes();

	return isset( $routes[ $key ] ) ? $routes[ $key ] : home_url( '/' );
}

/**
 * Redirect safely to a configured route.
 *
 * @param string              $key  Route key.
 * @param array<string,mixed> $args Query arguments.
 */
function identity_security_kit_redirect( $key, $args = array() ) {
	$url = identity_security_kit_get_route_url( $key );
	if ( ! empty( $args ) ) {
		$url = add_query_arg( $args, $url );
	}

	wp_safe_redirect( $url );
	exit;
}

/**
 * Check whether the current request is a POST request.
 *
 * @return bool
 */
function identity_security_kit_is_post_request() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';

	return 'POST' === strtoupper( $method );
}

/**
 * Return allowed image MIME types for identity uploads.
 *
 * @return array<string,string>
 */
function identity_security_kit_get_allowed_image_mimes() {
	$mimes = array(
		'jpg|jpeg' => 'image/jpeg',
		'png'      => 'image/png',
		'webp'     => 'image/webp',
	);

	/**
	 * Filter allowed image MIME types for identity uploads.
	 *
	 * @param array<string,string> $mimes MIME map.
	 */
	return apply_filters( 'identity_security_kit_allowed_image_mimes', $mimes );
}

/**
 * Validate an uploaded profile image server-side.
 *
 * @param array<string,mixed> $file Uploaded file array.
 * @return true|WP_Error
 */
function identity_security_kit_validate_uploaded_image_file( $file ) {
	if ( empty( $file['tmp_name'] ) || ! is_uploaded_file( $file['tmp_name'] ) ) {
		return new WP_Error( 'invalid_upload', __( 'The uploaded file is invalid.', 'identity-security-kit' ) );
	}

	$settings = function_exists( 'identity_security_kit_get_settings' ) ? identity_security_kit_get_settings() : array( 'max_avatar_size_mb' => 6, 'max_avatar_dimension' => 6000 );
	$max_size = (int) apply_filters( 'identity_security_kit_max_avatar_size', $settings['max_avatar_size_mb'] * MB_IN_BYTES );
	$size     = isset( $file['size'] ) ? (int) $file['size'] : 0;
	if ( $size <= 0 || $size > $max_size ) {
		return new WP_Error( 'file_too_large', __( 'The uploaded file is too large.', 'identity-security-kit' ) );
	}

	$filename = isset( $file['name'] ) ? sanitize_file_name( wp_unslash( $file['name'] ) ) : '';
	$check    = wp_check_filetype_and_ext( $file['tmp_name'], $filename, identity_security_kit_get_allowed_image_mimes() );
	if ( empty( $check['ext'] ) || empty( $check['type'] ) ) {
		return new WP_Error( 'invalid_file_type', __( 'This image type is not allowed.', 'identity-security-kit' ) );
	}

	$dimensions = @getimagesize( $file['tmp_name'] );
	if ( false === $dimensions ) {
		return new WP_Error( 'invalid_image', __( 'The uploaded file is not a valid image.', 'identity-security-kit' ) );
	}

	$max_dimension = (int) apply_filters( 'identity_security_kit_max_avatar_dimension', $settings['max_avatar_dimension'] );
	if ( $dimensions[0] > $max_dimension || $dimensions[1] > $max_dimension ) {
		return new WP_Error( 'image_too_large', __( 'The uploaded image dimensions are too large.', 'identity-security-kit' ) );
	}

	return true;
}


/**
 * Return the active minimum password length.
 *
 * @return int
 */
function identity_security_kit_get_min_password_length() {
	$settings = function_exists( 'identity_security_kit_get_settings' ) ? identity_security_kit_get_settings() : array( 'min_password_length' => 8 );

	return max( 8, absint( $settings['min_password_length'] ) );
}
/**
 * Resolve the default role for front-office registrations.
 *
 * @return string
 */
function identity_security_kit_get_registration_role() {
	$role = get_role( 'client' ) ? 'client' : 'subscriber';

	/**
	 * Filter the role assigned during front-office registration.
	 *
	 * @param string $role Role slug.
	 */
	return sanitize_key( apply_filters( 'identity_security_kit_registration_role', $role ) );
}

/**
 * Handle front-office login submissions.
 */
function identity_security_kit_handle_login() {
	if ( ! identity_security_kit_is_post_request() || ! isset( $_POST['photovault_login_nonce'] ) ) {
		return;
	}

	if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['photovault_login_nonce'] ) ), 'photovault_login_action' ) ) {
		identity_security_kit_log_event( 'login_nonce_failed', 'failure' );
		wp_die( esc_html__( 'Security verification failed.', 'identity-security-kit' ) );
	}
	if ( ! identity_security_kit_rate_limit_by_setting( 'login', 'login_attempts_per_window' ) ) {
		identity_security_kit_log_event( 'login_rate_limited', 'warning' );
		identity_security_kit_redirect( 'login', array( 'login' => 'rate_limited' ) );
	}

	$login    = isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '';
	$password = isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '';
	$remember = isset( $_POST['rememberme'] );
	$user     = wp_authenticate( $login, $password );

	if ( is_wp_error( $user ) ) {
		identity_security_kit_log_event( 'login_failed', 'failure', 0, array( 'reason' => $user->get_error_code() ) );
		identity_security_kit_redirect( 'login', array( 'login' => 'failed' ) );
	}

	$redirect_key = user_can( $user, 'photovault_manage_media' ) || user_can( $user, 'manage_options' ) ? 'dashboard' : 'after_login';
	if ( function_exists( 'identity_security_kit_is_totp_enabled' ) && identity_security_kit_is_totp_enabled( $user->ID ) ) {
		$challenge_url = identity_security_kit_create_login_challenge( $user->ID, $remember, identity_security_kit_get_route_url( $redirect_key ) );
		if ( is_wp_error( $challenge_url ) ) {
			identity_security_kit_log_event( 'login_mfa_challenge_failed', 'failure', $user->ID, array( 'reason' => $challenge_url->get_error_code() ) );
			identity_security_kit_redirect( 'login', array( 'login' => 'failed' ) );
		}
		wp_safe_redirect( $challenge_url );
		exit;
	}

	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, $remember, is_ssl() );
	do_action( 'wp_login', $user->user_login, $user );
	identity_security_kit_log_event( 'login_success', 'success', $user->ID );
	identity_security_kit_redirect( $redirect_key );
}
add_action( 'template_redirect', 'identity_security_kit_handle_login' );

/**
 * Handle front-office password reset requests with anti-enumeration responses.
 */
function identity_security_kit_handle_forgot_password() {
	if ( ! identity_security_kit_is_post_request() || ! isset( $_POST['photovault_forgot_nonce'] ) ) {
		return;
	}

	if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['photovault_forgot_nonce'] ) ), 'photovault_forgot_action' ) ) {
		identity_security_kit_log_event( 'password_reset_nonce_failed', 'failure' );
		identity_security_kit_redirect( 'forgot_password', array( 'forgot' => 'security_failed' ) );
	}
	if ( ! identity_security_kit_rate_limit_by_setting( 'password_reset', 'password_reset_attempts_per_window' ) ) {
		identity_security_kit_log_event( 'password_reset_rate_limited', 'warning' );
		identity_security_kit_redirect( 'forgot_password', array( 'forgot' => 'rate_limited' ) );
	}

	$user_input = isset( $_POST['user_login'] ) ? sanitize_text_field( wp_unslash( $_POST['user_login'] ) ) : '';
	if ( '' === $user_input ) {
		identity_security_kit_log_event( 'password_reset_empty_identifier', 'warning' );
		identity_security_kit_redirect( 'forgot_password', array( 'forgot' => 'fields_required' ) );
	}

	$user = is_email( $user_input ) ? get_user_by( 'email', $user_input ) : get_user_by( 'login', sanitize_user( $user_input ) );
	if ( $user ) {
		identity_security_kit_log_event( 'password_reset_requested', 'info', $user->ID );
		$key = get_password_reset_key( $user );
		if ( is_wp_error( $key ) ) {
			do_action( 'identity_security_kit_password_reset_failed', $key, $user->ID );
		} else {
			$reset_url = network_site_url(
				'wp-login.php?action=rp&key=' . rawurlencode( $key ) . '&login=' . rawurlencode( $user->user_login ),
				'login'
			);
			$subject   = sprintf( __( '[%s] Password reset', 'identity-security-kit' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) );
			$message   = sprintf(
				/* translators: 1: display name, 2: password reset URL. */
				__( "Hello %1$s,\n\nA password reset was requested for your account.\n\nOpen this secure link to choose a new password:\n%2$s\n\nIf you did not request this, you can ignore this email.", 'identity-security-kit' ),
				$user->display_name ? $user->display_name : $user->user_login,
				$reset_url
			);

			if ( ! wp_mail( $user->user_email, $subject, $message ) ) {
				do_action( 'identity_security_kit_password_reset_mail_failed', $user->ID );
			}
		}
	} else {
		identity_security_kit_log_event( 'password_reset_unknown_identifier', 'info' );
	}

	identity_security_kit_redirect( 'forgot_password', array( 'forgot' => 'sent' ) );
}
add_action( 'template_redirect', 'identity_security_kit_handle_forgot_password' );
/**
 * Handle front-office registration submissions.
 */
function identity_security_kit_handle_registration() {
	if ( ! identity_security_kit_is_post_request() || ! isset( $_POST['photovault_register_nonce'] ) ) {
		return;
	}

	if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['photovault_register_nonce'] ) ), 'photovault_register_action' ) ) {
		identity_security_kit_log_event( 'registration_nonce_failed', 'failure' );
		wp_die( esc_html__( 'Security verification failed.', 'identity-security-kit' ) );
	}
	if ( ! identity_security_kit_rate_limit_by_setting( 'registration', 'registration_attempts_per_window' ) ) {
		identity_security_kit_log_event( 'registration_rate_limited', 'warning' );
		identity_security_kit_redirect( 'register', array( 'register' => 'failed', 'err' => 'rate_limited' ) );
	}

	$first_name = isset( $_POST['first_name'] ) ? sanitize_text_field( wp_unslash( $_POST['first_name'] ) ) : '';
	$last_name  = isset( $_POST['last_name'] ) ? sanitize_text_field( wp_unslash( $_POST['last_name'] ) ) : '';
	$username   = isset( $_POST['username'] ) ? sanitize_user( wp_unslash( $_POST['username'] ) ) : '';
	$email      = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
	$phone      = isset( $_POST['phone'] ) ? sanitize_text_field( wp_unslash( $_POST['phone'] ) ) : '';
	$password   = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
	$password_c = isset( $_POST['password_confirm'] ) ? (string) wp_unslash( $_POST['password_confirm'] ) : '';

	$error_code       = '';
	$normalized_phone = '';
	$settings         = identity_security_kit_get_settings();

	if ( empty( $username ) || empty( $email ) || empty( $password ) ) {
		$error_code = 'fields_required';
	} elseif ( ! is_email( $email ) ) {
		$error_code = 'invalid_email';
	}

	if ( '' === $error_code ) {
		if ( ! empty( $settings['phone_required'] ) && '' === trim( $phone ) ) {
			$error_code = 'phone_required';
		} elseif ( '' !== trim( $phone ) ) {
			$phone_validation = identity_security_kit_validate_unique_phone( $phone );
			if ( is_wp_error( $phone_validation ) ) {
				$error_code = $phone_validation->get_error_code();
			} else {
				$normalized_phone = $phone_validation;
			}
		}
	}

	if ( '' === $error_code ) {
		if ( strlen( $password ) < identity_security_kit_get_min_password_length() ) {
			$error_code = 'weak_password';
		} elseif ( $password !== $password_c ) {
			$error_code = 'password_mismatch';
		} elseif ( email_exists( $email ) ) {
			$error_code = 'email_exists';
		} elseif ( username_exists( $username ) ) {
			$error_code = 'username_exists';
		}
	}

	if ( ! empty( $error_code ) ) {
		identity_security_kit_log_event( 'registration_rejected', 'warning', 0, array( 'reason' => $error_code ) );
		identity_security_kit_redirect( 'register', array( 'register' => 'failed', 'err' => $error_code ) );
	}

	$user_id = wp_insert_user(
		array(
			'user_login' => $username,
			'user_email' => $email,
			'user_pass'  => $password,
			'first_name' => $first_name,
			'last_name'  => $last_name,
			'role'       => identity_security_kit_get_registration_role(),
		)
	);

	if ( is_wp_error( $user_id ) ) {
		identity_security_kit_log_event( 'registration_failed', 'failure', 0, array( 'reason' => $user_id->get_error_code() ) );
		identity_security_kit_redirect( 'register', array( 'register' => 'failed', 'err' => 'failed' ) );
	}

	if ( '' !== $normalized_phone ) {
		$phone_result = identity_security_kit_set_user_phone( $user_id, $normalized_phone );
		if ( is_wp_error( $phone_result ) ) {
			identity_security_kit_log_event( 'registration_phone_failed', 'failure', $user_id, array( 'reason' => $phone_result->get_error_code() ) );
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $user_id );
			identity_security_kit_redirect( 'register', array( 'register' => 'failed', 'err' => 'phone_save_failed' ) );
		}
	}

	identity_security_kit_log_event( 'registration_success', 'success', $user_id );

	$verify_status = 'pending';
	if ( function_exists( 'identity_security_kit_create_email_verification_challenge' ) ) {
		$challenge = identity_security_kit_create_email_verification_challenge( $user_id, $email );
		if ( is_wp_error( $challenge ) ) {
			identity_security_kit_log_event( 'registration_email_verification_deferred', 'warning', $user_id, array( 'reason' => $challenge->get_error_code() ) );
			$verify_status = 'deferred';
		}
	}

	wp_set_current_user( $user_id );
	wp_set_auth_cookie( $user_id );
	identity_security_kit_redirect( 'profile', array( 'verify' => $verify_status ) );
}
add_action( 'template_redirect', 'identity_security_kit_handle_registration' );

/**
 * Handle front-office profile updates.
 */
function identity_security_kit_handle_profile_update() {
	if ( ! identity_security_kit_is_post_request() || ! isset( $_POST['photovault_profile_nonce'] ) ) {
		return;
	}

	if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['photovault_profile_nonce'] ) ), 'photovault_profile_action' ) ) {
		identity_security_kit_log_event( 'profile_nonce_failed', 'failure', get_current_user_id() );
		wp_die( esc_html__( 'Security verification failed.', 'identity-security-kit' ) );
	}

	if ( ! is_user_logged_in() ) {
		identity_security_kit_redirect( 'login' );
	}

	$current_user_id = get_current_user_id();
	$current_user    = wp_get_current_user();
	$email           = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
	$phone           = isset( $_POST['phone'] ) ? sanitize_text_field( wp_unslash( $_POST['phone'] ) ) : '';
	$email_changed   = strtolower( $email ) !== strtolower( $current_user->user_email );
	$bio             = isset( $_POST['bio'] ) ? sanitize_textarea_field( wp_unslash( $_POST['bio'] ) ) : '';
	$current_phone   = (string) get_user_meta( $current_user_id, identity_security_kit_phone_meta_key(), true );
	$phone_changed   = '' !== trim( $phone ) && $current_phone !== $phone;
	$settings        = identity_security_kit_get_settings();

	if ( empty( $email ) || ! is_email( $email ) ) {
		identity_security_kit_log_event( 'profile_update_rejected', 'warning', $current_user_id, array( 'reason' => 'invalid_email' ) );
		identity_security_kit_redirect( 'profile', array( 'profile' => 'invalid_email' ) );
	}

	if ( ! empty( $settings['phone_required'] ) && '' === trim( $phone ) ) {
		identity_security_kit_redirect( 'profile', array( 'profile' => 'phone_required' ) );
	}
	$normalized_phone = '';
	if ( '' !== trim( $phone ) ) {
		$phone_validation = identity_security_kit_validate_unique_phone( $phone, $current_user_id );
		if ( is_wp_error( $phone_validation ) ) {
			identity_security_kit_redirect( 'profile', array( 'profile' => sanitize_key( $phone_validation->get_error_code() ) ) );
		}
		$normalized_phone = $phone_validation;
		$phone_changed     = $current_phone !== $normalized_phone;
	}

	$email_owner = email_exists( $email );
	if ( $email_owner && (int) $email_owner !== (int) $current_user_id ) {
		identity_security_kit_log_event( 'profile_update_rejected', 'warning', $current_user_id, array( 'reason' => 'email_exists' ) );
		identity_security_kit_redirect( 'profile', array( 'profile' => 'email_exists' ) );
	}

	$user_data = array(
		'ID'          => $current_user_id,
		'user_email'  => $email,
		'description' => $bio,
	);

	if ( ! empty( $_POST['password'] ) || ! empty( $_POST['password_confirm'] ) ) {
		$current_password = isset( $_POST['current_password'] ) ? (string) wp_unslash( $_POST['current_password'] ) : '';
		$password         = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
		$password_c       = isset( $_POST['password_confirm'] ) ? (string) wp_unslash( $_POST['password_confirm'] ) : '';

		if ( empty( $current_password ) || ! wp_check_password( $current_password, $current_user->user_pass, $current_user_id ) ) {
			identity_security_kit_redirect( 'profile', array( 'profile' => 'current_password_invalid' ) );
		}

		if ( strlen( $password ) < identity_security_kit_get_min_password_length() ) {
			identity_security_kit_redirect( 'profile', array( 'profile' => 'weak_password' ) );
		}

		if ( $password !== $password_c ) {
			identity_security_kit_redirect( 'profile', array( 'profile' => 'pwd_mismatch' ) );
		}

		$user_data['user_pass'] = $password;
	}

	if ( ! empty( $_FILES['profile_avatar']['name'] ) ) {
		require_once ABSPATH . 'wp-admin/includes/image.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';

		$validation = identity_security_kit_validate_uploaded_image_file( $_FILES['profile_avatar'] );
		if ( is_wp_error( $validation ) ) {
			identity_security_kit_redirect( 'profile', array( 'profile' => sanitize_key( $validation->get_error_code() ) ) );
		}

		$attachment_id = media_handle_upload(
			'profile_avatar',
			0,
			array(),
			array( 'mimes' => identity_security_kit_get_allowed_image_mimes() )
		);

		if ( is_wp_error( $attachment_id ) ) {
			identity_security_kit_redirect( 'profile', array( 'profile' => 'avatar_upload_failed' ) );
		}

		$avatar_meta_key = sanitize_key( apply_filters( 'identity_security_kit_avatar_meta_key', 'photovault_avatar_id' ) );
		update_user_meta( $current_user_id, $avatar_meta_key, $attachment_id );
	}

	$result = wp_update_user( $user_data );
	if ( is_wp_error( $result ) ) {
		identity_security_kit_log_event( 'profile_update_failed', 'failure', $current_user_id, array( 'reason' => $result->get_error_code() ) );
		identity_security_kit_redirect( 'profile', array( 'profile' => 'failed' ) );
	}

	if ( '' !== $normalized_phone ) {
		$phone_result = identity_security_kit_set_user_phone( $current_user_id, $normalized_phone );
		if ( is_wp_error( $phone_result ) ) {
			identity_security_kit_redirect( 'profile', array( 'profile' => sanitize_key( $phone_result->get_error_code() ) ) );
		}
		if ( $phone_changed ) {
			update_user_meta( $current_user_id, 'identity_phone_verified', '0' );
		}
	}

	$redirect_args = array( 'profile' => 'success' );

	if ( $email_changed && function_exists( 'identity_security_kit_create_email_verification_challenge' ) ) {
		$challenge = identity_security_kit_create_email_verification_challenge( $current_user_id, $email );
		if ( is_wp_error( $challenge ) ) {
			identity_security_kit_log_event( 'profile_email_verification_deferred', 'warning', $current_user_id, array( 'reason' => $challenge->get_error_code() ) );
			$redirect_args['verify'] = 'deferred';
		} else {
			$redirect_args['verify'] = 'pending';
		}
	}

	if ( isset( $user_data['user_pass'] ) && function_exists( 'identity_security_kit_destroy_other_sessions' ) ) {
		identity_security_kit_destroy_other_sessions( $current_user_id );
	}

	identity_security_kit_log_event( 'profile_update_success', 'success', $current_user_id );

	identity_security_kit_redirect( 'profile', $redirect_args );
}
add_action( 'template_redirect', 'identity_security_kit_handle_profile_update' );