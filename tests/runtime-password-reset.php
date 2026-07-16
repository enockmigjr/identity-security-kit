<?php
/** WordPress runtime verification for branded password reset delivery. */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

require_once ABSPATH . 'wp-admin/includes/user.php';

function identity_password_reset_runtime_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

$suffix  = strtolower( wp_generate_password( 8, false, false ) );
$user_id = wp_insert_user( array( 'user_login' => 'identity_reset_' . $suffix, 'user_pass' => wp_generate_password( 24 ), 'user_email' => 'identity-reset-' . $suffix . '@photovault.test', 'display_name' => 'Reset Runtime' ) );

try {
	identity_password_reset_runtime_assert( ! is_wp_error( $user_id ), 'Runtime reset user could not be created.' );
	$user = get_userdata( $user_id );
	$key  = get_password_reset_key( $user );
	identity_password_reset_runtime_assert( ! is_wp_error( $key ), 'Password reset key could not be generated.' );
	$url = identity_security_kit_get_password_reset_url( $user, $key );
	identity_password_reset_runtime_assert( false !== strpos( $url, '/reset-password/' ) && false === strpos( $url, 'wp-login.php' ), 'Reset URL did not use the branded frontend route.' );

	$email = identity_security_kit_filter_password_reset_notification( array( 'to' => $user->user_email, 'subject' => 'Native', 'message' => 'Native', 'headers' => '' ), $key, $user->user_login, $user );
	identity_password_reset_runtime_assert( false !== strpos( $email['message'], '<table role="presentation"' ), 'Native reset email did not use the professional HTML layout.' );
	identity_password_reset_runtime_assert( false !== strpos( $email['message'], '/reset-password/' ) && false !== strpos( $email['headers'], 'text/html' ), 'Native reset email lost its frontend link or HTML header.' );
	identity_password_reset_runtime_assert( check_password_reset_key( $key, $user->user_login ) instanceof WP_User, 'Generated frontend reset key was not accepted by WordPress.' );
	$admin_email = identity_security_kit_filter_admin_password_change_email( array( 'to' => get_option( 'admin_email' ), 'subject' => '[%s] Password Changed', 'message' => 'Native', 'headers' => '' ), $user, get_option( 'blogname' ) );
	identity_password_reset_runtime_assert( false !== strpos( $admin_email['message'], '<table role="presentation"' ) && false !== strpos( $admin_email['headers'], 'text/html' ), 'Administrator password-change notice did not use the professional HTML layout.' );

	echo wp_json_encode( array( 'native_email' => 'professional_html', 'admin_notice' => 'professional_html', 'reset_route' => 'frontend', 'key_validation' => 'wordpress_native' ) );
} finally {
	if ( ! is_wp_error( $user_id ) ) {
		wp_delete_user( $user_id );
	}
}
