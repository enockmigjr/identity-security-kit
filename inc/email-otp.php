<?php
/**
 * Email OTP delivery and authenticated account controls.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Deliver an email OTP through WordPress mail transport. */
function identity_security_kit_deliver_email_otp( $email, $code, $context ) {
	$user    = get_userdata( absint( $context['user_id'] ?? 0 ) );
	$subject = sprintf( __( '[%s] Your security code', 'identity-security-kit' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) );
	$name = $user && $user->display_name ? $user->display_name : __( 'there', 'identity-security-kit' );
	$sent = identity_security_kit_send_transactional_email(
		$email,
		$subject,
		array(
			'preheader' => __( 'Your one-time security code is ready.', 'identity-security-kit' ),
			'title'     => __( 'Your security code', 'identity-security-kit' ),
			'greeting'  => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $name ),
			'intro'     => __( 'Use this code to complete the security check.', 'identity-security-kit' ),
			'code'      => $code,
			'details'   => array( sprintf( __( 'It expires in %d minutes and can only be used once. Never share this code.', 'identity-security-kit' ), absint( $context['ttl_minutes'] ?? 10 ) ) ),
			'notice'    => __( 'If you did not request this code, ignore this email.', 'identity-security-kit' ),
		)
	);

	return $sent ? true : new WP_Error( 'otp_delivery_failed', __( 'The verification code could not be sent.', 'identity-security-kit' ) );
}

/** Create an email OTP bound to the account's current address. */
function identity_security_kit_create_email_otp_challenge( $user_id, $purpose = 'account_verification' ) {
	$user = get_userdata( absint( $user_id ) );
	if ( ! $user || ! is_email( $user->user_email ) ) {
		return new WP_Error( 'invalid_otp_destination', __( 'A valid account email is required.', 'identity-security-kit' ) );
	}

	return identity_security_kit_create_otp_challenge( $user->ID, $purpose, 'email', $user->user_email, 'identity_security_kit_deliver_email_otp' );
}

/** Verify an email OTP against the current account address. */
function identity_security_kit_verify_email_otp_challenge( $challenge_id, $user_id, $code, $purpose = 'account_verification' ) {
	$user = get_userdata( absint( $user_id ) );
	if ( ! $user || ! is_email( $user->user_email ) ) {
		return new WP_Error( 'invalid_otp_destination', __( 'A valid account email is required.', 'identity-security-kit' ) );
	}
	$result = identity_security_kit_verify_otp_challenge( $challenge_id, $user->ID, $code, $purpose, 'email', $user->user_email );
	if ( ! is_wp_error( $result ) ) {
		update_user_meta( $user->ID, 'identity_email_otp_verified_at', gmdate( 'Y-m-d H:i:s' ) );
		do_action( 'identity_security_kit_email_otp_verified', $user->ID, identity_security_kit_normalize_otp_purpose( $purpose ), absint( $challenge_id ) );
	}

	return $result;
}

/** Redirect an authenticated email OTP action to the account route. */
function identity_security_kit_email_otp_redirect( $args ) {
	$routes = identity_security_kit_get_routes();
	$target = isset( $routes['profile'] ) ? $routes['profile'] : home_url( '/' );

	wp_safe_redirect( add_query_arg( $args, $target ) );
	exit;
}

/** Handle an authenticated request for a new email OTP. */
function identity_security_kit_handle_email_otp_request() {
	if ( ! is_user_logged_in() ) {
		auth_redirect();
	}
	$purpose = isset( $_POST['purpose'] ) ? identity_security_kit_normalize_otp_purpose( wp_unslash( $_POST['purpose'] ) ) : 'account_verification';
	check_admin_referer( 'identity_security_kit_email_otp_request_' . $purpose );
	$result = identity_security_kit_create_email_otp_challenge( get_current_user_id(), $purpose );
	identity_security_kit_email_otp_redirect( array( 'otp' => is_wp_error( $result ) ? sanitize_key( $result->get_error_code() ) : 'sent', 'challenge' => is_wp_error( $result ) ? 0 : absint( $result ) ) );
}
add_action( 'admin_post_identity_security_kit_email_otp_request', 'identity_security_kit_handle_email_otp_request' );

/** Handle an authenticated email OTP verification submission. */
function identity_security_kit_handle_email_otp_verify() {
	if ( ! is_user_logged_in() ) {
		auth_redirect();
	}
	$challenge_id = isset( $_POST['challenge_id'] ) ? absint( $_POST['challenge_id'] ) : 0;
	$purpose      = isset( $_POST['purpose'] ) ? identity_security_kit_normalize_otp_purpose( wp_unslash( $_POST['purpose'] ) ) : 'account_verification';
	check_admin_referer( 'identity_security_kit_email_otp_verify_' . $purpose );
	$code   = isset( $_POST['otp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['otp_code'] ) ) : '';
	$result = identity_security_kit_verify_email_otp_challenge( $challenge_id, get_current_user_id(), $code, $purpose );
	identity_security_kit_email_otp_redirect( array( 'otp' => is_wp_error( $result ) ? sanitize_key( $result->get_error_code() ) : 'verified', 'challenge' => is_wp_error( $result ) ? $challenge_id : 0 ) );
}
add_action( 'admin_post_identity_security_kit_email_otp_verify', 'identity_security_kit_handle_email_otp_verify' );

/** Render a reusable authenticated email OTP form. */
function identity_security_kit_render_email_otp_shortcode( $attributes ) {
	if ( ! is_user_logged_in() ) {
		return '';
	}
	$attributes   = shortcode_atts( array( 'purpose' => 'account_verification' ), $attributes, 'identity_security_email_otp' );
	$purpose      = identity_security_kit_normalize_otp_purpose( $attributes['purpose'] );
	$challenge_id = isset( $_GET['challenge'] ) ? absint( $_GET['challenge'] ) : 0;
	ob_start();
	if ( $challenge_id ) :
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_email_otp_verify"><input type="hidden" name="challenge_id" value="<?php echo esc_attr( $challenge_id ); ?>"><input type="hidden" name="purpose" value="<?php echo esc_attr( $purpose ); ?>"><?php wp_nonce_field( 'identity_security_kit_email_otp_verify_' . $purpose ); ?><label><?php esc_html_e( 'Security code', 'identity-security-kit' ); ?> <input name="otp_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" required></label><button type="submit"><?php esc_html_e( 'Verify code', 'identity-security-kit' ); ?></button></form>
		<?php
	else :
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_email_otp_request"><input type="hidden" name="purpose" value="<?php echo esc_attr( $purpose ); ?>"><?php wp_nonce_field( 'identity_security_kit_email_otp_request_' . $purpose ); ?><button type="submit"><?php esc_html_e( 'Send a security code by email', 'identity-security-kit' ); ?></button></form>
		<?php
	endif;

	return (string) ob_get_clean();
}
add_shortcode( 'identity_security_email_otp', 'identity_security_kit_render_email_otp_shortcode' );
