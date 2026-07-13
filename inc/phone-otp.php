<?php
/**
 * Phone verification and SMS OTP wrappers.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return whether the current stored phone was verified. */
function identity_security_kit_is_phone_verified( $user_id ) {
	$phone = (string) get_user_meta( absint( $user_id ), identity_security_kit_phone_meta_key(), true );
	$hash  = (string) get_user_meta( absint( $user_id ), 'identity_phone_verified_hash', true );

	return '' !== $phone && '1' === (string) get_user_meta( absint( $user_id ), 'identity_phone_verified', true ) && hash_equals( $hash, identity_security_kit_hash_otp_destination( $phone ) );
}

/** Deliver an SMS OTP without logging the code or full destination. */
function identity_security_kit_deliver_phone_otp( $phone, $code, $context ) {
	$message = sprintf(
		/* translators: 1: website name, 2: OTP code, 3: expiry in minutes. */
		__( '%1$s security code: %2$s. Expires in %3$d minutes. Never share this code.', 'identity-security-kit' ),
		wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ),
		$code,
		absint( $context['ttl_minutes'] ?? 10 )
	);

	return identity_security_kit_send_sms( $phone, $message, $context );
}

/** Create a phone OTP challenge for the current canonical number. */
function identity_security_kit_create_phone_otp_challenge( $user_id, $purpose = 'verify_phone' ) {
	$user_id = absint( $user_id );
	$phone   = (string) get_user_meta( $user_id, identity_security_kit_phone_meta_key(), true );
	if ( is_wp_error( identity_security_kit_normalize_phone( $phone ) ) ) {
		return new WP_Error( 'invalid_otp_destination', __( 'A valid international phone number is required.', 'identity-security-kit' ) );
	}
	if ( ! identity_security_kit_sms_provider_available() ) {
		return new WP_Error( 'sms_provider_not_configured', __( 'Phone verification is unavailable until an SMS provider is configured.', 'identity-security-kit' ) );
	}

	return identity_security_kit_create_otp_challenge( $user_id, $purpose, 'sms', $phone, 'identity_security_kit_deliver_phone_otp' );
}

/** Verify a phone OTP and mark the matching canonical number verified. */
function identity_security_kit_verify_phone_otp_challenge( $challenge_id, $user_id, $code, $purpose = 'verify_phone' ) {
	$user_id = absint( $user_id );
	$phone   = (string) get_user_meta( $user_id, identity_security_kit_phone_meta_key(), true );
	$result  = identity_security_kit_verify_otp_challenge( $challenge_id, $user_id, $code, $purpose, 'sms', $phone );
	if ( is_wp_error( $result ) ) {
		return $result;
	}
	if ( 'verify_phone' === identity_security_kit_normalize_otp_purpose( $purpose ) ) {
		$verified_at = gmdate( 'Y-m-d H:i:s' );
		update_user_meta( $user_id, 'identity_phone_verified', '1' );
		update_user_meta( $user_id, 'identity_phone_verified_at', $verified_at );
		update_user_meta( $user_id, 'identity_phone_verified_hash', identity_security_kit_hash_otp_destination( $phone ) );
		identity_security_kit_log_event( 'phone_verified', 'success', $user_id, array( 'phone' => identity_security_kit_mask_phone( $phone ) ) );
		do_action( 'identity_security_kit_phone_verified', $user_id );
	}

	return true;
}

/** Redirect phone verification actions to the account security page. */
function identity_security_kit_phone_otp_redirect( $args ) {
	$target = wp_get_referer();
	if ( ! $target ) {
		$target = identity_security_kit_get_route_url( 'profile' );
	}
	wp_safe_redirect( add_query_arg( $args, $target ) );
	exit;
}

/** Request an authenticated phone verification challenge. */
function identity_security_kit_handle_phone_otp_request() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_phone_otp_request' );
	$result = identity_security_kit_create_phone_otp_challenge( $user_id, 'verify_phone' );
	identity_security_kit_phone_otp_redirect( array( 'phone_otp' => is_wp_error( $result ) ? sanitize_key( $result->get_error_code() ) : 'sent', 'phone_challenge' => is_wp_error( $result ) ? 0 : absint( $result ) ) );
}
add_action( 'admin_post_identity_security_kit_phone_otp_request', 'identity_security_kit_handle_phone_otp_request' );

/** Verify an authenticated phone challenge. */
function identity_security_kit_handle_phone_otp_verify() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_phone_otp_verify' );
	$challenge_id = isset( $_POST['challenge_id'] ) ? absint( $_POST['challenge_id'] ) : 0;
	$code         = isset( $_POST['otp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['otp_code'] ) ) : '';
	$result       = identity_security_kit_verify_phone_otp_challenge( $challenge_id, $user_id, $code, 'verify_phone' );
	identity_security_kit_phone_otp_redirect( array( 'phone_otp' => is_wp_error( $result ) ? sanitize_key( $result->get_error_code() ) : 'verified' ) );
}
add_action( 'admin_post_identity_security_kit_phone_otp_verify', 'identity_security_kit_handle_phone_otp_verify' );

/** Render the phone verification controls for the authenticated user. */
function identity_security_kit_render_phone_verification_panel() {
	if ( ! is_user_logged_in() ) {
		return '';
	}
	$user_id       = get_current_user_id();
	$phone         = (string) get_user_meta( $user_id, identity_security_kit_phone_meta_key(), true );
	$challenge_id  = isset( $_GET['phone_challenge'] ) ? absint( $_GET['phone_challenge'] ) : 0;
	$status        = isset( $_GET['phone_otp'] ) ? sanitize_key( wp_unslash( $_GET['phone_otp'] ) ) : '';
	ob_start();
	?>
	<div class="identity-security-phone-verification">
		<h3><?php esc_html_e( 'Phone verification', 'identity-security-kit' ); ?></h3>
		<?php if ( identity_security_kit_is_phone_verified( $user_id ) ) : ?>
			<p><?php echo esc_html( sprintf( __( 'Verified: %s', 'identity-security-kit' ), identity_security_kit_mask_phone( $phone ) ) ); ?></p>
		<?php elseif ( '' === $phone ) : ?>
			<p><?php esc_html_e( 'Add an international phone number to your profile first.', 'identity-security-kit' ); ?></p>
		<?php elseif ( ! identity_security_kit_sms_provider_available() ) : ?>
			<p><?php esc_html_e( 'Phone verification is not available until an SMS provider is configured.', 'identity-security-kit' ); ?></p>
		<?php elseif ( $challenge_id ) : ?>
			<p><?php echo esc_html( sprintf( __( 'A code was sent to %s.', 'identity-security-kit' ), identity_security_kit_mask_phone( $phone ) ) ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_phone_otp_verify"><input type="hidden" name="challenge_id" value="<?php echo esc_attr( $challenge_id ); ?>"><?php wp_nonce_field( 'identity_security_kit_phone_otp_verify' ); ?><label><?php esc_html_e( 'SMS code', 'identity-security-kit' ); ?> <input name="otp_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" required></label> <button type="submit"><?php esc_html_e( 'Verify phone', 'identity-security-kit' ); ?></button></form>
		<?php else : ?>
			<?php if ( $status ) : ?><p><?php esc_html_e( 'The phone verification request could not be completed. Try again later.', 'identity-security-kit' ); ?></p><?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_phone_otp_request"><?php wp_nonce_field( 'identity_security_kit_phone_otp_request' ); ?><button type="submit"><?php esc_html_e( 'Send phone verification code', 'identity-security-kit' ); ?></button></form>
		<?php endif; ?>
	</div>
	<?php

	return (string) ob_get_clean();
}
add_shortcode( 'identity_security_phone_verification', 'identity_security_kit_render_phone_verification_panel' );
