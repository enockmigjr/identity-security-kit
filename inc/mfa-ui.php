<?php
/**
 * MFA account actions and user interfaces for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Redirect an MFA action to its safe referrer or the native profile page.
 *
 * @param array<string,string> $args Query arguments.
 */
function identity_security_kit_mfa_redirect( $args ) {
	$target = wp_get_referer();
	if ( ! $target ) {
		$target = admin_url( 'profile.php#identity-security-mfa' );
	}
	wp_safe_redirect( add_query_arg( $args, $target ) );
	exit;
}

/**
 * Ensure an MFA action targets the authenticated account.
 *
 * @return int
 */
function identity_security_kit_require_authenticated_user() {
	if ( ! is_user_logged_in() ) {
		auth_redirect();
	}

	return get_current_user_id();
}

/** Start TOTP enrollment after password confirmation. */
function identity_security_kit_handle_totp_start() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_totp_start' );
	$password = isset( $_POST['current_password'] ) ? (string) wp_unslash( $_POST['current_password'] ) : '';
	$user     = get_userdata( $user_id );
	if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'password_invalid' ) );
	}
	$result = identity_security_kit_begin_totp_enrollment( $user_id );
	identity_security_kit_mfa_redirect( array( 'mfa' => is_wp_error( $result ) ? $result->get_error_code() : 'enrollment_started' ) );
}
add_action( 'admin_post_identity_security_kit_totp_start', 'identity_security_kit_handle_totp_start' );

/** Confirm TOTP enrollment. */
function identity_security_kit_handle_totp_confirm() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_totp_confirm' );
	$code   = isset( $_POST['otp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['otp_code'] ) ) : '';
	$result = identity_security_kit_confirm_totp_enrollment( $user_id, $code );
	if ( is_wp_error( $result ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => $result->get_error_code() ) );
	}
	$token = identity_security_kit_store_recovery_display( $user_id, $result );
	identity_security_kit_mfa_redirect( array( 'mfa' => 'enabled', 'recovery' => is_wp_error( $token ) ? '' : $token ) );
}
add_action( 'admin_post_identity_security_kit_totp_confirm', 'identity_security_kit_handle_totp_confirm' );

/** Cancel a pending TOTP enrollment. */
function identity_security_kit_handle_totp_cancel() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_totp_cancel' );
	delete_user_meta( $user_id, 'identity_mfa_totp_pending' );
	identity_security_kit_log_event( 'totp_enrollment_cancelled', 'info', $user_id );
	identity_security_kit_mfa_redirect( array( 'mfa' => 'cancelled' ) );
}
add_action( 'admin_post_identity_security_kit_totp_cancel', 'identity_security_kit_handle_totp_cancel' );

/** Regenerate recovery codes after factor verification. */
function identity_security_kit_handle_recovery_regenerate() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_recovery_regenerate' );
	$code   = isset( $_POST['mfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mfa_code'] ) ) : '';
	$verify = identity_security_kit_verify_totp_or_recovery( $user_id, $code );
	if ( is_wp_error( $verify ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => $verify->get_error_code() ) );
	}
	$codes = identity_security_kit_generate_recovery_codes( $user_id );
	$token = is_wp_error( $codes ) ? $codes : identity_security_kit_store_recovery_display( $user_id, $codes );
	identity_security_kit_mfa_redirect( array( 'mfa' => is_wp_error( $token ) ? $token->get_error_code() : 'recovery_regenerated', 'recovery' => is_wp_error( $token ) ? '' : $token ) );
}
add_action( 'admin_post_identity_security_kit_recovery_regenerate', 'identity_security_kit_handle_recovery_regenerate' );

/** Disable TOTP after password and factor verification. */
function identity_security_kit_handle_totp_disable() {
	$user_id = identity_security_kit_require_authenticated_user();
	check_admin_referer( 'identity_security_kit_totp_disable' );
	$user     = get_userdata( $user_id );
	$password = isset( $_POST['current_password'] ) ? (string) wp_unslash( $_POST['current_password'] ) : '';
	$code     = isset( $_POST['mfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mfa_code'] ) ) : '';
	if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => 'password_invalid' ) );
	}
	$allowed = identity_security_kit_can_disable_mfa_method( $user_id, 'totp' );
	if ( is_wp_error( $allowed ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => $allowed->get_error_code() ) );
	}
	$verify = identity_security_kit_verify_totp_or_recovery( $user_id, $code );
	if ( is_wp_error( $verify ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => $verify->get_error_code() ) );
	}
	$result = identity_security_kit_disable_mfa_method( $user_id, 'totp' );
	if ( is_wp_error( $result ) ) {
		identity_security_kit_mfa_redirect( array( 'mfa' => $result->get_error_code() ) );
	}
	identity_security_kit_mfa_redirect( array( 'mfa' => 'disabled' ) );
}
add_action( 'admin_post_identity_security_kit_totp_disable', 'identity_security_kit_handle_totp_disable' );

/**
 * Render the reusable account MFA panel.
 *
 * @return string
 */
function identity_security_kit_render_mfa_panel() {
	if ( ! is_user_logged_in() ) {
		return '';
	}
	$user_id       = get_current_user_id();
	$enabled       = identity_security_kit_is_totp_enabled( $user_id );
	$pending       = identity_security_kit_get_pending_totp_secret( $user_id );
	$pending_valid = ! is_wp_error( $pending );
	$recovery      = isset( $_GET['recovery'] ) ? sanitize_text_field( wp_unslash( $_GET['recovery'] ) ) : '';
	$codes         = $recovery ? identity_security_kit_take_recovery_display( $user_id, $recovery ) : array();
	$remaining     = get_user_meta( $user_id, 'identity_mfa_recovery_codes', true );
	$remaining     = is_array( $remaining ) ? count( $remaining ) : 0;
	$status        = isset( $_GET['mfa'] ) ? sanitize_key( wp_unslash( $_GET['mfa'] ) ) : '';
	$messages      = array(
		'enrollment_started'    => __( 'Enter a current authenticator code to finish setup.', 'identity-security-kit' ),
		'enabled'               => __( 'Two-factor authentication is enabled.', 'identity-security-kit' ),
		'cancelled'             => __( 'Authenticator enrollment was cancelled.', 'identity-security-kit' ),
		'disabled'              => __( 'Authenticator verification was disabled.', 'identity-security-kit' ),
		'recovery_regenerated'  => __( 'New recovery codes were generated.', 'identity-security-kit' ),
		'required'              => __( 'Two-factor authentication is required before privileged access can continue.', 'identity-security-kit' ),
		'password_invalid'      => __( 'The current password is incorrect.', 'identity-security-kit' ),
		'totp_invalid'          => __( 'The authenticator code is invalid.', 'identity-security-kit' ),
		'totp_replayed'         => __( 'This authenticator code was already used.', 'identity-security-kit' ),
		'recovery_code_invalid' => __( 'The recovery code is invalid.', 'identity-security-kit' ),
		'mfa_rate_limited'      => __( 'Too many attempts. Try again later.', 'identity-security-kit' ),
		'channel_code_sent'     => __( 'A security code was sent. Enter it to enable the method.', 'identity-security-kit' ),
		'disable_code_sent'     => __( 'A security code was sent. Enter it to disable the method.', 'identity-security-kit' ),
		'preference_saved'      => __( 'Preferred verification method saved.', 'identity-security-kit' ),
		'method_not_allowed'    => __( 'This verification method is not allowed.', 'identity-security-kit' ),
		'method_not_enabled'    => __( 'This verification method is not enabled.', 'identity-security-kit' ),
		'mfa_last_factor_required' => __( 'This account must keep at least one verification method.', 'identity-security-kit' ),
		'email_not_verified'    => __( 'Verify the account email before enabling email MFA.', 'identity-security-kit' ),
		'phone_not_verified'    => __( 'Verify the phone number before enabling SMS MFA.', 'identity-security-kit' ),
		'sms_provider_not_configured' => __( 'The SMS provider is not configured.', 'identity-security-kit' ),
	);

	ob_start();
	?>
	<div id="identity-security-mfa" class="identity-security-mfa">
		<h2><?php esc_html_e( 'Two-factor authentication', 'identity-security-kit' ); ?></h2>
		<?php if ( $status && isset( $messages[ $status ] ) ) : ?><div class="notice notice-info"><p><?php echo esc_html( $messages[ $status ] ); ?></p></div><?php endif; ?>
		<?php if ( $codes ) : ?>
			<div class="notice notice-warning"><p><strong><?php esc_html_e( 'Save these recovery codes now. They will not be shown again.', 'identity-security-kit' ); ?></strong></p><ul><?php foreach ( $codes as $recovery_code ) : ?><li><code><?php echo esc_html( $recovery_code ); ?></code></li><?php endforeach; ?></ul></div>
		<?php endif; ?>
		<?php if ( $enabled ) : ?>
			<p><?php esc_html_e( 'Authenticator verification is enabled.', 'identity-security-kit' ); ?> <?php echo esc_html( sprintf( __( '%d recovery codes remain.', 'identity-security-kit' ), $remaining ) ); ?></p>
			<details><summary><?php esc_html_e( 'Replace recovery codes', 'identity-security-kit' ); ?></summary>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_recovery_regenerate"><?php wp_nonce_field( 'identity_security_kit_recovery_regenerate' ); ?><label><?php esc_html_e( 'Authenticator or recovery code', 'identity-security-kit' ); ?> <input name="mfa_code" autocomplete="one-time-code" required></label> <button type="submit"><?php esc_html_e( 'Replace codes', 'identity-security-kit' ); ?></button></form>
			</details>
			<details><summary><?php esc_html_e( 'Disable authenticator verification', 'identity-security-kit' ); ?></summary>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_totp_disable"><?php wp_nonce_field( 'identity_security_kit_totp_disable' ); ?><label><?php esc_html_e( 'Current password', 'identity-security-kit' ); ?> <input type="password" name="current_password" autocomplete="current-password" required></label> <label><?php esc_html_e( 'Authenticator or recovery code', 'identity-security-kit' ); ?> <input name="mfa_code" autocomplete="one-time-code" required></label> <button type="submit"><?php esc_html_e( 'Disable', 'identity-security-kit' ); ?></button></form>
			</details>
		<?php elseif ( $pending_valid ) : ?>
			<?php $uri = identity_security_kit_get_totp_uri( $user_id, $pending ); ?>
			<p><?php esc_html_e( 'Add this account manually to your authenticator application, then confirm a code.', 'identity-security-kit' ); ?></p>
			<p><code><?php echo esc_html( $pending ); ?></code></p>
			<?php if ( ! is_wp_error( $uri ) ) : ?><p><a href="<?php echo esc_url( $uri, array( 'otpauth' ) ); ?>"><?php esc_html_e( 'Open in an authenticator application', 'identity-security-kit' ); ?></a></p><?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_totp_confirm"><?php wp_nonce_field( 'identity_security_kit_totp_confirm' ); ?><label><?php esc_html_e( 'Six-digit code', 'identity-security-kit' ); ?> <input name="otp_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label> <button type="submit"><?php esc_html_e( 'Enable', 'identity-security-kit' ); ?></button></form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_totp_cancel"><?php wp_nonce_field( 'identity_security_kit_totp_cancel' ); ?><button type="submit"><?php esc_html_e( 'Cancel enrollment', 'identity-security-kit' ); ?></button></form>
		<?php else : ?>
			<p><?php esc_html_e( 'Use any RFC 6238 compatible authenticator application.', 'identity-security-kit' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="identity_security_kit_totp_start"><?php wp_nonce_field( 'identity_security_kit_totp_start' ); ?><label><?php esc_html_e( 'Current password', 'identity-security-kit' ); ?> <input type="password" name="current_password" autocomplete="current-password" required></label> <button type="submit"><?php esc_html_e( 'Configure authenticator', 'identity-security-kit' ); ?></button></form>
		<?php endif; ?>
		<?php echo identity_security_kit_render_mfa_channels_panel(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>
	<?php

	return (string) ob_get_clean();
}

/** Render the MFA panel shortcode. */
function identity_security_kit_render_mfa_shortcode() {
	return identity_security_kit_render_mfa_panel();
}
add_shortcode( 'identity_security_mfa', 'identity_security_kit_render_mfa_shortcode' );

/** Add the generic MFA panel to the native user profile. */
function identity_security_kit_render_native_profile_mfa() {
	echo identity_security_kit_render_mfa_panel(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Panel escapes dynamic values at render time.
}
add_action( 'show_user_profile', 'identity_security_kit_render_native_profile_mfa' );
