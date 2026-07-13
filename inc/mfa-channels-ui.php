<?php
/**
 * Email and SMS MFA enrollment controls.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Render one remote factor enrollment or removal form. */
function identity_security_kit_render_remote_factor_enrollment( $user_id, $method, $challenge_method, $challenge_id, $disable_method, $disable_challenge_id ) {
	if ( identity_security_kit_is_mfa_method_enabled( $user_id, $method ) ) {
		ob_start();
		?>
		<p><?php echo esc_html( sprintf( __( '%s is enabled.', 'identity-security-kit' ), identity_security_kit_get_mfa_method_label( $method ) ) ); ?></p>
		<?php if ( $method === $disable_method && $disable_challenge_id ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="identity_security_kit_channel_mfa_disable_confirm">
				<input type="hidden" name="mfa_method" value="<?php echo esc_attr( $method ); ?>">
				<input type="hidden" name="challenge_id" value="<?php echo esc_attr( $disable_challenge_id ); ?>">
				<?php wp_nonce_field( 'identity_security_kit_channel_mfa_disable_confirm' ); ?>
				<label><?php esc_html_e( 'Security code', 'identity-security-kit' ); ?> <input name="otp_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" required></label>
				<button type="submit"><?php echo esc_html( sprintf( __( 'Confirm removal of %s', 'identity-security-kit' ), identity_security_kit_get_mfa_method_label( $method ) ) ); ?></button>
			</form>
		<?php else : ?>
			<details><summary><?php echo esc_html( sprintf( __( 'Disable %s', 'identity-security-kit' ), identity_security_kit_get_mfa_method_label( $method ) ) ); ?></summary>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="identity_security_kit_channel_mfa_disable_start">
					<input type="hidden" name="mfa_method" value="<?php echo esc_attr( $method ); ?>">
					<?php wp_nonce_field( 'identity_security_kit_channel_mfa_disable_start' ); ?>
					<label><?php esc_html_e( 'Current password', 'identity-security-kit' ); ?> <input type="password" name="current_password" autocomplete="current-password" required></label>
					<button type="submit"><?php esc_html_e( 'Send confirmation code', 'identity-security-kit' ); ?></button>
				</form>
			</details>
		<?php endif; ?>
		<?php
		return (string) ob_get_clean();
	}
	if ( $method === $challenge_method && $challenge_id ) {
		ob_start();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="identity_security_kit_channel_mfa_confirm">
			<input type="hidden" name="mfa_method" value="<?php echo esc_attr( $method ); ?>">
			<input type="hidden" name="challenge_id" value="<?php echo esc_attr( $challenge_id ); ?>">
			<?php wp_nonce_field( 'identity_security_kit_channel_mfa_confirm' ); ?>
			<label><?php esc_html_e( 'Security code', 'identity-security-kit' ); ?> <input name="otp_code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" required></label>
			<button type="submit"><?php echo esc_html( sprintf( __( 'Enable %s', 'identity-security-kit' ), identity_security_kit_get_mfa_method_label( $method ) ) ); ?></button>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	ob_start();
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<input type="hidden" name="action" value="identity_security_kit_channel_mfa_start">
		<input type="hidden" name="mfa_method" value="<?php echo esc_attr( $method ); ?>">
		<?php wp_nonce_field( 'identity_security_kit_channel_mfa_start' ); ?>
		<label><?php esc_html_e( 'Current password', 'identity-security-kit' ); ?> <input type="password" name="current_password" autocomplete="current-password" required></label>
		<button type="submit"><?php echo esc_html( sprintf( __( 'Configure %s', 'identity-security-kit' ), identity_security_kit_get_mfa_method_label( $method ) ) ); ?></button>
	</form>
	<?php

	return (string) ob_get_clean();
}

/** Render remote factors and preferred-method controls. */
function identity_security_kit_render_mfa_channels_panel() {
	$user_id         = get_current_user_id();
	$allowed         = identity_security_kit_get_allowed_mfa_methods( $user_id );
	$enabled         = identity_security_kit_get_user_mfa_methods( $user_id );
	$preferred       = identity_security_kit_get_preferred_mfa_method( $user_id );
	$challenge_method = isset( $_GET['mfa_enroll_method'] ) ? sanitize_key( wp_unslash( $_GET['mfa_enroll_method'] ) ) : '';
	$challenge_id    = isset( $_GET['mfa_enroll_challenge'] ) ? absint( $_GET['mfa_enroll_challenge'] ) : 0;
	$disable_method  = isset( $_GET['mfa_disable_method'] ) ? sanitize_key( wp_unslash( $_GET['mfa_disable_method'] ) ) : '';
	$disable_challenge_id = isset( $_GET['mfa_disable_challenge'] ) ? absint( $_GET['mfa_disable_challenge'] ) : 0;
	ob_start();
	?>
	<section class="identity-security-mfa-channels">
		<h3><?php esc_html_e( 'Additional verification methods', 'identity-security-kit' ); ?></h3>
		<?php if ( in_array( 'email', $allowed, true ) ) : ?>
			<h4><?php esc_html_e( 'Email security code', 'identity-security-kit' ); ?></h4>
			<?php if ( function_exists( 'identity_security_kit_is_email_verified' ) && identity_security_kit_is_email_verified( $user_id ) ) : ?>
				<?php echo identity_security_kit_render_remote_factor_enrollment( $user_id, 'email', $challenge_method, $challenge_id, $disable_method, $disable_challenge_id ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php else : ?><p><?php esc_html_e( 'Verify your account email before enabling this method.', 'identity-security-kit' ); ?></p><?php endif; ?>
		<?php endif; ?>

		<?php if ( in_array( 'sms', $allowed, true ) ) : ?>
			<?php echo identity_security_kit_render_phone_verification_panel(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php if ( identity_security_kit_is_phone_verified( $user_id ) ) : ?>
				<?php echo identity_security_kit_render_remote_factor_enrollment( $user_id, 'sms', $challenge_method, $challenge_id, $disable_method, $disable_challenge_id ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php endif; ?>
		<?php endif; ?>

		<?php if ( count( $enabled ) > 1 ) : ?>
			<h4><?php esc_html_e( 'Preferred verification method', 'identity-security-kit' ); ?></h4>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="identity_security_kit_mfa_preference">
				<?php wp_nonce_field( 'identity_security_kit_mfa_preference' ); ?>
				<select name="mfa_method"><?php foreach ( $enabled as $method ) : ?><option value="<?php echo esc_attr( $method ); ?>" <?php selected( $preferred, $method ); ?>><?php echo esc_html( identity_security_kit_get_mfa_method_label( $method ) ); ?></option><?php endforeach; ?></select>
				<label><?php esc_html_e( 'Current password', 'identity-security-kit' ); ?> <input type="password" name="current_password" autocomplete="current-password" required></label>
				<button type="submit"><?php esc_html_e( 'Save preference', 'identity-security-kit' ); ?></button>
			</form>
		<?php endif; ?>
	</section>
	<?php

	return (string) ob_get_clean();
}
