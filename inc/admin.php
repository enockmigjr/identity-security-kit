<?php
/**
 * Admin interface for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Register Identity Kit admin screens.
 */
function identity_security_kit_register_admin_menu() {
	add_menu_page(
		__( 'Identity Kit', 'identity-security-kit' ),
		__( 'Identity Kit', 'identity-security-kit' ),
		'identity_manage_settings',
		'identity-security-kit',
		'identity_security_kit_render_admin_page',
		'dashicons-shield-alt',
		57
	);

	add_submenu_page(
		'identity-security-kit',
		__( 'Overview', 'identity-security-kit' ),
		__( 'Overview', 'identity-security-kit' ),
		'identity_manage_settings',
		'identity-security-kit',
		'identity_security_kit_render_admin_page'
	);

	add_submenu_page(
		'identity-security-kit',
		__( 'Security audit', 'identity-security-kit' ),
		__( 'Security audit', 'identity-security-kit' ),
		'identity_view_security_audit',
		'identity-security-kit-audit',
		'identity_security_kit_render_audit_page'
	);
}
add_action( 'admin_menu', 'identity_security_kit_register_admin_menu' );

/**
 * Count users with a PhotoVault-compatible avatar meta key.
 *
 * @return int
 */
function identity_security_kit_count_profile_avatars() {
	global $wpdb;

	$meta_key = sanitize_key( apply_filters( 'identity_security_kit_avatar_meta_key', 'photovault_avatar_id' ) );

	return (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value <> ''",
			$meta_key
		)
	);
}

/**
 * Count users by a single meta flag.
 *
 * @param string $meta_key Meta key.
 * @param string $value    Expected value.
 * @return int
 */
function identity_security_kit_count_users_by_meta_flag( $meta_key, $value ) {
	global $wpdb;

	return (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value = %s",
			$meta_key,
			$value
		)
	);
}

/**
 * Render a small metric card.
 *
 * @param string $label Metric label.
 * @param string $value Metric value.
 * @param string $note  Supporting note.
 */
function identity_security_kit_render_metric( $label, $value, $note ) {
	?>
	<div class="isk-card">
		<span><?php echo esc_html( $label ); ?></span>
		<strong><?php echo esc_html( $value ); ?></strong>
		<em><?php echo esc_html( $note ); ?></em>
	</div>
	<?php
}

/**
 * Render the admin page.
 */
function identity_security_kit_render_admin_page() {
	if ( ! current_user_can( 'identity_manage_settings' ) ) {
		wp_die( esc_html__( 'You are not allowed to manage Identity Kit settings.', 'identity-security-kit' ) );
	}

	$settings       = identity_security_kit_get_settings();
	$sms_ready      = function_exists( 'identity_security_kit_sms_provider_available' ) && identity_security_kit_sms_provider_available();
	$users_count    = count_users();
	$total_users    = isset( $users_count['total_users'] ) ? (int) $users_count['total_users'] : 0;
	$avatar_count   = identity_security_kit_count_profile_avatars();
	$verified_count = function_exists( 'identity_security_kit_email_verified_meta_key' ) ? identity_security_kit_count_users_by_meta_flag( identity_security_kit_email_verified_meta_key(), '1' ) : 0;
	$pending_count  = function_exists( 'identity_security_kit_email_pending_meta_key' ) ? identity_security_kit_count_users_by_meta_flag( identity_security_kit_email_pending_meta_key(), '1' ) : 0;
	$capabilities   = identity_security_kit_get_capabilities();
	$settings_saved = isset( $_GET['settings-updated'] ) && 'true' === sanitize_text_field( wp_unslash( $_GET['settings-updated'] ) );
	$sms_test       = isset( $_GET['sms-test'] ) ? sanitize_key( wp_unslash( $_GET['sms-test'] ) ) : '';
	$sms_test_code  = isset( $_GET['sms-test-code'] ) ? sanitize_key( wp_unslash( $_GET['sms-test-code'] ) ) : '';
	$audit_count    = function_exists( 'identity_security_kit_count_audit_events' ) ? identity_security_kit_count_audit_events() : 0;
	$audit_events   = function_exists( 'identity_security_kit_get_recent_audit_events' ) ? identity_security_kit_get_recent_audit_events( 12 ) : array();
	?>
	<div class="wrap identity-security-kit-admin">
		<h1><?php esc_html_e( 'Identity Security Kit', 'identity-security-kit' ); ?></h1>
		<p><?php esc_html_e( 'Front-office identity controls, server-side validation, email verification, and audit-ready account security.', 'identity-security-kit' ); ?></p>

		<?php if ( $settings_saved ) : ?>
			<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Identity settings saved.', 'identity-security-kit' ); ?></p></div>
		<?php endif; ?>
		<?php if ( 'sent' === $sms_test ) : ?>
			<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'The provider accepted the test SMS. Confirm its arrival on the destination phone.', 'identity-security-kit' ); ?></p></div>
		<?php elseif ( 'failed' === $sms_test ) : ?>
			<div class="notice notice-error is-dismissible"><p><?php echo esc_html( sprintf( __( 'The test SMS was not accepted (%s). Check the provider configuration and logs.', 'identity-security-kit' ), $sms_test_code ?: 'sms_test_failed' ) ); ?></p></div>
		<?php endif; ?>

		<div class="isk-grid">
			<?php identity_security_kit_render_metric( __( 'Users', 'identity-security-kit' ), number_format_i18n( $total_users ), __( 'WordPress accounts', 'identity-security-kit' ) ); ?>
			<?php identity_security_kit_render_metric( __( 'Avatars', 'identity-security-kit' ), number_format_i18n( $avatar_count ), __( 'Profiles with custom avatar', 'identity-security-kit' ) ); ?>
			<?php identity_security_kit_render_metric( __( 'Email verified', 'identity-security-kit' ), number_format_i18n( $verified_count ), __( 'Confirmed addresses', 'identity-security-kit' ) ); ?>
			<?php identity_security_kit_render_metric( __( 'Email pending', 'identity-security-kit' ), number_format_i18n( $pending_count ), __( 'Awaiting confirmation', 'identity-security-kit' ) ); ?>
			<?php identity_security_kit_render_metric( __( 'Password min', 'identity-security-kit' ), (string) $settings['min_password_length'], __( 'Characters required', 'identity-security-kit' ) ); ?>
			<?php identity_security_kit_render_metric( __( 'Rate window', 'identity-security-kit' ), sprintf( __( '%d min', 'identity-security-kit' ), $settings['rate_limit_window_minutes'] ), __( 'Identity throttling', 'identity-security-kit' ) ); ?>
			<?php identity_security_kit_render_metric( __( 'Audit events', 'identity-security-kit' ), number_format_i18n( $audit_count ), __( 'Sensitive actions logged', 'identity-security-kit' ) ); ?>
		</div>

		<div class="isk-layout">
			<section class="isk-panel">
				<h2><?php esc_html_e( 'Security settings', 'identity-security-kit' ); ?></h2>
				<form method="POST" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="identity_security_kit_save_settings">
					<?php wp_nonce_field( 'identity_security_kit_save_settings' ); ?>

					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="isk_min_password_length"><?php esc_html_e( 'Minimum password length', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_min_password_length" class="small-text" name="min_password_length" type="number" min="8" max="128" value="<?php echo esc_attr( $settings['min_password_length'] ); ?>">
								<p class="description"><?php esc_html_e( 'Bounded between 8 and 128 characters. Server-side only; frontend fields cannot bypass it.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_max_avatar_size_mb"><?php esc_html_e( 'Max avatar size', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_max_avatar_size_mb" class="small-text" name="max_avatar_size_mb" type="number" min="1" max="12" value="<?php echo esc_attr( $settings['max_avatar_size_mb'] ); ?>"> <?php esc_html_e( 'MB', 'identity-security-kit' ); ?>
								<p class="description"><?php esc_html_e( 'Bounded between 1 MB and 12 MB to avoid oversized profile uploads.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_max_avatar_dimension"><?php esc_html_e( 'Max avatar dimension', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_max_avatar_dimension" class="small-text" name="max_avatar_dimension" type="number" min="512" max="6000" value="<?php echo esc_attr( $settings['max_avatar_dimension'] ); ?>"> px
								<p class="description"><?php esc_html_e( 'Bounded between 512px and 6000px per side.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_email_verification_ttl_hours"><?php esc_html_e( 'Email verification expiry', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_email_verification_ttl_hours" class="small-text" name="email_verification_ttl_hours" type="number" min="1" max="168" value="<?php echo esc_attr( $settings['email_verification_ttl_hours'] ); ?>"> <?php esc_html_e( 'hours', 'identity-security-kit' ); ?>
								<p class="description"><?php esc_html_e( 'Verification links expire between 1 hour and 7 days after creation.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_email_verification_resend_minutes"><?php esc_html_e( 'Verification resend cooldown', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_email_verification_resend_minutes" class="small-text" name="email_verification_resend_minutes" type="number" min="1" max="1440" value="<?php echo esc_attr( $settings['email_verification_resend_minutes'] ); ?>"> <?php esc_html_e( 'minutes', 'identity-security-kit' ); ?>
								<p class="description"><?php esc_html_e( 'Authenticated users must wait before requesting another verification link.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_email_otp_ttl_minutes"><?php esc_html_e( 'Email OTP expiry', 'identity-security-kit' ); ?></label></th>
							<td><input id="isk_email_otp_ttl_minutes" class="small-text" name="email_otp_ttl_minutes" type="number" min="2" max="30" value="<?php echo esc_attr( $settings['email_otp_ttl_minutes'] ); ?>"> <?php esc_html_e( 'minutes', 'identity-security-kit' ); ?></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_email_otp_length"><?php esc_html_e( 'Email OTP length', 'identity-security-kit' ); ?></label></th>
							<td><input id="isk_email_otp_length" class="small-text" name="email_otp_length" type="number" min="6" max="8" value="<?php echo esc_attr( $settings['email_otp_length'] ); ?>"> <?php esc_html_e( 'digits', 'identity-security-kit' ); ?></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_email_otp_max_attempts"><?php esc_html_e( 'Email OTP attempts', 'identity-security-kit' ); ?></label></th>
							<td><input id="isk_email_otp_max_attempts" class="small-text" name="email_otp_max_attempts" type="number" min="3" max="10" value="<?php echo esc_attr( $settings['email_otp_max_attempts'] ); ?>"></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_email_otp_resend_minutes"><?php esc_html_e( 'Email OTP resend cooldown', 'identity-security-kit' ); ?></label></th>
							<td><input id="isk_email_otp_resend_minutes" class="small-text" name="email_otp_resend_minutes" type="number" min="1" max="30" value="<?php echo esc_attr( $settings['email_otp_resend_minutes'] ); ?>"> <?php esc_html_e( 'minutes', 'identity-security-kit' ); ?></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_sms_provider"><?php esc_html_e( 'SMS provider', 'identity-security-kit' ); ?></label></th>
							<td><select id="isk_sms_provider" name="sms_provider"><option value="disabled" <?php selected( $settings['sms_provider'], 'disabled' ); ?>><?php esc_html_e( 'Disabled', 'identity-security-kit' ); ?></option><option value="brevo" <?php selected( $settings['sms_provider'], 'brevo' ); ?>><?php esc_html_e( 'Brevo SMS (recommended)', 'identity-security-kit' ); ?></option><option value="twilio" <?php selected( $settings['sms_provider'], 'twilio' ); ?>>Twilio</option><option value="custom" <?php selected( $settings['sms_provider'], 'custom' ); ?>><?php esc_html_e( 'Custom adapter', 'identity-security-kit' ); ?></option></select><p><strong class="<?php echo $sms_ready ? 'isk-config-ready' : 'isk-config-missing'; ?>"><?php echo esc_html( $sms_ready ? __( 'Provider credentials detected.', 'identity-security-kit' ) : __( 'Provider credentials not detected.', 'identity-security-kit' ) ); ?></strong></p><p class="description"><?php esc_html_e( 'Choose the provider here, then define its secrets in wp-config.php or environment variables. Secrets are never stored in WordPress.', 'identity-security-kit' ); ?></p><details class="isk-config-help"><summary><?php esc_html_e( 'Show wp-config.php examples', 'identity-security-kit' ); ?></summary><pre><?php echo esc_html( "// Brevo\ndefine( 'IDENTITY_SECURITY_BREVO_API_KEY', 'your-server-side-key' );\ndefine( 'IDENTITY_SECURITY_BREVO_SMS_SENDER', 'PhotoVault' );\n\n// Twilio\ndefine( 'IDENTITY_SECURITY_TWILIO_ACCOUNT_SID', 'AC...' );\ndefine( 'IDENTITY_SECURITY_TWILIO_AUTH_TOKEN', 'your-server-side-token' );\ndefine( 'IDENTITY_SECURITY_TWILIO_FROM', '+12025550123' );" ); ?></pre></details></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_sms_otp_ttl_minutes"><?php esc_html_e( 'SMS OTP policy', 'identity-security-kit' ); ?></label></th>
							<td><input id="isk_sms_otp_ttl_minutes" class="small-text" name="sms_otp_ttl_minutes" type="number" min="2" max="30" value="<?php echo esc_attr( $settings['sms_otp_ttl_minutes'] ); ?>"> <?php esc_html_e( 'minutes', 'identity-security-kit' ); ?> <input class="small-text" name="sms_otp_max_attempts" type="number" min="3" max="10" value="<?php echo esc_attr( $settings['sms_otp_max_attempts'] ); ?>"> <?php esc_html_e( 'attempts', 'identity-security-kit' ); ?> <input class="small-text" name="sms_otp_resend_minutes" type="number" min="1" max="30" value="<?php echo esc_attr( $settings['sms_otp_resend_minutes'] ); ?>"> <?php esc_html_e( 'minutes before resend', 'identity-security-kit' ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'International phone', 'identity-security-kit' ); ?></th>
							<td><label><input name="phone_required" type="checkbox" value="1" <?php checked( 1, $settings['phone_required'] ); ?>> <?php esc_html_e( 'Require a unique E.164 phone number during registration and profile updates.', 'identity-security-kit' ); ?></label></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'MFA enforcement', 'identity-security-kit' ); ?></th>
							<td><label><input name="mfa_enforcement_enabled" type="checkbox" value="1" <?php checked( 1, $settings['mfa_enforcement_enabled'] ); ?>> <?php esc_html_e( 'Require MFA for accounts matching the capabilities below.', 'identity-security-kit' ); ?></label></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_mfa_grace_days"><?php esc_html_e( 'MFA grace period', 'identity-security-kit' ); ?></label></th>
							<td><input id="isk_mfa_grace_days" class="small-text" name="mfa_grace_days" type="number" min="1" max="30" value="<?php echo esc_attr( $settings['mfa_grace_days'] ); ?>"> <?php esc_html_e( 'days', 'identity-security-kit' ); ?><p class="description"><?php esc_html_e( 'Privileged wp-admin access is blocked after this deadline until MFA is configured.', 'identity-security-kit' ); ?></p></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_mfa_attempts_per_window"><?php esc_html_e( 'MFA attempts', 'identity-security-kit' ); ?></label></th>
							<td><input id="isk_mfa_attempts_per_window" class="small-text" name="mfa_attempts_per_window" type="number" min="3" max="10" value="<?php echo esc_attr( $settings['mfa_attempts_per_window'] ); ?>"><p class="description"><?php esc_html_e( 'This limit cannot be bypassed by administrators.', 'identity-security-kit' ); ?></p></td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Allowed MFA methods', 'identity-security-kit' ); ?></th>
							<td><?php foreach ( array( 'totp', 'email', 'sms' ) as $method ) : ?><label style="margin-right:16px"><input type="checkbox" name="mfa_allowed_methods[]" value="<?php echo esc_attr( $method ); ?>" <?php checked( in_array( $method, $settings['mfa_allowed_methods'], true ) ); ?>> <?php echo esc_html( identity_security_kit_get_mfa_method_label( $method ) ); ?></label><?php endforeach; ?></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_mfa_required_capabilities"><?php esc_html_e( 'Capabilities requiring MFA', 'identity-security-kit' ); ?></label></th>
							<td><textarea id="isk_mfa_required_capabilities" name="mfa_required_capabilities" rows="5" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['mfa_required_capabilities'] ) ); ?></textarea><p class="description"><?php esc_html_e( 'One capability per line. A matching account receives the grace period.', 'identity-security-kit' ); ?></p></td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_login_attempts_per_window"><?php esc_html_e( 'Login attempts', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_login_attempts_per_window" class="small-text" name="login_attempts_per_window" type="number" min="3" max="60" value="<?php echo esc_attr( $settings['login_attempts_per_window'] ); ?>">
								<p class="description"><?php esc_html_e( 'Allowed login submissions per visitor during the rate limit window.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_registration_attempts_per_window"><?php esc_html_e( 'Registration attempts', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_registration_attempts_per_window" class="small-text" name="registration_attempts_per_window" type="number" min="1" max="30" value="<?php echo esc_attr( $settings['registration_attempts_per_window'] ); ?>">
								<p class="description"><?php esc_html_e( 'Allowed registration submissions per visitor during the rate limit window.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_password_reset_attempts_per_window"><?php esc_html_e( 'Password reset attempts', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_password_reset_attempts_per_window" class="small-text" name="password_reset_attempts_per_window" type="number" min="1" max="30" value="<?php echo esc_attr( $settings['password_reset_attempts_per_window'] ); ?>">
								<p class="description"><?php esc_html_e( 'Allowed forgot-password submissions per visitor during the rate limit window.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_email_resend_attempts_per_window"><?php esc_html_e( 'Email resend attempts', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_email_resend_attempts_per_window" class="small-text" name="email_resend_attempts_per_window" type="number" min="1" max="30" value="<?php echo esc_attr( $settings['email_resend_attempts_per_window'] ); ?>">
								<p class="description"><?php esc_html_e( 'Allowed verification resend submissions per signed-in user during the rate limit window.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="isk_rate_limit_window_minutes"><?php esc_html_e( 'Rate limit window', 'identity-security-kit' ); ?></label></th>
							<td>
								<input id="isk_rate_limit_window_minutes" class="small-text" name="rate_limit_window_minutes" type="number" min="1" max="1440" value="<?php echo esc_attr( $settings['rate_limit_window_minutes'] ); ?>"> <?php esc_html_e( 'minutes', 'identity-security-kit' ); ?>
								<p class="description"><?php esc_html_e( 'Shared window for login, registration, password reset and resend throttling.', 'identity-security-kit' ); ?></p>
							</td>
						</tr>					</table>

					<?php submit_button( __( 'Save settings', 'identity-security-kit' ) ); ?>
				</form>
			</section>

			<section class="isk-panel">
				<h2><?php esc_html_e( 'Capabilities', 'identity-security-kit' ); ?></h2>
				<ul class="isk-list">
					<?php foreach ( $capabilities as $capability ) : ?>
						<li><code><?php echo esc_html( $capability ); ?></code></li>
					<?php endforeach; ?>
				</ul>
				<h2><?php esc_html_e( 'Security modules', 'identity-security-kit' ); ?></h2>
				<ul class="isk-list">
					<li><?php esc_html_e( 'Email verification challenges with hashed one-time tokens', 'identity-security-kit' ); ?></li>
					<li><?php esc_html_e( 'Email OTP challenges with bounded expiry, attempts and one-time consumption', 'identity-security-kit' ); ?></li>
					<li><?php esc_html_e( 'Encrypted RFC 6238 authenticator secrets with replay prevention', 'identity-security-kit' ); ?></li>
					<li><?php esc_html_e( 'Hashed one-time recovery codes and capability-based MFA grace policy', 'identity-security-kit' ); ?></li>
					<li><?php esc_html_e( 'Profile upload validation and bounded image dimensions', 'identity-security-kit' ); ?></li>
					<li><?php esc_html_e( 'Password reset flow without account enumeration', 'identity-security-kit' ); ?></li>
					<li><?php esc_html_e( 'Security audit events without raw secrets or tokens', 'identity-security-kit' ); ?></li>
				</ul>
			</section>

			<section class="isk-panel">
				<h2><?php esc_html_e( 'SMS provider test', 'identity-security-kit' ); ?></h2>
				<p><?php esc_html_e( 'Send one harmless transactional message through the selected production adapter. Provider charges may apply.', 'identity-security-kit' ); ?></p>
				<form method="POST" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="identity_security_kit_test_sms_provider">
					<?php wp_nonce_field( 'identity_security_kit_test_sms_provider' ); ?>
					<label for="isk_sms_test_phone"><strong><?php esc_html_e( 'Destination phone', 'identity-security-kit' ); ?></strong></label>
					<p><input id="isk_sms_test_phone" class="regular-text" name="phone" type="tel" inputmode="tel" autocomplete="tel" placeholder="+229..." required></p>
					<p class="description"><?php esc_html_e( 'Use an international E.164 number. The complete number is not written to the security audit.', 'identity-security-kit' ); ?></p>
					<?php submit_button( __( 'Send test SMS', 'identity-security-kit' ), 'secondary', 'submit', false, $sms_ready ? array() : array( 'disabled' => 'disabled' ) ); ?>
				</form>
			</section>

			<?php if ( current_user_can( 'identity_view_security_audit' ) ) : ?>
				<section class="isk-panel isk-audit-panel">
					<div class="isk-panel-heading"><div><h2><?php esc_html_e( 'Recent security audit', 'identity-security-kit' ); ?></h2><p><?php esc_html_e( 'The latest 12 events are shown here.', 'identity-security-kit' ); ?></p></div><a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=identity-security-kit-audit' ) ); ?>"><?php esc_html_e( 'View complete audit', 'identity-security-kit' ); ?></a></div>
					<table class="widefat fixed striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Event', 'identity-security-kit' ); ?></th>
								<th><?php esc_html_e( 'Status', 'identity-security-kit' ); ?></th>
								<th><?php esc_html_e( 'User', 'identity-security-kit' ); ?></th>
								<th><?php esc_html_e( 'Context', 'identity-security-kit' ); ?></th>
								<th><?php esc_html_e( 'Date', 'identity-security-kit' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php if ( empty( $audit_events ) ) : ?>
								<tr><td colspan="5"><?php esc_html_e( 'No audit event recorded yet.', 'identity-security-kit' ); ?></td></tr>
							<?php else : ?>
								<?php foreach ( $audit_events as $event ) : ?>
									<?php
									$context = ! empty( $event['context'] ) ? json_decode( $event['context'], true ) : array();
									$context = is_array( $context ) ? $context : array();
									?>
									<tr>
										<td><code><?php echo esc_html( $event['event'] ); ?></code></td>
										<td><?php echo esc_html( $event['status'] ); ?></td>
										<td><?php echo ! empty( $event['user_id'] ) ? esc_html( '#' . absint( $event['user_id'] ) ) : esc_html__( 'Unknown', 'identity-security-kit' ); ?></td>
										<td><?php echo esc_html( $context ? wp_json_encode( $context ) : '-' ); ?></td>
										<td><?php echo esc_html( get_date_from_gmt( $event['created_at'], 'Y-m-d H:i' ) ); ?></td>
									</tr>
								<?php endforeach; ?>
							<?php endif; ?>
						</tbody>
					</table>
				</section>
			<?php endif; ?>
		</div>
	</div>
	<style>
		.identity-security-kit-admin .isk-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin:18px 0}.identity-security-kit-admin .isk-card,.identity-security-kit-admin .isk-panel{background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:16px}.identity-security-kit-admin .isk-card span{display:block;color:#646970;font-size:12px;text-transform:uppercase;letter-spacing:.08em}.identity-security-kit-admin .isk-card strong{display:block;margin-top:8px;font-size:28px}.identity-security-kit-admin .isk-card em{display:block;margin-top:4px;color:#646970;font-style:normal}.identity-security-kit-admin .isk-layout{display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:16px}.identity-security-kit-admin .isk-audit-panel{grid-column:1/-1}.identity-security-kit-admin .isk-panel-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:16px}.identity-security-kit-admin .isk-panel-heading h2,.identity-security-kit-admin .isk-panel-heading p{margin-top:0}.identity-security-kit-admin .isk-config-ready{color:#008a20}.identity-security-kit-admin .isk-config-missing{color:#b32d2e}.identity-security-kit-admin .isk-list{margin-left:0}.identity-security-kit-admin .isk-list li{border-bottom:1px solid #f0f0f1;margin:0;padding:8px 0}.identity-security-kit-admin .isk-config-help{margin-top:10px}.identity-security-kit-admin .isk-config-help summary{cursor:pointer;font-weight:600}.identity-security-kit-admin .isk-config-help pre{max-width:100%;overflow:auto;padding:12px;background:#f6f7f7;border:1px solid #dcdcde}@media(max-width:1100px){.identity-security-kit-admin .isk-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:782px){.identity-security-kit-admin .isk-grid,.identity-security-kit-admin .isk-layout{grid-template-columns:1fr}.identity-security-kit-admin .isk-panel-heading{display:block}.identity-security-kit-admin .isk-panel-heading .button{margin-top:8px}}
	</style>
	<?php
}

/**
 * Save admin settings.
 */
function identity_security_kit_handle_save_settings() {
	if ( ! current_user_can( 'identity_manage_settings' ) ) {
		wp_die( esc_html__( 'You are not allowed to update Identity Kit settings.', 'identity-security-kit' ) );
	}

	check_admin_referer( 'identity_security_kit_save_settings' );

	$settings = array(
		'min_password_length'         => isset( $_POST['min_password_length'] ) ? max( 8, min( 128, absint( $_POST['min_password_length'] ) ) ) : 8,
		'max_avatar_size_mb'          => isset( $_POST['max_avatar_size_mb'] ) ? max( 1, min( 12, absint( $_POST['max_avatar_size_mb'] ) ) ) : 6,
		'max_avatar_dimension'        => isset( $_POST['max_avatar_dimension'] ) ? max( 512, min( 6000, absint( $_POST['max_avatar_dimension'] ) ) ) : 6000,
		'email_verification_ttl_hours'       => isset( $_POST['email_verification_ttl_hours'] ) ? max( 1, min( 168, absint( $_POST['email_verification_ttl_hours'] ) ) ) : 24,
		'email_verification_resend_minutes' => isset( $_POST['email_verification_resend_minutes'] ) ? max( 1, min( 1440, absint( $_POST['email_verification_resend_minutes'] ) ) ) : 15,
		'login_attempts_per_window'          => isset( $_POST['login_attempts_per_window'] ) ? max( 3, min( 60, absint( $_POST['login_attempts_per_window'] ) ) ) : 12,
		'registration_attempts_per_window'   => isset( $_POST['registration_attempts_per_window'] ) ? max( 1, min( 30, absint( $_POST['registration_attempts_per_window'] ) ) ) : 6,
		'password_reset_attempts_per_window' => isset( $_POST['password_reset_attempts_per_window'] ) ? max( 1, min( 30, absint( $_POST['password_reset_attempts_per_window'] ) ) ) : 6,
		'email_resend_attempts_per_window'   => isset( $_POST['email_resend_attempts_per_window'] ) ? max( 1, min( 30, absint( $_POST['email_resend_attempts_per_window'] ) ) ) : 6,
		'rate_limit_window_minutes'          => isset( $_POST['rate_limit_window_minutes'] ) ? max( 1, min( 1440, absint( $_POST['rate_limit_window_minutes'] ) ) ) : 15,
		'email_otp_ttl_minutes'               => isset( $_POST['email_otp_ttl_minutes'] ) ? max( 2, min( 30, absint( $_POST['email_otp_ttl_minutes'] ) ) ) : 10,
		'email_otp_length'                    => isset( $_POST['email_otp_length'] ) ? max( 6, min( 8, absint( $_POST['email_otp_length'] ) ) ) : 6,
		'email_otp_max_attempts'              => isset( $_POST['email_otp_max_attempts'] ) ? max( 3, min( 10, absint( $_POST['email_otp_max_attempts'] ) ) ) : 5,
		'email_otp_resend_minutes'            => isset( $_POST['email_otp_resend_minutes'] ) ? max( 1, min( 30, absint( $_POST['email_otp_resend_minutes'] ) ) ) : 2,
		'sms_otp_ttl_minutes'                 => isset( $_POST['sms_otp_ttl_minutes'] ) ? max( 2, min( 30, absint( $_POST['sms_otp_ttl_minutes'] ) ) ) : 10,
		'sms_otp_length'                      => 6,
		'sms_otp_max_attempts'                => isset( $_POST['sms_otp_max_attempts'] ) ? max( 3, min( 10, absint( $_POST['sms_otp_max_attempts'] ) ) ) : 5,
		'sms_otp_resend_minutes'              => isset( $_POST['sms_otp_resend_minutes'] ) ? max( 1, min( 30, absint( $_POST['sms_otp_resend_minutes'] ) ) ) : 2,
		'sms_provider'                        => isset( $_POST['sms_provider'] ) && in_array( sanitize_key( wp_unslash( $_POST['sms_provider'] ) ), array( 'disabled', 'brevo', 'twilio', 'custom' ), true ) ? sanitize_key( wp_unslash( $_POST['sms_provider'] ) ) : 'disabled',
		'phone_required'                      => isset( $_POST['phone_required'] ) ? 1 : 0,
		'mfa_enforcement_enabled'             => isset( $_POST['mfa_enforcement_enabled'] ) ? 1 : 0,
		'mfa_grace_days'                      => isset( $_POST['mfa_grace_days'] ) ? max( 1, min( 30, absint( $_POST['mfa_grace_days'] ) ) ) : 15,
		'mfa_attempts_per_window'             => isset( $_POST['mfa_attempts_per_window'] ) ? max( 3, min( 10, absint( $_POST['mfa_attempts_per_window'] ) ) ) : 5,
		'mfa_required_capabilities'           => isset( $_POST['mfa_required_capabilities'] ) ? array_values( array_unique( array_filter( array_map( 'sanitize_key', preg_split( '/[\s,]+/', wp_unslash( $_POST['mfa_required_capabilities'] ) ) ) ) ) ) : array(),
		'mfa_allowed_methods'                 => isset( $_POST['mfa_allowed_methods'] ) && is_array( $_POST['mfa_allowed_methods'] ) ? array_values( array_intersect( array( 'totp', 'email', 'sms' ), array_map( 'sanitize_key', wp_unslash( $_POST['mfa_allowed_methods'] ) ) ) ) : array( 'totp' ),
	);

	update_option( 'identity_security_kit_settings', $settings, false );
	update_option( 'identity_security_kit_mfa_policy_page', 1, false );
	identity_security_kit_log_event( 'identity_settings_changed', 'success' );
	wp_safe_redirect( admin_url( 'admin.php?page=identity-security-kit&settings-updated=true' ) );
	exit;
}
add_action( 'admin_post_identity_security_kit_save_settings', 'identity_security_kit_handle_save_settings' );

/** Send a rate-limited provider test without creating an OTP challenge. */
function identity_security_kit_handle_test_sms_provider() {
	if ( ! current_user_can( 'identity_manage_settings' ) ) {
		wp_die( esc_html__( 'You are not allowed to test Identity Kit providers.', 'identity-security-kit' ) );
	}

	check_admin_referer( 'identity_security_kit_test_sms_provider' );
	$redirect = admin_url( 'admin.php?page=identity-security-kit' );
	$user_id  = get_current_user_id();
	$lock_key = 'identity_sms_provider_test_' . $user_id;
	if ( get_transient( $lock_key ) ) {
		wp_safe_redirect( add_query_arg( array( 'sms-test' => 'failed', 'sms-test-code' => 'rate_limited' ), $redirect ) );
		exit;
	}

	$phone = isset( $_POST['phone'] ) ? identity_security_kit_normalize_phone( wp_unslash( $_POST['phone'] ) ) : new WP_Error( 'phone_required', __( 'A destination phone is required.', 'identity-security-kit' ) );
	if ( is_wp_error( $phone ) ) {
		wp_safe_redirect( add_query_arg( array( 'sms-test' => 'failed', 'sms-test-code' => $phone->get_error_code() ), $redirect ) );
		exit;
	}
	if ( ! identity_security_kit_sms_provider_available() ) {
		wp_safe_redirect( add_query_arg( array( 'sms-test' => 'failed', 'sms-test-code' => 'provider_not_configured' ), $redirect ) );
		exit;
	}

	set_transient( $lock_key, 1, MINUTE_IN_SECONDS );
	$result = identity_security_kit_send_sms(
		$phone,
		__( 'PhotoVault test SMS. Your security provider is operational.', 'identity-security-kit' ),
		array(
			'purpose'         => 'provider_test',
			'idempotency_key' => wp_generate_uuid4(),
		)
	);
	$code   = is_wp_error( $result ) ? $result->get_error_code() : '';
	identity_security_kit_log_event(
		'sms_provider_test',
		is_wp_error( $result ) ? 'failure' : 'success',
		$user_id,
		array(
			'provider'  => identity_security_kit_get_sms_provider(),
			'recipient' => identity_security_kit_mask_phone( $phone ),
			'reason'    => $code,
		)
	);

	wp_safe_redirect( add_query_arg( array_filter( array( 'sms-test' => is_wp_error( $result ) ? 'failed' : 'sent', 'sms-test-code' => $code ) ), $redirect ) );
	exit;
}
add_action( 'admin_post_identity_security_kit_test_sms_provider', 'identity_security_kit_handle_test_sms_provider' );

/** Remove every enrolled factor during an administrator-assisted recovery. */
function identity_security_kit_admin_reset_user_mfa( $user_id ) {
	$user_id = absint( $user_id );
	if ( ! get_userdata( $user_id ) ) {
		return new WP_Error( 'identity_user_not_found', __( 'User not found.', 'identity-security-kit' ) );
	}

	$challenge_hash = (string) get_user_meta( $user_id, 'identity_mfa_login_challenge', true );
	if ( preg_match( '/^[a-f0-9]{64}$/', $challenge_hash ) ) {
		delete_transient( 'isk_login_' . $challenge_hash );
	}
	foreach ( array(
		identity_security_kit_totp_secret_meta_key(),
		'identity_mfa_totp_last_counter',
		'identity_mfa_totp_pending',
		'identity_mfa_email_enabled',
		'identity_mfa_sms_enabled',
		'identity_mfa_recovery_codes',
		'identity_mfa_enabled_at',
		'identity_mfa_preferred_method',
		'identity_mfa_login_challenge',
	) as $meta_key ) {
		delete_user_meta( $user_id, $meta_key );
	}
	identity_security_kit_clear_mfa_grace_state( $user_id );
	identity_security_kit_refresh_mfa_grace( $user_id );
	identity_security_kit_destroy_other_sessions( $user_id );
	identity_security_kit_send_security_notification( $user_id, __( 'An administrator reset all two-factor authentication methods on your account. Enroll a new method before the grace period ends.', 'identity-security-kit' ) );
	identity_security_kit_log_event( 'mfa_admin_reset', 'warning', $user_id, array( 'actor_user_id' => get_current_user_id() ) );

	return true;
}

/** Restart the configured MFA grace period for an eligible account. */
function identity_security_kit_admin_restart_user_grace( $user_id ) {
	$user_id = absint( $user_id );
	if ( ! get_userdata( $user_id ) || ! identity_security_kit_user_requires_mfa( $user_id ) ) {
		return new WP_Error( 'identity_grace_not_required', __( 'This account is not subject to the MFA grace policy.', 'identity-security-kit' ) );
	}
	if ( identity_security_kit_user_has_mfa_method( $user_id ) ) {
		return new WP_Error( 'identity_grace_not_applicable', __( 'This account already has an active MFA method.', 'identity-security-kit' ) );
	}

	identity_security_kit_clear_mfa_grace_state( $user_id );
	update_user_meta( $user_id, 'identity_mfa_grace_started_at', time() );
	identity_security_kit_send_security_notification( $user_id, __( 'An administrator restarted your MFA enrollment grace period. Configure a verification method from your profile.', 'identity-security-kit' ) );
	identity_security_kit_log_event( 'mfa_grace_admin_restarted', 'warning', $user_id, array( 'actor_user_id' => get_current_user_id() ) );

	return true;
}

/** Execute one privileged user-list security operation. */
function identity_security_kit_ajax_user_security_action() {
	if ( ! current_user_can( 'identity_manage_security' ) ) {
		wp_send_json_error( array( 'message' => __( 'You are not allowed to manage account security.', 'identity-security-kit' ) ), 403 );
	}

	$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
	$action  = isset( $_POST['security_action'] ) ? sanitize_key( wp_unslash( $_POST['security_action'] ) ) : '';
	check_ajax_referer( 'identity_security_user_action_' . $user_id, 'nonce' );
	$user = get_userdata( $user_id );
	if ( ! $user ) {
		wp_send_json_error( array( 'message' => __( 'User not found.', 'identity-security-kit' ) ), 404 );
	}
	if ( get_current_user_id() === $user_id && in_array( $action, array( 'reset_mfa', 'restart_grace' ), true ) ) {
		wp_send_json_error( array( 'message' => __( 'Use your profile security flow for your own account.', 'identity-security-kit' ) ), 409 );
	}

	if ( 'reset_mfa' === $action ) {
		$result  = identity_security_kit_admin_reset_user_mfa( $user_id );
		$message = __( 'MFA methods were reset and the user was notified.', 'identity-security-kit' );
	} elseif ( 'restart_grace' === $action ) {
		$result  = identity_security_kit_admin_restart_user_grace( $user_id );
		$message = __( 'The MFA grace period was restarted.', 'identity-security-kit' );
	} elseif ( 'resend_verification' === $action ) {
		$result  = identity_security_kit_create_email_verification_challenge( $user_id, $user->user_email );
		$message = __( 'A new email verification link was sent.', 'identity-security-kit' );
		identity_security_kit_log_event( is_wp_error( $result ) ? 'email_verification_admin_resend_failed' : 'email_verification_admin_resent', is_wp_error( $result ) ? 'failure' : 'success', $user_id, array( 'actor_user_id' => get_current_user_id() ) );
	} else {
		$result  = new WP_Error( 'identity_security_action_invalid', __( 'Choose a valid security action.', 'identity-security-kit' ) );
		$message = '';
	}

	if ( is_wp_error( $result ) ) {
		wp_send_json_error( array( 'message' => $result->get_error_message() ), 422 );
	}
	wp_send_json_success( array( 'message' => $message ) );
}
add_action( 'wp_ajax_identity_security_user_action', 'identity_security_kit_ajax_user_security_action' );

/** Add one compact security launcher to the WordPress user list. */
function identity_security_kit_add_user_security_row_action( $actions, $user ) {
	if ( ! current_user_can( 'identity_manage_security' ) || ! $user instanceof WP_User ) {
		return $actions;
	}

	$actions['identity_security'] = sprintf(
		'<button type="button" class="button-link" data-identity-user-security data-user-id="%1$d" data-user-name="%2$s" data-nonce="%3$s">%4$s</button>',
		absint( $user->ID ),
		esc_attr( $user->display_name ?: $user->user_login ),
		esc_attr( wp_create_nonce( 'identity_security_user_action_' . $user->ID ) ),
		esc_html__( 'Security', 'identity-security-kit' )
	);

	return $actions;
}
add_filter( 'user_row_actions', 'identity_security_kit_add_user_security_row_action', 20, 2 );

/** Load the user security modal only on the user list. */
function identity_security_kit_enqueue_user_actions( $hook_suffix ) {
	if ( 'users.php' !== $hook_suffix || ! current_user_can( 'identity_manage_security' ) ) {
		return;
	}
	wp_enqueue_style( 'identity-security-kit-user-actions', IDENTITY_SECURITY_KIT_URL . 'assets/css/user-actions.css', array(), IDENTITY_SECURITY_KIT_VERSION );
	wp_enqueue_script( 'identity-security-kit-user-actions', IDENTITY_SECURITY_KIT_URL . 'assets/js/user-actions.js', array(), IDENTITY_SECURITY_KIT_VERSION, true );
	wp_localize_script(
		'identity-security-kit-user-actions',
		'IdentitySecurityUserActions',
		array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'labels'  => array(
				'eyebrow'           => __( 'Identity Security Kit', 'identity-security-kit' ),
				'title'             => __( 'Account security', 'identity-security-kit' ),
				'reset'             => __( 'Reset all MFA methods', 'identity-security-kit' ),
				'resetDescription'  => __( 'Remove authenticators, channel factors, and recovery codes.', 'identity-security-kit' ),
				'grace'             => __( 'Restart MFA grace period', 'identity-security-kit' ),
				'graceDescription'  => __( 'Start the configured enrollment window again.', 'identity-security-kit' ),
				'verify'            => __( 'Send email verification', 'identity-security-kit' ),
				'verifyDescription' => __( 'Send a fresh, expiring link to the account email.', 'identity-security-kit' ),
				'close'             => __( 'Close', 'identity-security-kit' ),
				'confirmTitle'      => __( 'Confirm this action', 'identity-security-kit' ),
				'confirmText'       => __( 'This security operation will be recorded in the audit log.', 'identity-security-kit' ),
				'confirm'           => __( 'Confirm', 'identity-security-kit' ),
				'cancel'            => __( 'Cancel', 'identity-security-kit' ),
				'error'             => __( 'The action could not be completed.', 'identity-security-kit' ),
			),
		)
	);
}
add_action( 'admin_enqueue_scripts', 'identity_security_kit_enqueue_user_actions' );

/** Load progressive navigation on Identity Kit administration screens. */
function identity_security_kit_enqueue_admin_runtime() {
	$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
	if ( ! in_array( $page, array( 'identity-security-kit', 'identity-security-kit-audit' ), true ) ) {
		return;
	}
	wp_enqueue_style( 'identity-security-kit-admin-runtime', IDENTITY_SECURITY_KIT_URL . 'assets/css/admin-runtime.css', array(), IDENTITY_SECURITY_KIT_VERSION );
	wp_enqueue_script( 'identity-security-kit-admin-runtime', IDENTITY_SECURITY_KIT_URL . 'assets/js/admin-runtime.js', array(), IDENTITY_SECURITY_KIT_VERSION, true );
}
add_action( 'admin_enqueue_scripts', 'identity_security_kit_enqueue_admin_runtime' );
