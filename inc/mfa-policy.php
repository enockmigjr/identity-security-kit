<?php
/**
 * Capability-based MFA grace policy for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Return normalized capabilities that require MFA.
 *
 * @return string[]
 */
function identity_security_kit_get_mfa_required_capabilities() {
	$settings     = identity_security_kit_get_settings();
	$capabilities = isset( $settings['mfa_required_capabilities'] ) && is_array( $settings['mfa_required_capabilities'] ) ? $settings['mfa_required_capabilities'] : array();
	$capabilities = array_values( array_unique( array_filter( array_map( 'sanitize_key', $capabilities ) ) ) );

	return apply_filters( 'identity_security_kit_mfa_required_capabilities', $capabilities );
}

/**
 * Determine whether a user is subject to the MFA policy.
 *
 * @param int|WP_User $user User or ID.
 * @return bool
 */
function identity_security_kit_user_requires_mfa( $user ) {
	$settings = identity_security_kit_get_settings();
	$user     = $user instanceof WP_User ? $user : get_userdata( absint( $user ) );
	$required = false;

	if ( $user && ! empty( $settings['mfa_enforcement_enabled'] ) && identity_security_kit_mfa_runtime_supported() ) {
		foreach ( identity_security_kit_get_mfa_required_capabilities() as $capability ) {
			if ( $user->has_cap( $capability ) ) {
				$required = true;
				break;
			}
		}
	}

	return (bool) apply_filters( 'identity_security_kit_user_requires_mfa', $required, $user );
}

/**
 * Determine whether a user currently satisfies the MFA policy.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function identity_security_kit_user_has_mfa( $user_id ) {
	$enabled = function_exists( 'identity_security_kit_user_has_mfa_method' ) && identity_security_kit_user_has_mfa_method( absint( $user_id ) );

	return (bool) apply_filters( 'identity_security_kit_user_has_mfa', $enabled, absint( $user_id ) );
}

/**
 * Ensure the grace period has a stable start timestamp.
 *
 * @param int $user_id User ID.
 * @return int Unix timestamp, or zero when not required.
 */
function identity_security_kit_ensure_mfa_grace_started( $user_id ) {
	$user_id = absint( $user_id );
	if ( ! identity_security_kit_user_requires_mfa( $user_id ) || identity_security_kit_user_has_mfa( $user_id ) ) {
		return 0;
	}
	$started = absint( get_user_meta( $user_id, 'identity_mfa_grace_started_at', true ) );
	if ( ! $started ) {
		$started = time();
		add_user_meta( $user_id, 'identity_mfa_grace_started_at', $started, true );
		identity_security_kit_log_event( 'mfa_grace_started', 'info', $user_id );
	}

	return $started;
}

/**
 * Return the MFA grace deadline.
 *
 * @param int $user_id User ID.
 * @return int
 */
function identity_security_kit_get_mfa_deadline( $user_id ) {
	$started  = identity_security_kit_ensure_mfa_grace_started( $user_id );
	$settings = identity_security_kit_get_settings();
	$days     = isset( $settings['mfa_grace_days'] ) ? absint( $settings['mfa_grace_days'] ) : 15;

	return $started ? $started + ( $days * DAY_IN_SECONDS ) : 0;
}

/** Return whether a required account is beyond its MFA grace deadline. */
function identity_security_kit_is_mfa_grace_expired( $user_id, $now = 0 ) {
	$deadline = identity_security_kit_get_mfa_deadline( absint( $user_id ) );
	$now      = $now ? absint( $now ) : time();

	return 0 !== $deadline && $now >= $deadline;
}

/** Initialize grace tracking after account or role changes. */
function identity_security_kit_refresh_mfa_grace( $user_id ) {
	identity_security_kit_ensure_mfa_grace_started( absint( $user_id ) );
}
add_action( 'user_register', 'identity_security_kit_refresh_mfa_grace', 30 );
add_action( 'set_user_role', 'identity_security_kit_refresh_mfa_grace', 30 );
add_action( 'add_user_role', 'identity_security_kit_refresh_mfa_grace', 30 );

/** Show a bounded warning while privileged users are in grace. */
function identity_security_kit_mfa_admin_notice() {
	$user_id = get_current_user_id();
	if ( ! $user_id || ! identity_security_kit_user_requires_mfa( $user_id ) || identity_security_kit_user_has_mfa( $user_id ) ) {
		return;
	}
	$deadline = identity_security_kit_get_mfa_deadline( $user_id );
	$days     = max( 0, (int) ceil( ( $deadline - time() ) / DAY_IN_SECONDS ) );
	$url      = admin_url( 'profile.php#identity-security-mfa' );
	?>
	<div class="notice notice-warning"><p><?php echo wp_kses_post( sprintf( __( 'Two-factor authentication is required for this account. Configure it within %1$d days in your <a href="%2$s">security profile</a>.', 'identity-security-kit' ), $days, esc_url( $url ) ) ); ?></p></div>
	<?php
}
add_action( 'admin_notices', 'identity_security_kit_mfa_admin_notice' );

/** Enforce MFA after grace while keeping enrollment and recovery paths available. */
function identity_security_kit_enforce_mfa_admin_access() {
	if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
		return;
	}
	$user_id = get_current_user_id();
	if ( ! $user_id || ! identity_security_kit_user_requires_mfa( $user_id ) || identity_security_kit_user_has_mfa( $user_id ) ) {
		return;
	}
	if ( ! identity_security_kit_is_mfa_grace_expired( $user_id ) ) {
		return;
	}

	$action          = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
	$allowed_actions = array(
		'identity_security_kit_totp_start',
		'identity_security_kit_totp_confirm',
		'identity_security_kit_totp_cancel',
		'identity_security_kit_recovery_regenerate',
		'identity_security_kit_totp_disable',
		'heartbeat',
	);
	if ( wp_doing_ajax() ) {
		if ( in_array( $action, $allowed_actions, true ) ) {
			return;
		}
		identity_security_kit_log_event( 'mfa_ajax_access_blocked', 'warning', $user_id, array( 'action' => $action ) );
		wp_send_json_error( array( 'code' => 'mfa_required' ), 403 );
	}

	$script = isset( $GLOBALS['pagenow'] ) ? (string) $GLOBALS['pagenow'] : '';
	if ( 'profile.php' === $script || ( 'admin-post.php' === $script && in_array( $action, $allowed_actions, true ) ) ) {
		return;
	}

	identity_security_kit_log_event( 'mfa_admin_access_blocked', 'warning', $user_id, array( 'script' => sanitize_key( $script ) ) );
	wp_safe_redirect( admin_url( 'profile.php?mfa=required#identity-security-mfa' ) );
	exit;
}
add_action( 'admin_init', 'identity_security_kit_enforce_mfa_admin_access', 1 );
