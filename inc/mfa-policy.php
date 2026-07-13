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

/** Return reminder milestones that occur before the configured deadline. */
function identity_security_kit_get_mfa_reminder_days( $grace_days ) {
	$grace_days = max( 1, absint( $grace_days ) );
	$days       = apply_filters( 'identity_security_kit_mfa_reminder_days', array( 1, 7, 12 ), $grace_days );
	$days       = is_array( $days ) ? array_map( 'absint', $days ) : array();
	$days       = array_values( array_unique( array_filter( $days, static function ( $day ) use ( $grace_days ) {
		return $day > 0 && $day < $grace_days;
	} ) ) );
	sort( $days, SORT_NUMERIC );

	return $days;
}

/** Clear reminder state when a grace period no longer applies. */
function identity_security_kit_clear_mfa_grace_state( $user_id ) {
	delete_user_meta( absint( $user_id ), 'identity_mfa_grace_started_at' );
	delete_user_meta( absint( $user_id ), 'identity_mfa_grace_reminders' );
}

/** Send one idempotent reminder for the highest milestone currently due. */
function identity_security_kit_maybe_send_mfa_grace_reminder( $user_id, $now = 0 ) {
	$user_id = absint( $user_id );
	$now     = $now ? absint( $now ) : time();
	$user    = get_userdata( $user_id );
	if ( ! $user || ! identity_security_kit_user_requires_mfa( $user ) || identity_security_kit_user_has_mfa( $user_id ) ) {
		return false;
	}

	$started    = identity_security_kit_ensure_mfa_grace_started( $user_id );
	$settings   = identity_security_kit_get_settings();
	$grace_days = absint( $settings['mfa_grace_days'] ?? 15 );
	if ( ! $started || ! is_email( $user->user_email ) ) {
		return false;
	}
	$elapsed = max( 0, (int) floor( ( $now - $started ) / DAY_IN_SECONDS ) );
	$due        = array_values( array_filter( identity_security_kit_get_mfa_reminder_days( $grace_days ), static function ( $day ) use ( $elapsed ) {
		return $day <= $elapsed;
	} ) );
	if ( empty( $due ) ) {
		return false;
	}

	$state = get_user_meta( $user_id, 'identity_mfa_grace_reminders', true );
	$state = is_array( $state ) && absint( $state['started'] ?? 0 ) === $started ? $state : array( 'started' => $started, 'sent' => array() );
	$sent  = isset( $state['sent'] ) && is_array( $state['sent'] ) ? array_map( 'absint', $state['sent'] ) : array();
	$day   = max( $due );
	if ( in_array( $day, $sent, true ) ) {
		return false;
	}

	$lock_key = 'isk_mfa_reminder_' . $user_id;
	if ( get_transient( $lock_key ) ) {
		return false;
	}
	set_transient( $lock_key, 1, 5 * MINUTE_IN_SECONDS );
	$deadline  = $started + ( $grace_days * DAY_IN_SECONDS );
	$remaining = max( 0, (int) ceil( ( $deadline - $now ) / DAY_IN_SECONDS ) );
	$sent_ok   = identity_security_kit_send_transactional_email(
		$user->user_email,
		sprintf( __( '[%s] Two-factor authentication required', 'identity-security-kit' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) ),
		array(
			'preheader'    => sprintf( __( '%d day(s) remain to configure two-factor authentication.', 'identity-security-kit' ), $remaining ),
			'title'        => __( 'Two-factor authentication required', 'identity-security-kit' ),
			'greeting'     => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $user->display_name ? $user->display_name : $user->user_login ),
			'intro'        => sprintf( __( 'Your account requires two-factor authentication. %d day(s) remain before privileged access is restricted.', 'identity-security-kit' ), $remaining ),
			'action_url'   => admin_url( 'profile.php#identity-security-mfa' ),
			'action_label' => __( 'Configure two-factor authentication', 'identity-security-kit' ),
			'notice'       => __( 'This requirement protects privileged access to the site.', 'identity-security-kit' ),
		)
	);
	delete_transient( $lock_key );

	if ( ! $sent_ok ) {
		identity_security_kit_log_event( 'mfa_grace_reminder_failed', 'failure', $user_id, array( 'day' => $day ) );
		return false;
	}

	$state['sent'] = array_values( array_unique( array_merge( $sent, $due ) ) );
	update_user_meta( $user_id, 'identity_mfa_grace_reminders', $state );
	identity_security_kit_log_event( 'mfa_grace_reminder_sent', 'success', $user_id, array( 'day' => $day, 'days_remaining' => $remaining ) );

	return $day;
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

/** Reconcile grace tracking after account, role or policy changes. */
function identity_security_kit_refresh_mfa_grace( $user_id ) {
	$user_id = absint( $user_id );
	if ( ! get_userdata( $user_id ) ) {
		return;
	}
	if ( ! identity_security_kit_user_requires_mfa( $user_id ) || identity_security_kit_user_has_mfa( $user_id ) ) {
		identity_security_kit_clear_mfa_grace_state( $user_id );
		return;
	}
	identity_security_kit_ensure_mfa_grace_started( $user_id );
}
add_action( 'user_register', 'identity_security_kit_refresh_mfa_grace', 30 );
add_action( 'set_user_role', 'identity_security_kit_refresh_mfa_grace', 30 );
add_action( 'add_user_role', 'identity_security_kit_refresh_mfa_grace', 30 );
add_action( 'remove_user_role', 'identity_security_kit_refresh_mfa_grace', 30 );

/** Process one bounded page of users for policy changes and reminders. */
function identity_security_kit_process_mfa_policy_batch( $now = 0, $page = null ) {
	$batch_size      = max( 20, min( 500, absint( apply_filters( 'identity_security_kit_mfa_policy_batch_size', 200 ) ) ) );
	$stored_page     = max( 1, absint( get_option( 'identity_security_kit_mfa_policy_page', 1 ) ) );
	$use_stored_page = null === $page;
	$page            = $use_stored_page ? $stored_page : max( 1, absint( $page ) );
	$user_ids        = get_users(
		array(
			'fields'  => 'ids',
			'number'  => $batch_size,
			'offset'  => ( $page - 1 ) * $batch_size,
			'orderby' => 'ID',
			'order'   => 'ASC',
		)
	);

	foreach ( $user_ids as $user_id ) {
		identity_security_kit_refresh_mfa_grace( $user_id );
		identity_security_kit_maybe_send_mfa_grace_reminder( $user_id, $now );
	}

	if ( $use_stored_page ) {
		update_option( 'identity_security_kit_mfa_policy_page', count( $user_ids ) < $batch_size ? 1 : $page + 1, false );
	}
	identity_security_kit_log_event( 'mfa_policy_batch_processed', 'success', 0, array( 'page' => $page, 'users' => count( $user_ids ) ) );

	return count( $user_ids );
}
add_action( 'identity_security_kit_mfa_policy_cron', 'identity_security_kit_process_mfa_policy_batch' );

/** Ensure the hourly reconciliation event exists exactly once. */
function identity_security_kit_schedule_mfa_policy_cron() {
	if ( ! wp_next_scheduled( 'identity_security_kit_mfa_policy_cron' ) ) {
		wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'hourly', 'identity_security_kit_mfa_policy_cron' );
	}
}
add_action( 'init', 'identity_security_kit_schedule_mfa_policy_cron' );

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
		'identity_security_kit_channel_mfa_start',
		'identity_security_kit_channel_mfa_confirm',
		'identity_security_kit_channel_mfa_disable_start',
		'identity_security_kit_channel_mfa_disable_confirm',
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
