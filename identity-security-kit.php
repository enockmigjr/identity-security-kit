<?php
/**
 * Plugin Name: Identity Security Kit
 * Description: Reusable identity, login, registration, and profile security handlers.
 * Version: 0.2.0
 * Author: PhotoVault
 * Text Domain: identity-security-kit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'IDENTITY_SECURITY_KIT_VERSION', '0.2.0' );
define( 'IDENTITY_SECURITY_KIT_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Return the public capabilities managed by the plugin.
 *
 * @return string[]
 */
function identity_security_kit_get_capabilities() {
	return array(
		'identity_manage_settings',
		'identity_manage_security',
		'identity_view_security_audit',
	);
}

/**
 * Return safe default settings.
 *
 * @return array<string,int>
 */
function identity_security_kit_get_default_settings() {
	return array(
		'min_password_length'         => 8,
		'max_avatar_size_mb'          => 6,
		'max_avatar_dimension'        => 6000,
		'email_verification_ttl_hours'       => 24,
		'email_verification_resend_minutes' => 15,
		'login_attempts_per_window'          => 12,
		'registration_attempts_per_window'   => 6,
		'password_reset_attempts_per_window' => 6,
		'email_resend_attempts_per_window'   => 6,
		'rate_limit_window_minutes'          => 15,
		'email_otp_ttl_minutes'               => 10,
		'email_otp_length'                    => 6,
		'email_otp_max_attempts'              => 5,
		'email_otp_resend_minutes'            => 2,
	);
}

/**
 * Return normalized plugin settings.
 *
 * @return array<string,int>
 */
function identity_security_kit_get_settings() {
	$settings = get_option( 'identity_security_kit_settings', array() );
	$settings = is_array( $settings ) ? $settings : array();
	$settings = wp_parse_args( $settings, identity_security_kit_get_default_settings() );

	$settings['min_password_length']         = max( 8, min( 128, absint( $settings['min_password_length'] ) ) );
	$settings['max_avatar_size_mb']          = max( 1, min( 12, absint( $settings['max_avatar_size_mb'] ) ) );
	$settings['max_avatar_dimension']        = max( 512, min( 6000, absint( $settings['max_avatar_dimension'] ) ) );
	$settings['email_verification_ttl_hours']       = max( 1, min( 168, absint( $settings['email_verification_ttl_hours'] ) ) );
	$settings['email_verification_resend_minutes'] = max( 1, min( 1440, absint( $settings['email_verification_resend_minutes'] ) ) );
	$settings['login_attempts_per_window']          = max( 3, min( 60, absint( $settings['login_attempts_per_window'] ) ) );
	$settings['registration_attempts_per_window']   = max( 1, min( 30, absint( $settings['registration_attempts_per_window'] ) ) );
	$settings['password_reset_attempts_per_window'] = max( 1, min( 30, absint( $settings['password_reset_attempts_per_window'] ) ) );
	$settings['email_resend_attempts_per_window']   = max( 1, min( 30, absint( $settings['email_resend_attempts_per_window'] ) ) );
	$settings['rate_limit_window_minutes']          = max( 1, min( 1440, absint( $settings['rate_limit_window_minutes'] ) ) );
	$settings['email_otp_ttl_minutes']               = max( 2, min( 30, absint( $settings['email_otp_ttl_minutes'] ) ) );
	$settings['email_otp_length']                    = max( 6, min( 8, absint( $settings['email_otp_length'] ) ) );
	$settings['email_otp_max_attempts']              = max( 3, min( 10, absint( $settings['email_otp_max_attempts'] ) ) );
	$settings['email_otp_resend_minutes']            = max( 1, min( 30, absint( $settings['email_otp_resend_minutes'] ) ) );

	return $settings;
}

/**
 * Build a privacy-preserving request fingerprint for rate limiting.
 *
 * @return string
 */
function identity_security_kit_get_rate_limit_fingerprint() {
	if ( is_user_logged_in() ) {
		return 'user:' . get_current_user_id();
	}

	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

	return 'anon:' . hash_hmac( 'sha256', $ip . '|' . $ua, wp_salt( 'auth' ) );
}

/**
 * Apply a transient-backed rate limit without storing raw IP addresses.
 *
 * @param string $bucket Bucket name.
 * @param int    $limit  Max attempts.
 * @param int    $window Window in seconds.
 * @return bool
 */
function identity_security_kit_rate_limit( $bucket, $limit, $window ) {
	$bucket = sanitize_key( $bucket );
	$limit  = max( 1, absint( $limit ) );
	$window = max( MINUTE_IN_SECONDS, absint( $window ) );

	if ( current_user_can( 'identity_manage_security' ) || current_user_can( 'manage_options' ) ) {
		return true;
	}

	$key      = 'isk_rl_' . md5( $bucket . '|' . identity_security_kit_get_rate_limit_fingerprint() );
	$attempts = absint( get_transient( $key ) );
	if ( $attempts >= $limit ) {
		return false;
	}

	set_transient( $key, $attempts + 1, $window );
	return true;
}

/**
 * Apply a configured Identity Kit rate limit bucket.
 *
 * @param string $bucket Bucket name.
 * @param string $setting_key Settings key containing the max attempts.
 * @return bool
 */
function identity_security_kit_rate_limit_by_setting( $bucket, $setting_key ) {
	$settings = identity_security_kit_get_settings();
	$limit    = isset( $settings[ $setting_key ] ) ? absint( $settings[ $setting_key ] ) : 6;
	$window   = isset( $settings['rate_limit_window_minutes'] ) ? absint( $settings['rate_limit_window_minutes'] ) * MINUTE_IN_SECONDS : 15 * MINUTE_IN_SECONDS;

	return identity_security_kit_rate_limit( $bucket, $limit, $window );
}
/**
 * Return the audit table name.
 *
 * @return string
 */
function identity_security_kit_get_audit_table() {
	global $wpdb;

	return $wpdb->prefix . 'identity_security_audit';
}

/**
 * Return the email verification challenge table name.
 *
 * @return string
 */
function identity_security_kit_get_email_verification_table() {
	global $wpdb;

	return $wpdb->prefix . 'identity_security_email_challenges';
}

/**
 * Return the email OTP challenge table name.
 *
 * @return string
 */
function identity_security_kit_get_email_otp_table() {
	global $wpdb;

	return $wpdb->prefix . 'identity_security_email_otp';
}

/**
 * Install or upgrade audit storage.
 */
function identity_security_kit_install_schema() {
	global $wpdb;

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';

	$table_name      = identity_security_kit_get_audit_table();
	$charset_collate = $wpdb->get_charset_collate();
	$sql             = "CREATE TABLE {$table_name} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		event varchar(80) NOT NULL,
		status varchar(24) NOT NULL DEFAULT 'info',
		user_id bigint(20) unsigned NULL,
		actor_user_id bigint(20) unsigned NULL,
		ip_hash char(64) NULL,
		user_agent varchar(255) NULL,
		context longtext NULL,
		created_at datetime NOT NULL,
		PRIMARY KEY  (id),
		KEY event (event),
		KEY status (status),
		KEY user_id (user_id),
		KEY created_at (created_at)
	) {$charset_collate};";

	dbDelta( $sql );

	$verification_table = identity_security_kit_get_email_verification_table();
	$verification_sql   = "CREATE TABLE {$verification_table} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		user_id bigint(20) unsigned NOT NULL,
		email_hash char(64) NOT NULL,
		token_hash char(64) NOT NULL,
		status varchar(24) NOT NULL DEFAULT 'pending',
		expires_at datetime NOT NULL,
		created_at datetime NOT NULL,
		verified_at datetime NULL,
		PRIMARY KEY  (id),
		KEY user_id (user_id),
		KEY token_hash (token_hash),
		KEY status (status),
		KEY expires_at (expires_at)
	) {$charset_collate};";

	dbDelta( $verification_sql );

	$otp_table = identity_security_kit_get_email_otp_table();
	$otp_sql   = "CREATE TABLE {$otp_table} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		user_id bigint(20) unsigned NOT NULL,
		purpose varchar(64) NOT NULL,
		destination_hash char(64) NOT NULL,
		code_hash varchar(255) NOT NULL,
		status varchar(24) NOT NULL DEFAULT 'pending',
		attempts smallint(5) unsigned NOT NULL DEFAULT 0,
		max_attempts smallint(5) unsigned NOT NULL,
		expires_at datetime NOT NULL,
		created_at datetime NOT NULL,
		consumed_at datetime NULL,
		PRIMARY KEY  (id),
		KEY user_purpose (user_id, purpose),
		KEY destination_hash (destination_hash),
		KEY status (status),
		KEY expires_at (expires_at)
	) {$charset_collate};";

	dbDelta( $otp_sql );
}

/**
 * Grant Identity Kit capabilities to administrators.
 */
function identity_security_kit_activate() {
	$admin = get_role( 'administrator' );
	if ( $admin ) {
		foreach ( identity_security_kit_get_capabilities() as $capability ) {
			$admin->add_cap( $capability );
		}
	}

	if ( false === get_option( 'identity_security_kit_settings', false ) ) {
		update_option( 'identity_security_kit_settings', identity_security_kit_get_default_settings(), false );
	}

	identity_security_kit_install_schema();
	update_option( 'identity_security_kit_version', IDENTITY_SECURITY_KIT_VERSION, false );
}
register_activation_hook( __FILE__, 'identity_security_kit_activate' );

/**
 * Apply versioned upgrades for already active installations.
 */
function identity_security_kit_maybe_upgrade() {
	$installed_version = get_option( 'identity_security_kit_version' );
	if ( IDENTITY_SECURITY_KIT_VERSION === $installed_version ) {
		return;
	}

	identity_security_kit_activate();
}
add_action( 'admin_init', 'identity_security_kit_maybe_upgrade' );

require_once IDENTITY_SECURITY_KIT_DIR . 'inc/audit.php';
require_once IDENTITY_SECURITY_KIT_DIR . 'inc/email-verification.php';
require_once IDENTITY_SECURITY_KIT_DIR . 'inc/email-otp.php';
require_once IDENTITY_SECURITY_KIT_DIR . 'inc/auth-handlers.php';
require_once IDENTITY_SECURITY_KIT_DIR . 'inc/admin.php';
