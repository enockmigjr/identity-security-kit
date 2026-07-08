<?php
/**
 * Audit logging for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hash the request IP to avoid storing raw network identifiers.
 *
 * @return string
 */
function identity_security_kit_get_request_ip_hash() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	if ( '' === $ip ) {
		return '';
	}

	return hash_hmac( 'sha256', $ip, wp_salt( 'nonce' ) );
}

/**
 * Write a sanitized audit event.
 *
 * @param string              $event   Event key.
 * @param string              $status  info|success|warning|failure.
 * @param int                 $user_id Related user ID, if known.
 * @param array<string,mixed> $context Non-secret contextual metadata.
 * @return bool
 */
function identity_security_kit_log_event( $event, $status = 'info', $user_id = 0, $context = array() ) {
	global $wpdb;

	$allowed_statuses = array( 'info', 'success', 'warning', 'failure' );
	$status           = in_array( $status, $allowed_statuses, true ) ? $status : 'info';
	$table_name       = identity_security_kit_get_audit_table();
	$user_agent       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '';
	$context          = is_array( $context ) ? $context : array();

	foreach ( $context as $key => $value ) {
		if ( is_scalar( $value ) || null === $value ) {
			$context[ $key ] = sanitize_text_field( (string) $value );
		} else {
			unset( $context[ $key ] );
		}
	}

	$inserted = $wpdb->insert(
		$table_name,
		array(
			'event'         => sanitize_key( $event ),
			'status'        => $status,
			'user_id'       => $user_id > 0 ? absint( $user_id ) : null,
			'actor_user_id' => get_current_user_id() > 0 ? get_current_user_id() : null,
			'ip_hash'       => identity_security_kit_get_request_ip_hash(),
			'user_agent'    => $user_agent,
			'context'       => wp_json_encode( $context ),
			'created_at'    => current_time( 'mysql', true ),
		),
		array( '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s' )
	);

	return false !== $inserted;
}

/**
 * Fetch recent audit events for administrators.
 *
 * @param int $limit Maximum number of rows.
 * @return array<int,array<string,mixed>>
 */
function identity_security_kit_get_recent_audit_events( $limit = 20 ) {
	global $wpdb;

	$table_name = identity_security_kit_get_audit_table();
	$limit      = max( 1, min( 100, absint( $limit ) ) );

	return $wpdb->get_results(
		$wpdb->prepare(
			"SELECT id, event, status, user_id, actor_user_id, context, created_at FROM {$table_name} ORDER BY created_at DESC, id DESC LIMIT %d",
			$limit
		),
		ARRAY_A
	);
}

/**
 * Count audit events.
 *
 * @return int
 */
function identity_security_kit_count_audit_events() {
	global $wpdb;

	$table_name = identity_security_kit_get_audit_table();

	return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
}