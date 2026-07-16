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
	return identity_security_kit_get_audit_events( array( 'per_page' => $limit ) );
}

/** Build the sanitized SQL conditions shared by audit queries. */
function identity_security_kit_get_audit_conditions( $args ) {
	$conditions = array( '1=1' );
	$values     = array();
	$status     = isset( $args['status'] ) ? sanitize_key( $args['status'] ) : '';
	$event      = isset( $args['event'] ) ? sanitize_key( $args['event'] ) : '';
	$user_id    = isset( $args['user_id'] ) ? absint( $args['user_id'] ) : 0;

	if ( in_array( $status, array( 'info', 'success', 'warning', 'failure' ), true ) ) {
		$conditions[] = 'status = %s';
		$values[]     = $status;
	}
	if ( '' !== $event ) {
		$conditions[] = 'event = %s';
		$values[]     = $event;
	}
	if ( $user_id > 0 ) {
		$conditions[] = 'user_id = %d';
		$values[]     = $user_id;
	}

	return array( implode( ' AND ', $conditions ), $values );
}

/** Fetch one bounded page of security audit events. */
function identity_security_kit_get_audit_events( $args = array() ) {
	global $wpdb;

	$args     = wp_parse_args( $args, array( 'per_page' => 25, 'paged' => 1, 'status' => '', 'event' => '', 'user_id' => 0 ) );
	$per_page = max( 1, min( 100, absint( $args['per_page'] ) ) );
	$paged    = max( 1, absint( $args['paged'] ) );
	list( $where, $values ) = identity_security_kit_get_audit_conditions( $args );
	$values[] = $per_page;
	$values[] = ( $paged - 1 ) * $per_page;
	$table    = identity_security_kit_get_audit_table();
	$sql      = "SELECT id, event, status, user_id, actor_user_id, context, created_at FROM {$table} WHERE {$where} ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d";

	return $wpdb->get_results( $wpdb->prepare( $sql, $values ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
}

/** Count security audit events matching the current filters. */
function identity_security_kit_count_filtered_audit_events( $args = array() ) {
	global $wpdb;

	list( $where, $values ) = identity_security_kit_get_audit_conditions( $args );
	$table = identity_security_kit_get_audit_table();
	$sql   = "SELECT COUNT(*) FROM {$table} WHERE {$where}";
	if ( ! empty( $values ) ) {
		$sql = $wpdb->prepare( $sql, $values );
	}

	return (int) $wpdb->get_var( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
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

/** Render the complete, filterable and paginated audit screen. */
function identity_security_kit_render_audit_page() {
	if ( ! current_user_can( 'identity_view_security_audit' ) ) {
		wp_die( esc_html__( 'You are not allowed to view the security audit.', 'identity-security-kit' ) );
	}

	$args = array(
		'status'   => isset( $_GET['audit_status'] ) ? sanitize_key( wp_unslash( $_GET['audit_status'] ) ) : '',
		'event'    => isset( $_GET['audit_event'] ) ? sanitize_key( wp_unslash( $_GET['audit_event'] ) ) : '',
		'user_id'  => isset( $_GET['audit_user_id'] ) ? absint( $_GET['audit_user_id'] ) : 0,
		'paged'    => isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1,
		'per_page' => 25,
	);
	$events      = identity_security_kit_get_audit_events( $args );
	$total       = identity_security_kit_count_filtered_audit_events( $args );
	$total_pages = max( 1, (int) ceil( $total / $args['per_page'] ) );
	$base_args   = array_filter(
		array(
			'page'          => 'identity-security-kit-audit',
			'audit_status'  => $args['status'],
			'audit_event'   => $args['event'],
			'audit_user_id' => $args['user_id'],
		)
	);
	?>
	<div class="wrap identity-security-audit-admin">
		<div class="isk-audit-heading"><div><h1><?php esc_html_e( 'Security audit', 'identity-security-kit' ); ?></h1><p><?php esc_html_e( 'Review every sensitive identity event without exposing raw IP addresses, tokens or credentials.', 'identity-security-kit' ); ?></p></div><span><?php echo esc_html( sprintf( _n( '%s event', '%s events', $total, 'identity-security-kit' ), number_format_i18n( $total ) ) ); ?></span></div>
		<form method="get" class="isk-audit-filters">
			<input type="hidden" name="page" value="identity-security-kit-audit">
			<label for="isk-audit-status"><?php esc_html_e( 'Status', 'identity-security-kit' ); ?><select id="isk-audit-status" name="audit_status"><option value=""><?php esc_html_e( 'All statuses', 'identity-security-kit' ); ?></option><?php foreach ( array( 'info', 'success', 'warning', 'failure' ) as $status ) : ?><option value="<?php echo esc_attr( $status ); ?>" <?php selected( $args['status'], $status ); ?>><?php echo esc_html( ucfirst( $status ) ); ?></option><?php endforeach; ?></select></label>
			<label for="isk-audit-event"><?php esc_html_e( 'Exact event', 'identity-security-kit' ); ?><input id="isk-audit-event" name="audit_event" type="text" value="<?php echo esc_attr( $args['event'] ); ?>" placeholder="login_success"></label>
			<label for="isk-audit-user"><?php esc_html_e( 'User ID', 'identity-security-kit' ); ?><input id="isk-audit-user" name="audit_user_id" type="number" min="1" value="<?php echo $args['user_id'] ? esc_attr( $args['user_id'] ) : ''; ?>"></label>
			<button class="button button-primary" type="submit"><?php esc_html_e( 'Filter events', 'identity-security-kit' ); ?></button>
			<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=identity-security-kit-audit' ) ); ?>"><?php esc_html_e( 'Reset', 'identity-security-kit' ); ?></a>
		</form>
		<div class="isk-audit-table-wrap">
		<table class="widefat fixed striped">
			<thead><tr><th><?php esc_html_e( 'Event', 'identity-security-kit' ); ?></th><th><?php esc_html_e( 'Status', 'identity-security-kit' ); ?></th><th><?php esc_html_e( 'Subject / actor', 'identity-security-kit' ); ?></th><th><?php esc_html_e( 'Details', 'identity-security-kit' ); ?></th><th><?php esc_html_e( 'Date', 'identity-security-kit' ); ?></th></tr></thead>
			<tbody>
			<?php if ( empty( $events ) ) : ?><tr><td colspan="5"><?php esc_html_e( 'No audit event matches these filters.', 'identity-security-kit' ); ?></td></tr><?php endif; ?>
			<?php foreach ( $events as $event ) : $context = json_decode( (string) $event['context'], true ); $context = is_array( $context ) ? $context : array(); ?>
				<tr><td><code><?php echo esc_html( $event['event'] ); ?></code><small>#<?php echo esc_html( $event['id'] ); ?></small></td><td><span class="isk-audit-status is-<?php echo esc_attr( $event['status'] ); ?>"><?php echo esc_html( $event['status'] ); ?></span></td><td><?php echo $event['user_id'] ? esc_html( '#' . absint( $event['user_id'] ) ) : esc_html__( 'Unknown', 'identity-security-kit' ); ?><small><?php echo $event['actor_user_id'] ? esc_html( sprintf( __( 'Actor #%d', 'identity-security-kit' ), absint( $event['actor_user_id'] ) ) ) : esc_html__( 'Public request', 'identity-security-kit' ); ?></small></td><td><?php if ( $context ) : ?><details><summary><?php esc_html_e( 'View sanitized context', 'identity-security-kit' ); ?></summary><pre><?php echo esc_html( wp_json_encode( $context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ); ?></pre></details><?php else : ?>&mdash;<?php endif; ?></td><td><?php echo esc_html( get_date_from_gmt( $event['created_at'], 'Y-m-d H:i:s' ) ); ?></td></tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		</div>
		<?php if ( $total_pages > 1 ) : ?><div class="tablenav"><div class="tablenav-pages"><?php echo wp_kses_post( paginate_links( array( 'base' => add_query_arg( array_merge( $base_args, array( 'paged' => '%#%' ) ), admin_url( 'admin.php' ) ), 'current' => $args['paged'], 'total' => $total_pages, 'type' => 'list' ) ) ); ?></div></div><?php endif; ?>
	</div>
	<style>
		.identity-security-audit-admin .isk-audit-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin:18px 0}.identity-security-audit-admin .isk-audit-heading h1,.identity-security-audit-admin .isk-audit-heading p{margin-top:0}.identity-security-audit-admin .isk-audit-heading>span{border:1px solid #dcdcde;background:#fff;padding:10px 14px;font-weight:600}.identity-security-audit-admin .isk-audit-filters{display:flex;align-items:end;gap:12px;flex-wrap:wrap;margin-bottom:18px;border:1px solid #dcdcde;background:#fff;padding:16px}.identity-security-audit-admin .isk-audit-filters label{display:grid;gap:6px;font-weight:600}.identity-security-audit-admin .isk-audit-filters input,.identity-security-audit-admin .isk-audit-filters select{min-width:160px}.identity-security-audit-admin .isk-audit-table-wrap{overflow-x:auto}.identity-security-audit-admin td small{display:block;margin-top:6px;color:#646970}.identity-security-audit-admin details pre{max-width:480px;overflow:auto;white-space:pre-wrap}.identity-security-audit-admin .isk-audit-status{display:inline-block;border:1px solid #c3c4c7;padding:3px 7px;text-transform:uppercase;font-size:10px;font-weight:700}.identity-security-audit-admin .isk-audit-status.is-success{border-color:#00a32a;color:#006b1b}.identity-security-audit-admin .isk-audit-status.is-warning{border-color:#dba617;color:#7a4f01}.identity-security-audit-admin .isk-audit-status.is-failure{border-color:#d63638;color:#a00}@media(max-width:782px){.identity-security-audit-admin .isk-audit-heading{display:block}.identity-security-audit-admin .isk-audit-heading>span{display:inline-block}.identity-security-audit-admin .isk-audit-filters{align-items:stretch}.identity-security-audit-admin .isk-audit-filters label,.identity-security-audit-admin .isk-audit-filters input,.identity-security-audit-admin .isk-audit-filters select{width:100%}}
	</style>
	<?php
}
