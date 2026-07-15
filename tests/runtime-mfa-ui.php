<?php
/**
 * WordPress runtime verification for the account MFA settings markup.
 *
 * Run with: wp eval-file tests/runtime-mfa-ui.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

function identity_mfa_ui_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

$previous_user = get_current_user_id();

try {
	$administrator = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ids' ) );
	identity_mfa_ui_assert( ! empty( $administrator ), 'No administrator is available.' );
	wp_set_current_user( (int) $administrator[0] );

	$markup = identity_security_kit_render_mfa_panel();
	identity_mfa_ui_assert( false !== strpos( $markup, 'identity-security-mfa-method__header' ), 'MFA method headers are missing.' );
	identity_mfa_ui_assert( false !== strpos( $markup, 'identity-security-mfa-status' ), 'MFA status indicators are missing.' );
	identity_mfa_ui_assert( false !== strpos( $markup, 'data-mfa-method="totp"' ), 'Authenticator settings are missing.' );
	identity_mfa_ui_assert( false !== strpos( $markup, 'data-mfa-method="email"' ), 'Email factor settings are missing.' );
	identity_mfa_ui_assert( false !== strpos( $markup, '<details>' ), 'Sensitive MFA actions are not collapsed.' );

	echo wp_json_encode( array( 'method_rows' => true, 'status_indicators' => true, 'collapsed_actions' => true ) );
} finally {
	wp_set_current_user( $previous_user );
}
