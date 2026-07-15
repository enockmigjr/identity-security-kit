<?php
/**
 * WordPress runtime verification for local TOTP QR enrollment.
 *
 * Run with: wp eval-file tests/runtime-totp-qr.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

function identity_totp_qr_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

global $wpdb;

$suffix        = strtolower( wp_generate_password( 8, false, false ) );
$user_id       = 0;
$original_user = get_current_user_id();
$audit_table   = identity_security_kit_get_audit_table();

try {
	$user_id = wp_create_user( 'totp-qr-' . $suffix, wp_generate_password( 24, true, true ), 'totp-qr-' . $suffix . '@photovault.test' );
	identity_totp_qr_assert( is_int( $user_id ), 'The QR fixture account could not be created.' );
	wp_set_current_user( $user_id );

	$secret = identity_security_kit_begin_totp_enrollment( $user_id );
	identity_totp_qr_assert( is_string( $secret ) && preg_match( '/^[A-Z2-7]+$/', $secret ), 'TOTP enrollment did not create a Base32 secret.' );
	$html = identity_security_kit_render_mfa_panel();
	identity_totp_qr_assert( false !== strpos( $html, 'data-identity-totp-uri=' ) && false !== strpos( $html, 'otpauth://totp/' ), 'The enrollment panel does not expose a local QR payload.' );
	identity_totp_qr_assert( false !== strpos( $html, 'Manual setup key' ) && false !== strpos( $html, esc_html( $secret ) ), 'The manual enrollment fallback is missing.' );

	$scripts = wp_scripts();
	foreach ( array( 'identity-security-kit-qrcode', 'identity-security-kit-mfa-qr' ) as $handle ) {
		identity_totp_qr_assert( isset( $scripts->registered[ $handle ] ), 'A QR enrollment script was not registered.' );
		$source = (string) $scripts->registered[ $handle ]->src;
		identity_totp_qr_assert( 0 === strpos( $source, IDENTITY_SECURITY_KIT_URL ), 'A QR enrollment script is not served locally by the plugin.' );
		identity_totp_qr_assert( wp_script_is( $handle, 'enqueued' ), 'A QR enrollment script was not enqueued.' );
	}

	$vendor_file = IDENTITY_SECURITY_KIT_DIR . 'assets/vendor/qrcodejs/qrcode.min.js';
	identity_totp_qr_assert( is_readable( $vendor_file ), 'The pinned QRCode.js asset is unavailable.' );
	identity_totp_qr_assert( 'c541ef06327885a8415bca8df6071e14189b4855336def4f36db54bde8484f36' === hash_file( 'sha256', $vendor_file ), 'The pinned QRCode.js checksum changed.' );
	identity_totp_qr_assert( is_readable( IDENTITY_SECURITY_KIT_DIR . 'assets/vendor/qrcodejs/LICENSE' ), 'The vendored QRCode.js license is missing.' );

	WP_CLI::success(
		wp_json_encode(
			array(
				'qr_payload'       => 'otpauth_local_only',
				'assets'           => 'plugin_local_and_pinned',
				'manual_fallback'  => 'available',
				'vendor_sha256'    => hash_file( 'sha256', $vendor_file ),
			)
		)
	);
} finally {
	wp_set_current_user( $original_user );
	if ( $user_id ) {
		$wpdb->delete( $audit_table, array( 'user_id' => $user_id ), array( '%d' ) );
		wp_delete_user( $user_id );
	}
}
