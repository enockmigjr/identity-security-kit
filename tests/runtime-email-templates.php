<?php
/**
 * WordPress runtime verification for professional multipart identity emails.
 *
 * Run with: wp eval-file tests/runtime-email-templates.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

function identity_email_templates_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

$captured_mail = array();
$alt_body      = '';
$capture_mail  = static function ( $attributes ) use ( &$captured_mail ) {
	$captured_mail = $attributes;

	return $attributes;
};
$capture_alt = static function ( $phpmailer ) use ( &$alt_body ) {
	$alt_body = (string) $phpmailer->AltBody;
};

add_filter( 'wp_mail', $capture_mail, 20 );
add_action( 'phpmailer_init', $capture_alt, 20 );

try {
	$content = array(
		'preheader'    => 'Runtime professional email preview',
		'eyebrow'      => 'Runtime security',
		'title'        => 'Confirm the security check',
		'greeting'     => 'Hello Runtime User,',
		'intro'        => 'A protected action needs your confirmation.',
		'details'      => array( 'The code expires in 10 minutes.', '<script>alert(1)</script>' ),
		'code'         => '483921',
		'action_url'   => home_url( '/?identity-runtime-confirm=1' ),
		'action_label' => 'Confirm securely',
		'notice'       => 'Never share this code. Ignore this email if you did not request it.',
	);
	$sent = identity_security_kit_send_transactional_email( 'identity-template-runtime@photovault.test', '[PhotoVault] Runtime professional email', $content, 'reply-runtime@photovault.test' );
	identity_email_templates_assert( true === $sent, 'Professional identity email was not handed to wp_mail.' );
	identity_email_templates_assert( false !== strpos( $captured_mail['message'], '<table role="presentation"' ), 'Responsive table email layout is missing.' );
	identity_email_templates_assert( false !== strpos( $captured_mail['message'], '483921' ) && false !== strpos( $captured_mail['message'], 'Confirm securely' ), 'OTP or secure CTA is missing from HTML.' );
	identity_email_templates_assert( false === strpos( $captured_mail['message'], '<script' ), 'Untrusted detail content reached the HTML email.' );
	identity_email_templates_assert( in_array( 'Content-Type: text/html; charset=UTF-8', $captured_mail['headers'], true ), 'HTML content type was not scoped to the email.' );
	identity_email_templates_assert( in_array( 'Reply-To: reply-runtime@photovault.test', $captured_mail['headers'], true ), 'Validated Reply-To was not handed to wp_mail.' );
	identity_email_templates_assert( false !== strpos( $alt_body, 'Your one-time security code is: 483921' ), 'PHPMailer AltBody does not contain the OTP.' );
	identity_email_templates_assert( false !== strpos( $alt_body, 'Confirm securely:' ) && false !== strpos( $alt_body, 'identity-runtime-confirm=1' ), 'PHPMailer AltBody does not contain the secure action.' );
	identity_email_templates_assert( false === identity_security_kit_send_transactional_email( 'invalid', 'Invalid recipient', $content ), 'Invalid recipient was accepted.' );
	$recovery = identity_security_kit_filter_recovery_mode_email(
		array(
			'to'      => 'admin@photovault.test',
			'subject' => 'Native recovery subject',
			'message' => "WordPress caught an error.\nPlugin: Runtime component\nError: Runtime failure",
			'headers' => '',
		),
		home_url( '/wp-login.php?action=enter_recovery_mode&rm_token=runtime' )
	);
	identity_email_templates_assert( false !== strpos( $recovery['message'], '<table role="presentation"' ) && false !== strpos( $recovery['message'], 'Runtime component' ), 'Recovery mode lost its professional layout or diagnostic.' );
	identity_email_templates_assert( false !== strpos( $recovery['message'], 'enter_recovery_mode' ) && false !== strpos( $recovery['headers'], 'text/html' ), 'Recovery mode lost its protected action or HTML header.' );

	echo wp_json_encode(
		array(
			'version'          => IDENTITY_SECURITY_KIT_VERSION,
			'html_layout'      => 'responsive_table',
			'plain_text'       => true,
			'phpmailer_alt_body' => true,
			'otp_component'    => true,
			'cta_component'    => true,
			'reply_to'         => 'validated',
			'wp_mail'          => true,
			'recovery_mode'    => true,
		)
	);
} finally {
	remove_filter( 'wp_mail', $capture_mail, 20 );
	remove_action( 'phpmailer_init', $capture_alt, 20 );
}
