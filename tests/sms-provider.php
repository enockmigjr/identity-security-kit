<?php
/**
 * Focused SMS adapter tests without a WordPress bootstrap.
 */

define( 'ABSPATH', __DIR__ );
define( 'IDENTITY_SECURITY_TWILIO_ACCOUNT_SID', 'ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'IDENTITY_SECURITY_TWILIO_AUTH_TOKEN', 'test-auth-token' );
define( 'IDENTITY_SECURITY_TWILIO_FROM', '+15551234567' );
define( 'IDENTITY_SECURITY_BREVO_API_KEY', 'runtime-brevo-key' );
define( 'IDENTITY_SECURITY_BREVO_SMS_SENDER', 'PhotoVault' );

$test_settings = array( 'sms_provider' => 'twilio' );
$test_response = array( 'response' => array( 'code' => 201 ), 'body' => '{"sid":"SM123"}' );
$test_request  = array();

class WP_Error {
	private $code;
	public function __construct( $code ) {
		$this->code = $code;
	}
	public function get_error_code() {
		return $this->code;
	}
}

function identity_security_kit_get_settings() {
	global $test_settings;
	return $test_settings;
}
function sanitize_key( $value ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $value ) );
}
function apply_filters( $hook, $value ) {
	return $value;
}
function __( $message ) {
	return $message;
}
function is_wp_error( $value ) {
	return $value instanceof WP_Error;
}
function wp_remote_post( $url, $args ) {
	global $test_request, $test_response;
	$test_request = array( 'url' => $url, 'args' => $args );
	return $test_response;
}
function wp_safe_remote_post( $url, $args ) {
	return wp_remote_post( $url, $args );
}
function wp_json_encode( $value ) {
	return json_encode( $value );
}
function wp_remote_retrieve_response_code( $response ) {
	return (int) $response['response']['code'];
}
function wp_remote_retrieve_body( $response ) {
	return (string) $response['body'];
}

require_once dirname( __DIR__ ) . '/inc/sms-provider.php';

function assert_same( $expected, $actual, $message ) {
	if ( $expected !== $actual ) {
		throw new RuntimeException( $message . ' Expected ' . var_export( $expected, true ) . ', got ' . var_export( $actual, true ) );
	}
}
function assert_true( $actual, $message ) {
	assert_same( true, $actual, $message );
}

assert_same( '+229******34', identity_security_kit_mask_phone( '+22997000034' ), 'Phone masking must preserve only a short prefix and suffix.' );

$result = identity_security_kit_send_sms( '+22997000034', 'Security code', array( 'idempotency_key' => str_repeat( 'a', 64 ) ) );
assert_true( $result, 'Twilio success response must be accepted.' );
assert_same( 'https://api.twilio.com/2010-04-01/Accounts/ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Messages.json', $test_request['url'], 'Twilio endpoint must be fixed and account-scoped.' );
assert_same( '+22997000034', $test_request['args']['body']['To'], 'Destination must be sent in the request body.' );
assert_true( false === array_key_exists( 'AuthToken', $test_request['args']['body'] ), 'Provider secrets must not be copied into the request body.' );

$test_response = array( 'response' => array( 'code' => 429 ), 'body' => '{"code":20429}' );
$result        = identity_security_kit_send_sms( '+22997000034', 'Security code' );
assert_true( is_wp_error( $result ), 'Provider failures must fail closed.' );
assert_same( 'sms_provider_rejected', $result->get_error_code(), 'Provider failure must expose a stable internal code.' );

$test_settings = array( 'sms_provider' => 'brevo' );
$test_response = array( 'response' => array( 'code' => 201 ), 'body' => '{"messageId":1511882900176220}' );
$result = identity_security_kit_send_sms( '+2290197000034', 'Security code', array( 'purpose' => 'mfa_login', 'idempotency_key' => str_repeat( 'b', 64 ) ) );
assert_true( $result, 'Brevo success response must be accepted.' );
assert_same( 'https://api.brevo.com/v3/transactionalSMS/send', $test_request['url'], 'Brevo endpoint must be fixed.' );
$brevo_body = json_decode( $test_request['args']['body'], true );
assert_same( '2290197000034', $brevo_body['recipient'], 'Brevo recipient must be an international digit string.' );
assert_same( 'transactional', $brevo_body['type'], 'Security codes must use transactional SMS.' );
assert_same( 'runtime-brevo-key', $test_request['args']['headers']['api-key'], 'Brevo API key must stay in a request header.' );

echo "SMS provider tests passed.\n";
