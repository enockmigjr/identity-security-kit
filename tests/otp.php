<?php
/** Focused channel-independent OTP tests without a WordPress bootstrap. */

define( 'ABSPATH', __DIR__ );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'ARRAY_A', 'ARRAY_A' );

class WP_Error {
	private $code;
	public function __construct( $code ) {
		$this->code = $code;
	}
	public function get_error_code() {
		return $this->code;
	}
}

class FakeWpdb {
	public $prefix = 'wp_';
	public $insert_id = 0;
	public $rows = array();
	public function prepare( $query, ...$args ) {
		return array( 'query' => $query, 'args' => $args );
	}
	public function get_var( $prepared ) {
		return null;
	}
	public function insert( $table, $row ) {
		$this->insert_id++;
		$row['id'] = $this->insert_id;
		$this->rows[ $this->insert_id ] = $row;
		return 1;
	}
	public function update( $table, $data, $where ) {
		$id = (int) $where['id'];
		if ( ! isset( $this->rows[ $id ] ) || ( isset( $where['status'] ) && $this->rows[ $id ]['status'] !== $where['status'] ) ) {
			return 0;
		}
		$this->rows[ $id ] = array_merge( $this->rows[ $id ], $data );
		return 1;
	}
	public function get_row( $prepared ) {
		$args = $prepared['args'];
		$id   = (int) $args[0];
		if ( ! isset( $this->rows[ $id ] ) ) {
			return null;
		}
		$row = $this->rows[ $id ];
		if ( (int) $row['user_id'] !== (int) $args[1] || $row['purpose'] !== $args[2] || $row['channel'] !== $args[3] ) {
			return null;
		}
		return $row;
	}
	public function query( $prepared ) {
		$args = $prepared['args'];
		if ( false !== strpos( $prepared['query'], 'id <> %d' ) ) {
			foreach ( $this->rows as $id => $row ) {
				if ( (int) $row['user_id'] === (int) $args[2] && $row['purpose'] === $args[3] && $row['channel'] === $args[4] && $row['status'] === $args[5] && $id !== (int) $args[6] ) {
					$this->rows[ $id ]['status'] = $args[0];
					$this->rows[ $id ]['code_hash'] = $args[1];
				}
			}
			return 1;
		}
		$id = (int) $args[3];
		if ( ! isset( $this->rows[ $id ] ) || 'pending' !== $this->rows[ $id ]['status'] ) {
			return 0;
		}
		$this->rows[ $id ]['status']      = $args[0];
		$this->rows[ $id ]['consumed_at'] = $args[1];
		$this->rows[ $id ]['code_hash']   = $args[2];
		return 1;
	}
}

$wpdb = new FakeWpdb();
$captured_code = '';

function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $value ) ); }
function absint( $value ) { return abs( (int) $value ); }
function get_userdata( $user_id ) { return $user_id > 0 ? (object) array( 'ID' => $user_id ) : false; }
function identity_security_kit_get_settings() { return array( 'email_otp_ttl_minutes' => 10, 'email_otp_length' => 6, 'email_otp_max_attempts' => 3, 'email_otp_resend_minutes' => 2 ); }
function apply_filters( $hook, $value ) { return $value; }
function wp_salt( $scheme ) { return 'test-' . $scheme; }
function wp_generate_uuid4() { return '12345678-1234-4234-8234-123456789abc'; }
function wp_hash_password( $value ) { return password_hash( $value, PASSWORD_DEFAULT ); }
function wp_check_password( $value, $hash ) { return password_verify( $value, $hash ); }
function __( $message ) { return $message; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function identity_security_kit_log_event() { return true; }
function do_action() {}
function test_delivery( $destination, $code ) { global $captured_code; $captured_code = $code; return true; }

require_once dirname( __DIR__ ) . '/inc/otp.php';

function assert_true( $actual, $message ) {
	if ( true !== $actual ) { throw new RuntimeException( $message ); }
}
function assert_same( $expected, $actual, $message ) {
	if ( $expected !== $actual ) { throw new RuntimeException( $message ); }
}

$challenge_id = identity_security_kit_create_otp_challenge( 7, 'verify_email', 'email', 'person@example.test', 'test_delivery' );
assert_same( 1, $challenge_id, 'The first challenge ID must be returned.' );
assert_true( '' !== $captured_code, 'The raw OTP must only reach the delivery adapter.' );
assert_true( $captured_code !== $wpdb->rows[1]['code_hash'], 'The raw OTP must not be stored.' );
assert_true( 'person@example.test' !== $wpdb->rows[1]['destination_hash'], 'The destination must be HMAC protected.' );
assert_true( 64 === strlen( $wpdb->rows[1]['idempotency_key'] ), 'Every challenge must carry an idempotency key.' );

$wrong = identity_security_kit_verify_otp_challenge( 1, 7, '000000', 'verify_email', 'email', 'person@example.test' );
assert_same( 'otp_incorrect', $wrong->get_error_code(), 'An incorrect code must be rejected.' );
assert_same( 1, $wpdb->rows[1]['attempts'], 'Incorrect attempts must be counted.' );

$verified = identity_security_kit_verify_otp_challenge( 1, 7, $captured_code, 'verify_email', 'email', 'person@example.test' );
assert_true( $verified, 'The correct code must be consumed.' );
assert_same( 'consumed', $wpdb->rows[1]['status'], 'Successful challenges must be marked consumed.' );
assert_same( '', $wpdb->rows[1]['code_hash'], 'Consumed challenge hashes must be erased.' );

$replay = identity_security_kit_verify_otp_challenge( 1, 7, $captured_code, 'verify_email', 'email', 'person@example.test' );
assert_same( 'otp_invalid', $replay->get_error_code(), 'A consumed code must not be replayable.' );

$second = identity_security_kit_create_otp_challenge( 7, 'login_second_factor', 'email', 'person@example.test', 'test_delivery' );
$wrong_purpose = identity_security_kit_verify_otp_challenge( $second, 7, $captured_code, 'verify_email', 'email', 'person@example.test' );
assert_same( 'otp_invalid', $wrong_purpose->get_error_code(), 'An OTP must be isolated to its purpose.' );
$changed = identity_security_kit_verify_otp_challenge( $second, 7, $captured_code, 'login_second_factor', 'email', 'other@example.test' );
assert_same( 'otp_destination_changed', $changed->get_error_code(), 'Changing destination must invalidate the challenge.' );

echo "Generic OTP tests passed.\n";
