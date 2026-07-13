<?php
/**
 * One-time email challenge handling for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Normalize an OTP purpose exposed to integrations.
 *
 * @param string $purpose Raw purpose.
 * @return string
 */
function identity_security_kit_normalize_otp_purpose( $purpose ) {
	$purpose = sanitize_key( $purpose );

	return '' !== $purpose ? substr( $purpose, 0, 64 ) : 'account_verification';
}

/**
 * Hash an OTP destination without retaining the address in challenge storage.
 *
 * @param string $destination Email address.
 * @return string
 */
function identity_security_kit_hash_otp_destination( $destination ) {
	return hash_hmac( 'sha256', strtolower( trim( $destination ) ), wp_salt( 'auth' ) );
}

/**
 * Create and deliver an email OTP challenge.
 *
 * @param int    $user_id User ID.
 * @param string $purpose Challenge purpose.
 * @return int|WP_Error Challenge ID or error.
 */
function identity_security_kit_create_email_otp_challenge( $user_id, $purpose = 'account_verification' ) {
	global $wpdb;

	$user_id = absint( $user_id );
	$purpose = identity_security_kit_normalize_otp_purpose( $purpose );
	$user    = get_userdata( $user_id );

	if ( ! $user || ! is_email( $user->user_email ) ) {
		return new WP_Error( 'invalid_otp_destination', __( 'A valid account email is required.', 'identity-security-kit' ) );
	}

	$settings         = identity_security_kit_get_settings();
	$ttl_minutes      = $settings['email_otp_ttl_minutes'];
	$length           = $settings['email_otp_length'];
	$max_attempts     = $settings['email_otp_max_attempts'];
	$resend_seconds   = $settings['email_otp_resend_minutes'] * MINUTE_IN_SECONDS;
	$table            = identity_security_kit_get_email_otp_table();
	$destination_hash = identity_security_kit_hash_otp_destination( $user->user_email );
	$latest_created   = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT created_at FROM {$table} WHERE user_id = %d AND purpose = %s AND status <> %s ORDER BY id DESC LIMIT 1",
			$user_id,
			$purpose,
			'delivery_failed'
		)
	);

	if ( $latest_created ) {
		$latest_timestamp = strtotime( $latest_created . ' UTC' );
		if ( $latest_timestamp && ( time() - $latest_timestamp ) < $resend_seconds ) {
			return new WP_Error( 'otp_rate_limited', __( 'Please wait before requesting another code.', 'identity-security-kit' ) );
		}
	}

	$minimum = 10 ** ( $length - 1 );
	$maximum = ( 10 ** $length ) - 1;

	try {
		$code = (string) random_int( $minimum, $maximum );
	} catch ( Exception $exception ) {
		identity_security_kit_log_event( 'email_otp_random_failed', 'failure', $user_id, array( 'purpose' => $purpose ) );
		return new WP_Error( 'otp_generation_failed', __( 'The verification code could not be prepared.', 'identity-security-kit' ) );
	}
	$now     = gmdate( 'Y-m-d H:i:s' );
	$expires = gmdate( 'Y-m-d H:i:s', time() + ( $ttl_minutes * MINUTE_IN_SECONDS ) );

	$inserted = $wpdb->insert(
		$table,
		array(
			'user_id'          => $user_id,
			'purpose'          => $purpose,
			'destination_hash' => $destination_hash,
			'code_hash'        => wp_hash_password( $code ),
			'status'           => 'pending',
			'attempts'         => 0,
			'max_attempts'     => $max_attempts,
			'expires_at'       => $expires,
			'created_at'       => $now,
		),
		array( '%d', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s' )
	);

	if ( false === $inserted ) {
		identity_security_kit_log_event( 'email_otp_create_failed', 'failure', $user_id, array( 'purpose' => $purpose ) );
		return new WP_Error( 'otp_storage_failed', __( 'The verification code could not be prepared.', 'identity-security-kit' ) );
	}

	$challenge_id = absint( $wpdb->insert_id );
	$subject      = sprintf( __( '[%s] Your security code', 'identity-security-kit' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) );
	$message      = sprintf(
		/* translators: 1: display name, 2: OTP code, 3: expiration in minutes. */
		__( "Hello %1\$s,\n\nYour one-time security code is: %2\$s\n\nIt expires in %3\$d minutes and can only be used once. Never share this code.\n\nIf you did not request it, you can ignore this email.", 'identity-security-kit' ),
		$user->display_name ? $user->display_name : __( 'there', 'identity-security-kit' ),
		$code,
		$ttl_minutes
	);

	if ( ! wp_mail( $user->user_email, $subject, $message ) ) {
		$wpdb->update( $table, array( 'status' => 'delivery_failed', 'code_hash' => '' ), array( 'id' => $challenge_id ), array( '%s', '%s' ), array( '%d' ) );
		identity_security_kit_log_event( 'email_otp_delivery_failed', 'failure', $user_id, array( 'purpose' => $purpose ) );
		return new WP_Error( 'otp_delivery_failed', __( 'The verification code could not be sent.', 'identity-security-kit' ) );
	}

	$wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table} SET status = %s, code_hash = %s WHERE user_id = %d AND purpose = %s AND status = %s AND id <> %d",
			'superseded',
			'',
			$user_id,
			$purpose,
			'pending',
			$challenge_id
		)
	);

	identity_security_kit_log_event( 'email_otp_created', 'info', $user_id, array( 'purpose' => $purpose, 'ttl_minutes' => $ttl_minutes ) );
	do_action( 'identity_security_kit_email_otp_created', $challenge_id, $user_id, $purpose );

	return $challenge_id;
}

/**
 * Verify and atomically consume an email OTP challenge.
 *
 * @param int    $challenge_id Challenge ID.
 * @param int    $user_id      User ID.
 * @param string $code         Submitted code.
 * @param string $purpose      Expected purpose.
 * @return true|WP_Error
 */
function identity_security_kit_verify_email_otp_challenge( $challenge_id, $user_id, $code, $purpose = 'account_verification' ) {
	global $wpdb;

	$challenge_id = absint( $challenge_id );
	$user_id      = absint( $user_id );
	$purpose      = identity_security_kit_normalize_otp_purpose( $purpose );
	$code         = preg_replace( '/\D+/', '', (string) $code );
	$table        = identity_security_kit_get_email_otp_table();
	$now          = gmdate( 'Y-m-d H:i:s' );
	$challenge    = $wpdb->get_row(
		$wpdb->prepare(
			"SELECT id, destination_hash, code_hash, status, attempts, max_attempts, expires_at FROM {$table} WHERE id = %d AND user_id = %d AND purpose = %s LIMIT 1",
			$challenge_id,
			$user_id,
			$purpose
		),
		ARRAY_A
	);

	if ( ! $challenge || 'pending' !== $challenge['status'] ) {
		identity_security_kit_log_event( 'email_otp_rejected', 'warning', $user_id, array( 'purpose' => $purpose, 'reason' => 'invalid_or_replayed' ) );
		return new WP_Error( 'otp_invalid', __( 'The verification code is invalid or no longer available.', 'identity-security-kit' ) );
	}

	$user = get_userdata( $user_id );
	if ( ! $user || ! hash_equals( $challenge['destination_hash'], identity_security_kit_hash_otp_destination( $user->user_email ) ) ) {
		$wpdb->update( $table, array( 'status' => 'superseded', 'code_hash' => '' ), array( 'id' => $challenge_id ), array( '%s', '%s' ), array( '%d' ) );
		return new WP_Error( 'otp_destination_changed', __( 'The account email changed. Request a new code.', 'identity-security-kit' ) );
	}

	if ( $challenge['expires_at'] < $now ) {
		$wpdb->update( $table, array( 'status' => 'expired', 'code_hash' => '' ), array( 'id' => $challenge_id ), array( '%s', '%s' ), array( '%d' ) );
		identity_security_kit_log_event( 'email_otp_expired', 'warning', $user_id, array( 'purpose' => $purpose ) );
		return new WP_Error( 'otp_expired', __( 'The verification code has expired.', 'identity-security-kit' ) );
	}

	$attempts     = absint( $challenge['attempts'] );
	$max_attempts = absint( $challenge['max_attempts'] );
	if ( $attempts >= $max_attempts ) {
		$wpdb->update( $table, array( 'status' => 'locked', 'code_hash' => '' ), array( 'id' => $challenge_id ), array( '%s', '%s' ), array( '%d' ) );
		return new WP_Error( 'otp_locked', __( 'Too many incorrect attempts. Request a new code.', 'identity-security-kit' ) );
	}

	if ( ! preg_match( '/^[0-9]{6,8}$/', $code ) || ! wp_check_password( $code, $challenge['code_hash'] ) ) {
		$new_attempts = $attempts + 1;
		$new_status   = $new_attempts >= $max_attempts ? 'locked' : 'pending';
		$new_hash     = 'locked' === $new_status ? '' : $challenge['code_hash'];
		$wpdb->update(
			$table,
			array( 'attempts' => $new_attempts, 'status' => $new_status, 'code_hash' => $new_hash ),
			array( 'id' => $challenge_id, 'status' => 'pending' ),
			array( '%d', '%s', '%s' ),
			array( '%d', '%s' )
		);
		identity_security_kit_log_event( 'email_otp_rejected', 'warning', $user_id, array( 'purpose' => $purpose, 'reason' => 'incorrect', 'attempts' => $new_attempts ) );
		return new WP_Error( 'otp_incorrect', __( 'The verification code is incorrect.', 'identity-security-kit' ) );
	}

	$consumed = $wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table} SET status = %s, consumed_at = %s, code_hash = %s WHERE id = %d AND user_id = %d AND purpose = %s AND status = %s AND expires_at >= %s AND attempts < max_attempts",
			'consumed',
			$now,
			'',
			$challenge_id,
			$user_id,
			$purpose,
			'pending',
			$now
		)
	);

	if ( 1 !== $consumed ) {
		return new WP_Error( 'otp_replayed', __( 'The verification code was already used or expired.', 'identity-security-kit' ) );
	}

	update_user_meta( $user_id, 'identity_email_otp_verified_at', $now );
	identity_security_kit_log_event( 'email_otp_verified', 'success', $user_id, array( 'purpose' => $purpose ) );
	do_action( 'identity_security_kit_email_otp_verified', $user_id, $purpose, $challenge_id );

	return true;
}

/**
 * Redirect an authenticated OTP action back to the configured account route.
 *
 * @param array<string,string|int> $args Query arguments.
 */
function identity_security_kit_email_otp_redirect( $args ) {
	$routes = identity_security_kit_get_routes();
	$target = isset( $routes['profile'] ) ? $routes['profile'] : home_url( '/' );

	wp_safe_redirect( add_query_arg( $args, $target ) );
	exit;
}

/**
 * Handle an authenticated request for a new email OTP.
 */
function identity_security_kit_handle_email_otp_request() {
	if ( ! is_user_logged_in() ) {
		auth_redirect();
	}

	$purpose = isset( $_POST['purpose'] ) ? identity_security_kit_normalize_otp_purpose( wp_unslash( $_POST['purpose'] ) ) : 'account_verification';
	check_admin_referer( 'identity_security_kit_email_otp_request_' . $purpose );
	$result  = identity_security_kit_create_email_otp_challenge( get_current_user_id(), $purpose );

	if ( is_wp_error( $result ) ) {
		identity_security_kit_email_otp_redirect( array( 'otp' => sanitize_key( $result->get_error_code() ) ) );
	}

	identity_security_kit_email_otp_redirect( array( 'otp' => 'sent', 'challenge' => absint( $result ) ) );
}
add_action( 'admin_post_identity_security_kit_email_otp_request', 'identity_security_kit_handle_email_otp_request' );

/**
 * Handle an authenticated email OTP verification submission.
 */
function identity_security_kit_handle_email_otp_verify() {
	if ( ! is_user_logged_in() ) {
		auth_redirect();
	}

	$challenge_id = isset( $_POST['challenge_id'] ) ? absint( $_POST['challenge_id'] ) : 0;
	$purpose      = isset( $_POST['purpose'] ) ? identity_security_kit_normalize_otp_purpose( wp_unslash( $_POST['purpose'] ) ) : 'account_verification';
	check_admin_referer( 'identity_security_kit_email_otp_verify_' . $purpose );
	$code         = isset( $_POST['otp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['otp_code'] ) ) : '';
	$result       = identity_security_kit_verify_email_otp_challenge( $challenge_id, get_current_user_id(), $code, $purpose );

	if ( is_wp_error( $result ) ) {
		identity_security_kit_email_otp_redirect( array( 'otp' => sanitize_key( $result->get_error_code() ), 'challenge' => $challenge_id ) );
	}

	identity_security_kit_email_otp_redirect( array( 'otp' => 'verified' ) );
}
add_action( 'admin_post_identity_security_kit_email_otp_verify', 'identity_security_kit_handle_email_otp_verify' );

/**
 * Render a reusable authenticated email OTP form.
 *
 * @param array<string,string> $attributes Shortcode attributes.
 * @return string
 */
function identity_security_kit_render_email_otp_shortcode( $attributes ) {
	if ( ! is_user_logged_in() ) {
		return '';
	}

	$attributes   = shortcode_atts( array( 'purpose' => 'account_verification' ), $attributes, 'identity_security_email_otp' );
	$purpose      = identity_security_kit_normalize_otp_purpose( $attributes['purpose'] );
	$challenge_id = isset( $_GET['challenge'] ) ? absint( $_GET['challenge'] ) : 0;

	ob_start();
	if ( $challenge_id ) :
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="identity_security_kit_email_otp_verify">
			<input type="hidden" name="challenge_id" value="<?php echo esc_attr( $challenge_id ); ?>">
			<input type="hidden" name="purpose" value="<?php echo esc_attr( $purpose ); ?>">
			<?php wp_nonce_field( 'identity_security_kit_email_otp_verify_' . $purpose ); ?>
			<label for="identity-email-otp-code"><?php esc_html_e( 'Security code', 'identity-security-kit' ); ?></label>
			<input id="identity-email-otp-code" name="otp_code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,8}" required>
			<button type="submit"><?php esc_html_e( 'Verify code', 'identity-security-kit' ); ?></button>
		</form>
		<?php
	else :
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="identity_security_kit_email_otp_request">
			<input type="hidden" name="purpose" value="<?php echo esc_attr( $purpose ); ?>">
			<?php wp_nonce_field( 'identity_security_kit_email_otp_request_' . $purpose ); ?>
			<button type="submit"><?php esc_html_e( 'Send a security code by email', 'identity-security-kit' ); ?></button>
		</form>
		<?php
	endif;

	return (string) ob_get_clean();
}
add_shortcode( 'identity_security_email_otp', 'identity_security_kit_render_email_otp_shortcode' );
