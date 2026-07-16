<?php
/**
 * Browser-bound multi-method MFA login challenges.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Return login methods, including recovery codes as a fallback. */
function identity_security_kit_get_login_mfa_methods( $user_id ) {
	$methods  = identity_security_kit_get_user_mfa_methods( $user_id );
	$recovery = get_user_meta( absint( $user_id ), 'identity_mfa_recovery_codes', true );
	if ( is_array( $recovery ) && ! empty( $recovery ) ) {
		$methods[] = 'recovery';
	}

	return array_values( array_unique( $methods ) );
}

/** Persist the serializable portion of a login challenge. */
function identity_security_kit_store_login_challenge_payload( $token_hash, $payload ) {
	$redirect_to = wp_validate_redirect( $payload['redirect_to'] ?? '', home_url( '/' ) );
	if ( '' === $redirect_to ) {
		$redirect_to = home_url( '/' );
	}
	$stored = array(
		'user_id'          => absint( $payload['user_id'] ?? 0 ),
		'remember'         => ! empty( $payload['remember'] ),
		'redirect_to'      => $redirect_to,
		'fingerprint'      => (string) ( $payload['fingerprint'] ?? '' ),
		'expires_at'       => absint( $payload['expires_at'] ?? 0 ),
		'methods'          => array_values( array_map( 'sanitize_key', $payload['methods'] ?? array() ) ),
		'method'           => sanitize_key( $payload['method'] ?? '' ),
		'otp_challenge_id' => absint( $payload['otp_challenge_id'] ?? 0 ),
	);
	$encrypted = identity_security_kit_encrypt_secret( wp_json_encode( $stored ) );
	if ( is_wp_error( $encrypted ) ) {
		return $encrypted;
	}
	$ttl = max( 1, $stored['expires_at'] - time() );
	set_transient( 'isk_login_' . $token_hash, $encrypted, $ttl );

	return true;
}

/** Create a browser-bound, one-time challenge after password validation. */
function identity_security_kit_create_login_challenge( $user_id, $remember = false, $redirect_to = '' ) {
	$user_id = absint( $user_id );
	$methods = identity_security_kit_get_login_mfa_methods( $user_id );
	if ( empty( $methods ) ) {
		return new WP_Error( 'mfa_not_enabled', __( 'Two-factor authentication is not enabled.', 'identity-security-kit' ) );
	}
	try {
		$token = identity_security_kit_base64url_encode( random_bytes( 24 ) );
	} catch ( Exception $exception ) {
		return new WP_Error( 'mfa_challenge_failed', __( 'The security challenge could not be created.', 'identity-security-kit' ) );
	}

	$token_hash = hash( 'sha256', $token );
	$old_hash   = (string) get_user_meta( $user_id, 'identity_mfa_login_challenge', true );
	if ( preg_match( '/^[a-f0-9]{64}$/', $old_hash ) ) {
		delete_transient( 'isk_login_' . $old_hash );
	}
	$preferred       = identity_security_kit_get_preferred_mfa_method( $user_id );
	$safe_redirect   = wp_validate_redirect( $redirect_to, home_url( '/' ) );
	$safe_redirect   = '' !== $safe_redirect ? $safe_redirect : home_url( '/' );
	$payload   = array(
		'user_id'          => $user_id,
		'remember'         => (bool) $remember,
		'redirect_to'      => $safe_redirect,
		'fingerprint'      => identity_security_kit_get_rate_limit_fingerprint(),
		'expires_at'       => time() + ( 5 * MINUTE_IN_SECONDS ),
		'methods'          => $methods,
		'method'           => in_array( $preferred, $methods, true ) ? $preferred : $methods[0],
		'otp_challenge_id' => 0,
	);
	$stored = identity_security_kit_store_login_challenge_payload( $token_hash, $payload );
	if ( is_wp_error( $stored ) ) {
		return $stored;
	}
	update_user_meta( $user_id, 'identity_mfa_login_challenge', $token_hash );
	identity_security_kit_log_event( 'mfa_login_challenge_created', 'info', $user_id, array( 'methods' => $methods ) );

	return add_query_arg( array( 'action' => 'identity_security_mfa', 'token' => $token ), wp_login_url() );
}

/** Read and validate a pending login challenge. */
function identity_security_kit_get_login_challenge( $token ) {
	$token = preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $token );
	if ( strlen( $token ) < 30 ) {
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	$token_hash = hash( 'sha256', $token );
	$encrypted  = get_transient( 'isk_login_' . $token_hash );
	if ( ! is_string( $encrypted ) ) {
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	$decrypted = identity_security_kit_decrypt_secret( $encrypted );
	$payload   = is_wp_error( $decrypted ) ? array() : json_decode( $decrypted, true );
	if ( ! is_array( $payload ) || empty( $payload['user_id'] ) || empty( $payload['fingerprint'] ) || empty( $payload['expires_at'] ) || ! is_array( $payload['methods'] ?? null ) ) {
		delete_transient( 'isk_login_' . $token_hash );
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	if ( absint( $payload['expires_at'] ) < time() || ! hash_equals( (string) $payload['fingerprint'], identity_security_kit_get_rate_limit_fingerprint() ) ) {
		delete_transient( 'isk_login_' . $token_hash );
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	$user            = get_userdata( absint( $payload['user_id'] ) );
	$current_methods = $user ? identity_security_kit_get_login_mfa_methods( $user->ID ) : array();
	$payload_methods = array_values( array_intersect( array_map( 'sanitize_key', $payload['methods'] ), $current_methods ) );
	if ( ! $user || empty( $payload_methods ) || ! hash_equals( $token_hash, (string) get_user_meta( $user->ID, 'identity_mfa_login_challenge', true ) ) ) {
		delete_transient( 'isk_login_' . $token_hash );
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	$payload['methods']    = $payload_methods;
	$payload['method']     = in_array( sanitize_key( $payload['method'] ?? '' ), $payload_methods, true ) ? sanitize_key( $payload['method'] ) : $payload_methods[0];
	$payload['token_hash'] = $token_hash;
	$payload['user']       = $user;

	return $payload;
}

/** Select a method and deliver its remote code when needed. */
function identity_security_kit_prepare_login_method( $token, $method ) {
	$payload = identity_security_kit_get_login_challenge( $token );
	$method  = sanitize_key( $method );
	if ( is_wp_error( $payload ) ) {
		return $payload;
	}
	if ( ! in_array( $method, $payload['methods'], true ) ) {
		return new WP_Error( 'mfa_method_invalid', __( 'This verification method is not available.', 'identity-security-kit' ) );
	}

	$challenge_id = 0;
	if ( 'email' === $method ) {
		$challenge_id = identity_security_kit_create_email_otp_challenge( $payload['user']->ID, 'login_second_factor' );
	} elseif ( 'sms' === $method ) {
		$challenge_id = identity_security_kit_create_phone_otp_challenge( $payload['user']->ID, 'login_second_factor' );
	}
	if ( is_wp_error( $challenge_id ) ) {
		return $challenge_id;
	}
	$payload['method']           = $method;
	$payload['otp_challenge_id'] = absint( $challenge_id );
	$stored = identity_security_kit_store_login_challenge_payload( $payload['token_hash'], $payload );
	if ( is_wp_error( $stored ) ) {
		return $stored;
	}
	identity_security_kit_log_event( 'mfa_login_method_prepared', 'info', $payload['user']->ID, array( 'method' => $method ) );

	return identity_security_kit_get_login_challenge( $token );
}

/** Verify the selected factor and atomically consume the browser challenge. */
function identity_security_kit_consume_login_challenge( $token, $code, $method = '' ) {
	$payload = identity_security_kit_get_login_challenge( $token );
	$method  = sanitize_key( $method );
	if ( ! is_wp_error( $payload ) && '' === $method ) {
		$method = sanitize_key( $payload['method'] );
	}
	if ( is_wp_error( $payload ) ) {
		return $payload;
	}
	if ( ! in_array( $method, $payload['methods'], true ) || $method !== $payload['method'] ) {
		return new WP_Error( 'mfa_method_invalid', __( 'Select and prepare the verification method again.', 'identity-security-kit' ) );
	}
	if ( 'totp' === $method ) {
		$verify = identity_security_kit_verify_totp_for_user( $payload['user']->ID, $code );
	} elseif ( 'recovery' === $method ) {
		$verify = identity_security_kit_verify_recovery_code( $payload['user']->ID, $code );
	} elseif ( ! absint( $payload['otp_challenge_id'] ?? 0 ) ) {
		return new WP_Error( 'mfa_code_not_sent', __( 'Send a security code before verifying.', 'identity-security-kit' ) );
	} elseif ( 'email' === $method ) {
		$verify = identity_security_kit_verify_email_otp_challenge( $payload['otp_challenge_id'], $payload['user']->ID, $code, 'login_second_factor' );
	} elseif ( 'sms' === $method ) {
		$verify = identity_security_kit_verify_phone_otp_challenge( $payload['otp_challenge_id'], $payload['user']->ID, $code, 'login_second_factor' );
	} else {
		$verify = new WP_Error( 'mfa_method_invalid', __( 'This verification method is not available.', 'identity-security-kit' ) );
	}
	if ( is_wp_error( $verify ) ) {
		return $verify;
	}
	delete_transient( 'isk_login_' . $payload['token_hash'] );
	delete_user_meta( $payload['user']->ID, 'identity_mfa_login_challenge', $payload['token_hash'] );
	identity_security_kit_log_event( 'mfa_login_challenge_verified', 'success', $payload['user']->ID, array( 'method' => $method ) );

	return $payload;
}

/** Intercept native password login after WordPress validates the password. */
function identity_security_kit_require_mfa_on_native_login( $user, $password ) {
	if ( is_wp_error( $user ) || ! $user instanceof WP_User || ! identity_security_kit_user_has_mfa_method( $user->ID ) ) {
		return $user;
	}
	if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
		return new WP_Error( 'mfa_required', __( 'Password authentication is disabled for this account on XML-RPC. Use an application password.', 'identity-security-kit' ) );
	}
	if ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
		return $user;
	}
	$script = isset( $GLOBALS['pagenow'] ) ? (string) $GLOBALS['pagenow'] : '';
	$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
	if ( 'wp-login.php' !== $script || 'identity_security_mfa' === $action || ! identity_security_kit_is_post_request() ) {
		return $user;
	}
	$remember    = ! empty( $_POST['rememberme'] );
	$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url();
	$url         = identity_security_kit_create_login_challenge( $user->ID, $remember, $redirect_to );
	if ( is_wp_error( $url ) ) {
		return $url;
	}
	wp_safe_redirect( $url );
	exit;
}
add_filter( 'wp_authenticate_user', 'identity_security_kit_require_mfa_on_native_login', 99, 2 );

/** Render and process the native wp-login.php MFA action. */
function identity_security_kit_handle_native_mfa_login() {
	$token = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
	$error = null;
	if ( identity_security_kit_is_post_request() ) {
		$nonce  = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		$intent = isset( $_POST['mfa_intent'] ) ? sanitize_key( wp_unslash( $_POST['mfa_intent'] ) ) : 'verify';
		$method = isset( $_POST['mfa_method'] ) ? sanitize_key( wp_unslash( $_POST['mfa_method'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'identity_security_mfa_login_' . $token ) ) {
			$error = new WP_Error( 'mfa_nonce_failed', __( 'Security verification failed. Start the login again.', 'identity-security-kit' ) );
		} elseif ( 'send' === $intent ) {
			$result = identity_security_kit_prepare_login_method( $token, $method );
			$error  = is_wp_error( $result ) ? $result : null;
		} else {
			$code   = isset( $_POST['mfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mfa_code'] ) ) : '';
			$result = identity_security_kit_consume_login_challenge( $token, $code, $method );
			if ( is_wp_error( $result ) ) {
				$error = $result;
			} else {
				$user = $result['user'];
				wp_set_current_user( $user->ID );
				wp_set_auth_cookie( $user->ID, ! empty( $result['remember'] ), is_ssl() );
				do_action( 'wp_login', $user->user_login, $user );
				$destination = identity_security_kit_get_login_redirect( $user, $result['redirect_to'] );
				identity_security_kit_log_event( 'mfa_login_redirect', 'success', $user->ID, array( 'destination_path' => (string) wp_parse_url( $destination, PHP_URL_PATH ) ) );
				wp_safe_redirect( $destination, 303 );
				exit;
			}
		}
	}
	$challenge = identity_security_kit_get_login_challenge( $token );
	if ( is_wp_error( $challenge ) && ! $error ) {
		$error = $challenge;
	}
	login_header( __( 'Security verification', 'identity-security-kit' ), '', $error );
	if ( ! is_wp_error( $challenge ) ) :
		$selected = $challenge['method'];
		$remote = in_array( $selected, array( 'email', 'sms' ), true );
		$sent   = $remote && ! empty( $challenge['otp_challenge_id'] );
		?>
		<div class="isk-login-intro"><span><?php esc_html_e( 'Account protection', 'identity-security-kit' ); ?></span><h2><?php esc_html_e( 'Confirm that it is really you', 'identity-security-kit' ); ?></h2><p><?php esc_html_e( 'Choose an available verification method, then enter the security code to continue to your original destination.', 'identity-security-kit' ); ?></p></div>
		<form name="identity-security-mfa" id="identity-security-mfa" action="<?php echo esc_url( add_query_arg( 'action', 'identity_security_mfa', wp_login_url() ) ); ?>" method="post">
			<fieldset><legend><?php esc_html_e( 'Verification method', 'identity-security-kit' ); ?></legend><div class="isk-login-methods">
			<?php foreach ( $challenge['methods'] as $method ) : ?>
				<label class="isk-login-method"><input type="radio" name="mfa_method" value="<?php echo esc_attr( $method ); ?>" <?php checked( $selected, $method ); ?>><span><strong><?php echo esc_html( identity_security_kit_get_mfa_method_label( $method ) ); ?></strong><?php $destination = identity_security_kit_get_masked_mfa_destination( $challenge['user']->ID, $method ); ?><?php if ( $destination ) : ?><small><?php echo esc_html( $destination ); ?></small><?php endif; ?></span></label>
			<?php endforeach; ?>
			</div></fieldset>
			<p><label for="mfa_code"><?php esc_html_e( 'Security code', 'identity-security-kit' ); ?><br><input type="text" name="mfa_code" id="mfa_code" class="input" autocomplete="one-time-code"></label></p>
			<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>">
			<?php wp_nonce_field( 'identity_security_mfa_login_' . $token ); ?>
			<p class="submit"><button type="submit" name="mfa_intent" value="send" class="button"><?php esc_html_e( 'Use this method / send code', 'identity-security-kit' ); ?></button> <button type="submit" name="mfa_intent" value="verify" class="button button-primary"><?php esc_html_e( 'Verify and sign in', 'identity-security-kit' ); ?></button></p>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Restart login', 'identity-security-kit' ); ?></a></p>
		<?php
	endif;
	login_footer();
	exit;
}
add_action( 'login_form_identity_security_mfa', 'identity_security_kit_handle_native_mfa_login' );

/** Load the self-contained MFA login presentation only for this login action. */
function identity_security_kit_enqueue_mfa_login_assets() {
	$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
	if ( 'identity_security_mfa' !== $action ) {
		return;
	}

	wp_enqueue_style(
		'identity-security-kit-mfa-login',
		IDENTITY_SECURITY_KIT_URL . 'assets/css/mfa-login.css',
		array( 'login' ),
		IDENTITY_SECURITY_KIT_VERSION
	);
}
add_action( 'login_enqueue_scripts', 'identity_security_kit_enqueue_mfa_login_assets' );
