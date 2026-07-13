<?php
/**
 * Browser-bound MFA login challenges for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Create a browser-bound, one-time login challenge after password validation.
 *
 * @param int    $user_id    User ID.
 * @param bool   $remember   Remember session preference.
 * @param string $redirect_to Safe post-login target.
 * @return string|WP_Error Challenge URL.
 */
function identity_security_kit_create_login_challenge( $user_id, $remember = false, $redirect_to = '' ) {
	$user_id = absint( $user_id );
	if ( ! identity_security_kit_is_totp_enabled( $user_id ) ) {
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
	$payload = array(
		'user_id'      => $user_id,
		'remember'     => (bool) $remember,
		'redirect_to'  => wp_validate_redirect( $redirect_to, home_url( '/' ) ),
		'fingerprint'  => identity_security_kit_get_rate_limit_fingerprint(),
		'expires_at'   => time() + ( 5 * MINUTE_IN_SECONDS ),
	);
	$encrypted = identity_security_kit_encrypt_secret( wp_json_encode( $payload ) );
	if ( is_wp_error( $encrypted ) ) {
		return $encrypted;
	}
	set_transient( 'isk_login_' . $token_hash, $encrypted, 5 * MINUTE_IN_SECONDS );
	update_user_meta( $user_id, 'identity_mfa_login_challenge', $token_hash );
	identity_security_kit_log_event( 'mfa_login_challenge_created', 'info', $user_id );

	return add_query_arg(
		array(
			'action' => 'identity_security_mfa',
			'token'  => $token,
		),
		wp_login_url()
	);
}

/**
 * Read and validate a pending login challenge.
 *
 * @param string $token Raw challenge token.
 * @return array<string,mixed>|WP_Error
 */
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
	if ( ! is_array( $payload ) || empty( $payload['user_id'] ) || empty( $payload['fingerprint'] ) || empty( $payload['expires_at'] ) ) {
		delete_transient( 'isk_login_' . $token_hash );
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	if ( absint( $payload['expires_at'] ) < time() || ! hash_equals( (string) $payload['fingerprint'], identity_security_kit_get_rate_limit_fingerprint() ) ) {
		delete_transient( 'isk_login_' . $token_hash );
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	$user = get_userdata( absint( $payload['user_id'] ) );
	if ( ! $user || ! identity_security_kit_is_totp_enabled( $user->ID ) || ! hash_equals( $token_hash, (string) get_user_meta( $user->ID, 'identity_mfa_login_challenge', true ) ) ) {
		delete_transient( 'isk_login_' . $token_hash );
		return new WP_Error( 'mfa_challenge_invalid', __( 'The security challenge is invalid or expired.', 'identity-security-kit' ) );
	}
	$payload['token_hash'] = $token_hash;
	$payload['user']       = $user;

	return $payload;
}

/**
 * Verify and atomically consume a pending login challenge.
 *
 * @param string $token Challenge token.
 * @param string $code  Authenticator or recovery code.
 * @return array<string,mixed>|WP_Error
 */
function identity_security_kit_consume_login_challenge( $token, $code ) {
	$payload = identity_security_kit_get_login_challenge( $token );
	if ( is_wp_error( $payload ) ) {
		return $payload;
	}
	$verify = identity_security_kit_verify_totp_or_recovery( $payload['user']->ID, $code );
	if ( is_wp_error( $verify ) ) {
		return $verify;
	}
	delete_transient( 'isk_login_' . $payload['token_hash'] );
	delete_user_meta( $payload['user']->ID, 'identity_mfa_login_challenge', $payload['token_hash'] );
	identity_security_kit_log_event( 'mfa_login_challenge_verified', 'success', $payload['user']->ID );

	return $payload;
}

/**
 * Intercept native password login after WordPress validates the password.
 *
 * @param WP_User|WP_Error $user Authenticated user or error.
 * @param string           $password Submitted password.
 * @return WP_User|WP_Error
 */
function identity_security_kit_require_mfa_on_native_login( $user, $password ) {
	if ( is_wp_error( $user ) || ! $user instanceof WP_User || ! identity_security_kit_is_totp_enabled( $user->ID ) ) {
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
		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'identity_security_mfa_login_' . $token ) ) {
			$error = new WP_Error( 'mfa_nonce_failed', __( 'Security verification failed. Start the login again.', 'identity-security-kit' ) );
		} else {
			$code   = isset( $_POST['mfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mfa_code'] ) ) : '';
			$result = identity_security_kit_consume_login_challenge( $token, $code );
			if ( is_wp_error( $result ) ) {
				$error = $result;
			} else {
				$user = $result['user'];
				wp_set_current_user( $user->ID );
				wp_set_auth_cookie( $user->ID, ! empty( $result['remember'] ), is_ssl() );
				do_action( 'wp_login', $user->user_login, $user );
				wp_safe_redirect( wp_validate_redirect( $result['redirect_to'], admin_url() ) );
				exit;
			}
		}
	}
	$challenge = identity_security_kit_get_login_challenge( $token );
	if ( is_wp_error( $challenge ) && ! $error ) {
		$error = $challenge;
	}
	login_header( __( 'Security verification', 'identity-security-kit' ), '', $error );
	?>
	<form name="identity-security-mfa" id="identity-security-mfa" action="<?php echo esc_url( add_query_arg( 'action', 'identity_security_mfa', wp_login_url() ) ); ?>" method="post">
		<p><label for="mfa_code"><?php esc_html_e( 'Authenticator or recovery code', 'identity-security-kit' ); ?><br><input type="text" name="mfa_code" id="mfa_code" class="input" inputmode="numeric" autocomplete="one-time-code" required></label></p>
		<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>">
		<?php wp_nonce_field( 'identity_security_mfa_login_' . $token ); ?>
		<p class="submit"><button type="submit" class="button button-primary button-large"><?php esc_html_e( 'Verify and sign in', 'identity-security-kit' ); ?></button></p>
	</form>
	<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Restart login', 'identity-security-kit' ); ?></a></p>
	<?php
	login_footer();
	exit;
}
add_action( 'login_form_identity_security_mfa', 'identity_security_kit_handle_native_mfa_login' );
