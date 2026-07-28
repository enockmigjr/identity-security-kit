<?php
/**
 * Public second-factor challenge.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$token     = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';
$challenge = identity_security_kit_get_login_challenge( $token );
$state     = is_wp_error( $challenge ) ? array() : identity_security_kit_get_public_mfa_state( $challenge );
$selected  = $state['method'] ?? '';
$methods   = $state['methods'] ?? array();
$current   = array();
foreach ( $methods as $method ) {
	if ( $method['id'] === $selected ) {
		$current = $method;
		break;
	}
}

get_header();
?>
<main class="isk-mfa-shell">
	<section class="isk-mfa-context" aria-labelledby="isk-mfa-context-title">
		<div>
			<p class="isk-mfa-eyebrow"><?php esc_html_e( 'PhotoVault / Acces protege', 'identity-security-kit' ); ?></p>
			<h1 id="isk-mfa-context-title"><?php esc_html_e( 'Une derniere verification avant d ouvrir votre espace.', 'identity-security-kit' ); ?></h1>
		</div>
		<p><?php esc_html_e( 'Cette etape protege les collections privees, vos informations personnelles et les actions sensibles du compte.', 'identity-security-kit' ); ?></p>
	</section>

	<section class="isk-mfa-workspace" aria-labelledby="isk-mfa-title">
		<div class="isk-mfa-panel">
			<p class="isk-mfa-eyebrow"><?php esc_html_e( 'Verification de securite', 'identity-security-kit' ); ?></p>
			<h2 id="isk-mfa-title"><?php esc_html_e( 'Confirmez qu il s agit bien de vous', 'identity-security-kit' ); ?></h2>

			<?php if ( is_wp_error( $challenge ) ) : ?>
				<div class="isk-mfa-notice is-error" role="alert"><?php echo esc_html( $challenge->get_error_message() ); ?></div>
				<a class="isk-mfa-primary" href="<?php echo esc_url( home_url( '/login/' ) ); ?>"><?php esc_html_e( 'Recommencer la connexion', 'identity-security-kit' ); ?></a>
			<?php else : ?>
				<div
					data-isk-mfa
					data-token="<?php echo esc_attr( $token ); ?>"
					data-nonce="<?php echo esc_attr( wp_create_nonce( 'identity_security_mfa_rest_' . $token ) ); ?>"
					data-prepare-url="<?php echo esc_url( rest_url( 'identity-security-kit/v1/mfa/prepare' ) ); ?>"
					data-verify-url="<?php echo esc_url( rest_url( 'identity-security-kit/v1/mfa/verify' ) ); ?>"
					data-method="<?php echo esc_attr( $selected ); ?>"
					data-prepared="<?php echo ! empty( $state['prepared'] ) ? '1' : '0'; ?>"
				>
					<div class="isk-mfa-notice" role="status" data-isk-mfa-notice hidden></div>
					<div class="isk-mfa-method-current">
						<span class="isk-mfa-method-icon" aria-hidden="true"><?php echo esc_html( strtoupper( substr( $current['label'] ?? '2FA', 0, 1 ) ) ); ?></span>
						<div><strong data-isk-current-label><?php echo esc_html( $current['label'] ?? '' ); ?></strong><small data-isk-current-destination><?php echo esc_html( $current['destination'] ?? '' ); ?></small></div>
					</div>

					<button class="isk-mfa-primary" type="button" data-isk-prepare <?php echo ! empty( $state['prepared'] ) ? 'hidden' : ''; ?>><?php esc_html_e( 'Utiliser cette methode', 'identity-security-kit' ); ?></button>

					<form class="isk-mfa-code" data-isk-code-form <?php echo empty( $state['prepared'] ) ? 'hidden' : ''; ?>>
						<label for="isk-mfa-code"><?php esc_html_e( 'Code de securite', 'identity-security-kit' ); ?></label>
						<input id="isk-mfa-code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" required>
						<button class="isk-mfa-primary" type="submit"><?php esc_html_e( 'Verifier et continuer', 'identity-security-kit' ); ?></button>
					</form>

					<details class="isk-mfa-alternatives">
						<summary><?php esc_html_e( 'Utiliser une autre methode', 'identity-security-kit' ); ?></summary>
						<div class="isk-mfa-method-list">
							<?php foreach ( $methods as $method ) : ?>
								<?php if ( $method['id'] === $selected ) : continue; endif; ?>
								<button type="button" data-isk-method="<?php echo esc_attr( $method['id'] ); ?>" data-label="<?php echo esc_attr( $method['label'] ); ?>" data-destination="<?php echo esc_attr( $method['destination'] ); ?>">
									<strong><?php echo esc_html( $method['label'] ); ?></strong>
									<?php if ( $method['destination'] ) : ?><small><?php echo esc_html( $method['destination'] ); ?></small><?php endif; ?>
								</button>
							<?php endforeach; ?>
						</div>
					</details>
				</div>
				<a class="isk-mfa-restart" href="<?php echo esc_url( home_url( '/login/' ) ); ?>"><?php esc_html_e( 'Recommencer la connexion', 'identity-security-kit' ); ?></a>
			<?php endif; ?>
		</div>
	</section>
</main>
<?php get_footer(); ?>
