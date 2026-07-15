<?php
/**
 * Professional HTML and plain-text transactional email rendering.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function identity_security_kit_sanitize_email_text( $value, $max_length = 500 ) {
	$value = is_scalar( $value ) ? (string) $value : '';

	return substr( sanitize_text_field( $value ), 0, max( 1, absint( $max_length ) ) );
}

function identity_security_kit_get_email_brand() {
	$brand = array(
		'name'       => wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ),
		'accent'     => '#1f6f54',
		'background' => '#f3f1ec',
		'website'    => home_url( '/' ),
	);

	/** Filter safe visual identity values used by transactional emails. */
	$brand = apply_filters( 'identity_security_kit_email_brand', $brand );
	$brand = is_array( $brand ) ? $brand : array();

	return array(
		'name'       => identity_security_kit_sanitize_email_text( $brand['name'] ?? get_bloginfo( 'name' ), 120 ),
		'accent'     => sanitize_hex_color( is_scalar( $brand['accent'] ?? null ) ? (string) $brand['accent'] : '' ) ?: '#1f6f54',
		'background' => sanitize_hex_color( is_scalar( $brand['background'] ?? null ) ? (string) $brand['background'] : '' ) ?: '#f3f1ec',
		'website'    => esc_url_raw( is_scalar( $brand['website'] ?? null ) ? (string) $brand['website'] : home_url( '/' ) ),
	);
}

/** Normalize semantic email content before rendering either representation. */
function identity_security_kit_prepare_email_content( $content ) {
	$content = is_array( $content ) ? $content : array();
	$details = isset( $content['details'] ) && is_array( $content['details'] ) ? array_slice( $content['details'], 0, 12 ) : array();
	$details = array_map( 'identity_security_kit_sanitize_email_text', $details );

	return array(
		'preheader'    => identity_security_kit_sanitize_email_text( $content['preheader'] ?? '', 255 ),
		'eyebrow'      => identity_security_kit_sanitize_email_text( $content['eyebrow'] ?? __( 'Account security', 'identity-security-kit' ), 80 ),
		'title'        => identity_security_kit_sanitize_email_text( $content['title'] ?? '', 190 ),
		'greeting'     => identity_security_kit_sanitize_email_text( $content['greeting'] ?? '', 190 ),
		'intro'        => identity_security_kit_sanitize_email_text( $content['intro'] ?? '' ),
		'details'      => array_values( array_filter( $details ) ),
		'code'         => substr( preg_replace( '/[^A-Za-z0-9-]/', '', is_scalar( $content['code'] ?? null ) ? (string) $content['code'] : '' ), 0, 32 ),
		'action_url'   => esc_url_raw( is_scalar( $content['action_url'] ?? null ) ? (string) $content['action_url'] : '' ),
		'action_label' => identity_security_kit_sanitize_email_text( $content['action_label'] ?? '', 120 ),
		'notice'       => identity_security_kit_sanitize_email_text( $content['notice'] ?? '' ),
	);
}

function identity_security_kit_render_email_text( $content ) {
	$content = identity_security_kit_prepare_email_content( $content );
	$lines   = array_filter( array( $content['title'], $content['greeting'], $content['intro'] ), 'strlen' );
	$lines   = array_merge( $lines, $content['details'] );
	if ( '' !== $content['code'] ) {
		$lines[] = sprintf( __( 'Your one-time security code is: %s', 'identity-security-kit' ), $content['code'] );
	}
	if ( '' !== $content['action_url'] ) {
		$lines[] = ( '' !== $content['action_label'] ? $content['action_label'] . ':' : __( 'Secure link:', 'identity-security-kit' ) ) . "\n" . $content['action_url'];
	}
	if ( '' !== $content['notice'] ) {
		$lines[] = $content['notice'];
	}

	return implode( "\n\n", $lines );
}

function identity_security_kit_render_email_html( $content ) {
	$content = identity_security_kit_prepare_email_content( $content );
	$brand   = identity_security_kit_get_email_brand();
	$accent  = $brand['accent'];
	$background = $brand['background'];
	ob_start();
	?><!doctype html>
<html lang="<?php echo esc_attr( get_bloginfo( 'language' ) ); ?>">
<head><meta charset="<?php echo esc_attr( get_bloginfo( 'charset' ) ); ?>"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?php echo esc_html( $content['title'] ); ?></title></head>
<body style="margin:0;padding:0;background:<?php echo esc_attr( $background ); ?>;color:#20231f;font-family:Arial,sans-serif;">
	<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;"><?php echo esc_html( $content['preheader'] ); ?></div>
	<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:<?php echo esc_attr( $background ); ?>;padding:24px 12px;"><tr><td align="center">
		<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:620px;background:#ffffff;border:1px solid #dedbd4;">
			<tr><td style="padding:24px 32px;border-bottom:1px solid #e9e6df;font-family:Georgia,serif;font-size:22px;color:#171a17;"><?php echo esc_html( $brand['name'] ); ?></td></tr>
			<tr><td style="padding:40px 32px;">
				<p style="margin:0 0 12px;color:<?php echo esc_attr( $accent ); ?>;font-size:12px;font-weight:bold;text-transform:uppercase;letter-spacing:0;"><?php echo esc_html( $content['eyebrow'] ); ?></p>
				<h1 style="margin:0 0 24px;font-family:Georgia,serif;font-size:32px;line-height:1.2;font-weight:normal;color:#171a17;"><?php echo esc_html( $content['title'] ); ?></h1>
				<?php if ( '' !== $content['greeting'] ) : ?><p style="margin:0 0 16px;font-size:16px;line-height:1.7;"><?php echo esc_html( $content['greeting'] ); ?></p><?php endif; ?>
				<?php if ( '' !== $content['intro'] ) : ?><p style="margin:0 0 16px;font-size:16px;line-height:1.7;"><?php echo esc_html( $content['intro'] ); ?></p><?php endif; ?>
				<?php foreach ( $content['details'] as $detail ) : ?><p style="margin:0 0 16px;font-size:15px;line-height:1.7;color:#4a4f49;"><?php echo esc_html( $detail ); ?></p><?php endforeach; ?>
				<?php if ( '' !== $content['code'] ) : ?><div style="margin:28px 0;padding:20px;border:1px solid #d7e4de;background:#f2f8f5;text-align:center;"><p style="margin:0 0 8px;font-size:13px;color:#4a4f49;"><?php esc_html_e( 'Your one-time security code is:', 'identity-security-kit' ); ?></p><p style="margin:0;font-family:Consolas,monospace;font-size:32px;font-weight:bold;letter-spacing:0;color:#171a17;"><?php echo esc_html( $content['code'] ); ?></p></div><?php endif; ?>
				<?php if ( '' !== $content['action_url'] && '' !== $content['action_label'] ) : ?><table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:28px 0;"><tr><td style="background:<?php echo esc_attr( $accent ); ?>;"><a href="<?php echo esc_url( $content['action_url'] ); ?>" style="display:inline-block;padding:14px 22px;color:#ffffff;text-decoration:none;font-size:15px;font-weight:bold;"><?php echo esc_html( $content['action_label'] ); ?></a></td></tr></table><p style="margin:0 0 20px;font-size:12px;line-height:1.6;color:#656b65;overflow-wrap:anywhere;"><?php echo esc_html( $content['action_url'] ); ?></p><?php endif; ?>
				<?php if ( '' !== $content['notice'] ) : ?><div style="margin-top:28px;padding:16px;border-left:3px solid <?php echo esc_attr( $accent ); ?>;background:#f7f7f5;font-size:13px;line-height:1.6;color:#4a4f49;"><?php echo esc_html( $content['notice'] ); ?></div><?php endif; ?>
			</td></tr>
			<tr><td style="padding:20px 32px;border-top:1px solid #e9e6df;font-size:12px;line-height:1.6;color:#686d68;"><?php echo esc_html( sprintf( __( 'Automated message from %s.', 'identity-security-kit' ), $brand['name'] ) ); ?> <a href="<?php echo esc_url( $brand['website'] ); ?>" style="color:<?php echo esc_attr( $accent ); ?>;"><?php esc_html_e( 'Visit the website', 'identity-security-kit' ); ?></a></td></tr>
		</table>
	</td></tr></table>
</body></html><?php

	return (string) ob_get_clean();
}

/** Send one scoped multipart transactional email through the WordPress stack. */
function identity_security_kit_send_transactional_email( $to, $subject, $content, $reply_to = '' ) {
	$to      = sanitize_email( $to );
	$subject = sanitize_text_field( $subject );
	$reply_to = sanitize_email( $reply_to );
	if ( ! is_email( $to ) || '' === $subject ) {
		return false;
	}

	$html     = identity_security_kit_render_email_html( $content );
	$alt_body = identity_security_kit_render_email_text( $content );
	$set_alt_body = static function ( $phpmailer ) use ( $alt_body ) {
		$phpmailer->AltBody = $alt_body;
	};
	$headers = array( 'Content-Type: text/html; charset=UTF-8' );
	if ( is_email( $reply_to ) ) {
		$headers[] = 'Reply-To: ' . $reply_to;
	}
	add_action( 'phpmailer_init', $set_alt_body );
	try {
		return wp_mail( $to, $subject, $html, $headers );
	} finally {
		remove_action( 'phpmailer_init', $set_alt_body );
	}
}

/** Apply an AltBody to the next WordPress email only. */
function identity_security_kit_register_next_email_alt_body( $alt_body ) {
	$alt_body = trim( (string) $alt_body );
	$callback = null;
	$callback = static function ( $phpmailer ) use ( $alt_body, &$callback ) {
		$phpmailer->AltBody = $alt_body;
		remove_action( 'phpmailer_init', $callback );
	};
	add_action( 'phpmailer_init', $callback );
}

/** Render the native WordPress email-change notice with the Identity layout. */
function identity_security_kit_filter_email_change_email( $email, $user, $userdata ) {
	$name      = identity_security_kit_sanitize_email_text( $user['display_name'] ?? $user['user_login'] ?? __( 'there', 'identity-security-kit' ), 190 );
	$new_email = sanitize_email( $userdata['user_email'] ?? '' );
	$content   = array(
		'preheader' => __( 'The email address on your account was changed.', 'identity-security-kit' ),
		'title'     => __( 'Email address changed', 'identity-security-kit' ),
		'greeting'  => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $name ),
		'intro'     => sprintf( __( 'This notice confirms that the email address on your account was changed to %s.', 'identity-security-kit' ), $new_email ),
		'notice'    => sprintf( __( 'If you did not make this change, reset your password and contact the site administrator at %s.', 'identity-security-kit' ), sanitize_email( get_option( 'admin_email' ) ) ),
	);
	$email['message'] = identity_security_kit_render_email_html( $content );
	$email['headers'] = 'Content-Type: text/html; charset=UTF-8';
	identity_security_kit_register_next_email_alt_body( identity_security_kit_render_email_text( $content ) );

	return $email;
}
add_filter( 'email_change_email', 'identity_security_kit_filter_email_change_email', 10, 3 );

/** Render the native WordPress password-change notice with the Identity layout. */
function identity_security_kit_filter_password_change_email( $email, $user, $userdata ) {
	$name    = identity_security_kit_sanitize_email_text( $user['display_name'] ?? $user['user_login'] ?? __( 'there', 'identity-security-kit' ), 190 );
	$content = array(
		'preheader' => __( 'The password on your account was changed.', 'identity-security-kit' ),
		'title'     => __( 'Password changed', 'identity-security-kit' ),
		'greeting'  => sprintf( __( 'Hello %s,', 'identity-security-kit' ), $name ),
		'intro'     => __( 'This notice confirms that the password on your account was changed.', 'identity-security-kit' ),
		'notice'    => sprintf( __( 'If you did not make this change, contact the site administrator immediately at %s.', 'identity-security-kit' ), sanitize_email( get_option( 'admin_email' ) ) ),
	);
	$email['message'] = identity_security_kit_render_email_html( $content );
	$email['headers'] = 'Content-Type: text/html; charset=UTF-8';
	identity_security_kit_register_next_email_alt_body( identity_security_kit_render_email_text( $content ) );

	return $email;
}
add_filter( 'password_change_email', 'identity_security_kit_filter_password_change_email', 10, 3 );
