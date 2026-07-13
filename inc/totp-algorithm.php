<?php
/**
 * RFC 4226 / RFC 6238 primitives for Identity Security Kit.
 *
 * @package IdentitySecurityKit
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encode binary data using unpadded RFC 4648 Base32.
 *
 * @param string $binary Binary data.
 * @return string
 */
function identity_security_kit_base32_encode( $binary ) {
	$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	$bits     = '';
	$output   = '';

	foreach ( unpack( 'C*', (string) $binary ) as $byte ) {
		$bits .= str_pad( decbin( $byte ), 8, '0', STR_PAD_LEFT );
	}

	foreach ( str_split( $bits, 5 ) as $chunk ) {
		$chunk   = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
		$output .= $alphabet[ bindec( $chunk ) ];
	}

	return $output;
}

/**
 * Decode RFC 4648 Base32.
 *
 * @param string $encoded Base32 string.
 * @return string|false
 */
function identity_security_kit_base32_decode( $encoded ) {
	$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	$encoded  = strtoupper( preg_replace( '/[\s=-]+/', '', (string) $encoded ) );
	if ( '' === $encoded || preg_match( '/[^A-Z2-7]/', $encoded ) ) {
		return false;
	}

	$bits = '';
	foreach ( str_split( $encoded ) as $character ) {
		$position = strpos( $alphabet, $character );
		if ( false === $position ) {
			return false;
		}
		$bits .= str_pad( decbin( $position ), 5, '0', STR_PAD_LEFT );
	}

	$output = '';
	foreach ( str_split( $bits, 8 ) as $byte ) {
		if ( 8 === strlen( $byte ) ) {
			$output .= chr( bindec( $byte ) );
		}
	}

	return $output;
}

/**
 * Pack a non-negative counter as an unsigned 64-bit big-endian value.
 *
 * @param int $counter Counter.
 * @return string
 */
function identity_security_kit_pack_counter( $counter ) {
	$counter = max( 0, (int) $counter );
	$high    = intdiv( $counter, 4294967296 );
	$low     = $counter % 4294967296;

	return pack( 'N2', $high, $low );
}

/**
 * Generate a TOTP value for a specific timestamp.
 *
 * @param string $secret    Base32 secret.
 * @param int    $timestamp Unix timestamp.
 * @param int    $digits    Output digits.
 * @param int    $period    Time step in seconds.
 * @return string|false
 */
function identity_security_kit_totp_at( $secret, $timestamp, $digits = 6, $period = 30 ) {
	$binary = identity_security_kit_base32_decode( $secret );
	$digits = max( 6, min( 8, absint( $digits ) ) );
	$period = max( 15, min( 120, absint( $period ) ) );
	if ( false === $binary || '' === $binary ) {
		return false;
	}

	$counter = intdiv( max( 0, (int) $timestamp ), $period );
	$hash    = hash_hmac( 'sha1', identity_security_kit_pack_counter( $counter ), $binary, true );
	$offset  = ord( substr( $hash, -1 ) ) & 0x0f;
	$value   = unpack( 'N', substr( $hash, $offset, 4 ) )[1] & 0x7fffffff;
	$modulo  = 10 ** $digits;

	return str_pad( (string) ( $value % $modulo ), $digits, '0', STR_PAD_LEFT );
}

/**
 * Verify a TOTP value and return the matching time counter.
 *
 * @param string $secret    Base32 secret.
 * @param string $code      Submitted code.
 * @param int    $timestamp Unix timestamp.
 * @param int    $window    Allowed steps before/after current time.
 * @param int    $digits    Code digits.
 * @param int    $period    Time step.
 * @return int|false
 */
function identity_security_kit_totp_verify_counter( $secret, $code, $timestamp, $window = 1, $digits = 6, $period = 30 ) {
	$code   = preg_replace( '/\D+/', '', (string) $code );
	$window = max( 0, min( 2, absint( $window ) ) );
	$digits = max( 6, min( 8, absint( $digits ) ) );
	$period = max( 15, min( 120, absint( $period ) ) );
	if ( ! preg_match( '/^[0-9]{' . $digits . '}$/', $code ) ) {
		return false;
	}

	$current_counter = intdiv( max( 0, (int) $timestamp ), $period );
	for ( $offset = -$window; $offset <= $window; $offset++ ) {
		$counter = $current_counter + $offset;
		if ( $counter < 0 ) {
			continue;
		}
		$expected = identity_security_kit_totp_at( $secret, $counter * $period, $digits, $period );
		if ( is_string( $expected ) && hash_equals( $expected, $code ) ) {
			return $counter;
		}
	}

	return false;
}
