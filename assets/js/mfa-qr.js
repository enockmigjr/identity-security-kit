( function () {
	'use strict';

	function renderAuthenticatorCodes() {
		if ( typeof window.QRCode !== 'function' ) {
			return;
		}

		document.querySelectorAll( '[data-identity-totp-uri]' ).forEach( function ( enrollment ) {
			var target = enrollment.querySelector( '.identity-totp-qr__canvas' );
			var uri = enrollment.getAttribute( 'data-identity-totp-uri' );

			if ( ! target || ! uri || target.dataset.rendered === 'true' ) {
				return;
			}

			new window.QRCode( target, {
				text: uri,
				width: 220,
				height: 220,
				colorDark: '#111111',
				colorLight: '#ffffff',
				correctLevel: window.QRCode.CorrectLevel.M,
			} );
			target.dataset.rendered = 'true';
		} );
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', renderAuthenticatorCodes );
	} else {
		renderAuthenticatorCodes();
	}
}() );
