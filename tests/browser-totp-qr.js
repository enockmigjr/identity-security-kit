const assert = require( 'node:assert/strict' );
const { chromium } = require( 'playwright' );

( async () => {
	const baseUrl = process.env.IDENTITY_TEST_BASE_URL || 'http://localhost:8080';
	const username = process.env.IDENTITY_TEST_USERNAME;
	const password = process.env.IDENTITY_TEST_PASSWORD;
	const loginPath = process.env.IDENTITY_TEST_LOGIN_PATH || '/wp-login.php';
	const profilePath = process.env.IDENTITY_TEST_PROFILE_PATH || '/wp-admin/profile.php';
	const usernameSelector = process.env.IDENTITY_TEST_USERNAME_SELECTOR || '#user_login';
	const passwordSelector = process.env.IDENTITY_TEST_PASSWORD_SELECTOR || '#user_pass';
	const submitSelector = process.env.IDENTITY_TEST_SUBMIT_SELECTOR || '#wp-submit';

	assert.ok( username && password, 'Temporary WordPress credentials are required.' );

	const launchOptions = { headless: true };
	if ( process.env.IDENTITY_TEST_BROWSER ) {
		launchOptions.executablePath = process.env.IDENTITY_TEST_BROWSER;
	}
	const browser = await chromium.launch( launchOptions );
	const page = await browser.newPage( { viewport: { width: 1280, height: 900 } } );
	const qrRequests = [];
	page.on( 'request', ( request ) => {
		if ( request.url().includes( 'qrcode' ) || request.url().includes( 'mfa-qr' ) ) {
			qrRequests.push( request.url() );
		}
	} );

	try {
		await page.goto( `${ baseUrl }${ loginPath }`, { waitUntil: 'networkidle' } );
		await page.locator( usernameSelector ).fill( username );
		await page.locator( passwordSelector ).fill( password );
		await Promise.all( [
			page.waitForLoadState( 'networkidle' ),
			page.locator( submitSelector ).click(),
		] );
		await page.goto( `${ baseUrl }${ profilePath }#identity-security-mfa`, { waitUntil: 'networkidle' } );
		const canvas = page.locator( '.identity-totp-qr__canvas canvas' );
		await canvas.waitFor( { state: 'visible', timeout: 10000 } );

		const pixels = await canvas.evaluate( ( element ) => {
			const context = element.getContext( '2d' );
			const data = context.getImageData( 0, 0, element.width, element.height ).data;
			let dark = 0;
			let light = 0;
			for ( let index = 0; index < data.length; index += 4 ) {
				const luminance = data[ index ] + data[ index + 1 ] + data[ index + 2 ];
				if ( luminance < 180 ) dark++;
				if ( luminance > 720 ) light++;
			}
			return { dark, light, width: element.width, height: element.height };
		} );
		assert.deepEqual( [ pixels.width, pixels.height ], [ 220, 220 ] );
		assert.ok( pixels.dark > 1000 && pixels.light > 1000, 'The QR canvas is blank or monochrome.' );
		assert.ok( qrRequests.length >= 2, 'The local QR assets were not requested.' );
		qrRequests.forEach( ( url ) => assert.equal( new URL( url ).origin, new URL( baseUrl ).origin ) );

		console.log( JSON.stringify( { canvas: 'nonblank', dimensions: '220x220', qrAssets: 'same-origin' } ) );
	} finally {
		await browser.close();
	}
} )().catch( ( error ) => {
	console.error( error );
	process.exitCode = 1;
} );
