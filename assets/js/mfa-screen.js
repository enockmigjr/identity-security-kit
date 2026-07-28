(function() {
	'use strict';

	const root = document.querySelector('[data-isk-mfa]');
	if (!root) {
		return;
	}

	const prepareButton = root.querySelector('[data-isk-prepare]');
	const codeForm = root.querySelector('[data-isk-code-form]');
	const codeInput = codeForm.querySelector('input[name="code"]');
	const notice = root.querySelector('[data-isk-mfa-notice]');
	const label = root.querySelector('[data-isk-current-label]');
	const destination = root.querySelector('[data-isk-current-destination]');
	let method = root.dataset.method;

	function setBusy(busy) {
		root.toggleAttribute('aria-busy', busy);
		root.querySelectorAll('button').forEach(function(button) {
			button.disabled = busy;
		});
	}

	function showNotice(message, success) {
		notice.hidden = false;
		notice.textContent = message;
		notice.classList.toggle('is-success', success);
		notice.classList.toggle('is-error', !success);
		notice.setAttribute('role', success ? 'status' : 'alert');
	}

	async function request(url, payload) {
		setBusy(true);
		try {
			const response = await fetch(url, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-Identity-Nonce': root.dataset.nonce
				},
				body: JSON.stringify(Object.assign({ token: root.dataset.token }, payload))
			});
			const result = await response.json().catch(function() {
				return {};
			});
			if (!response.ok || !result.success) {
				throw result;
			}
			return result;
		} finally {
			setBusy(false);
		}
	}

	async function prepare() {
		try {
			const result = await request(root.dataset.prepareUrl, { method: method });
			showNotice(result.message, true);
			prepareButton.hidden = true;
			codeForm.hidden = false;
			codeInput.focus();
		} catch (error) {
			showNotice(error.message || 'La methode n a pas pu etre preparee.', false);
		}
	}

	prepareButton.addEventListener('click', prepare);

	root.querySelectorAll('[data-isk-method]').forEach(function(button) {
		button.addEventListener('click', function() {
			method = button.dataset.iskMethod;
			label.textContent = button.dataset.label;
			destination.textContent = button.dataset.destination;
			prepareButton.hidden = false;
			codeForm.hidden = true;
			codeInput.value = '';
			notice.hidden = true;
			const details = button.closest('details');
			if (details) {
				details.open = false;
			}
		});
	});

	codeForm.addEventListener('submit', async function(event) {
		event.preventDefault();
		try {
			const result = await request(root.dataset.verifyUrl, { method: method, code: codeInput.value });
			showNotice(result.message, true);
			window.location.assign(result.data.redirect_url);
		} catch (error) {
			showNotice(error.message || 'Le code est invalide ou expire.', false);
			codeInput.select();
		}
	});
})();
