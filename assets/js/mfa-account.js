(function() {
	'use strict';

	function config() {
		return window.IdentitySecurityMfaAccount || {};
	}

	function feedback(form, message, success) {
		let notice = form.querySelector('[data-isk-form-feedback]');
		if (!notice) {
			notice = document.createElement('p');
			notice.dataset.iskFormFeedback = '';
			form.prepend(notice);
		}
		notice.textContent = message;
		notice.className = success ? 'identity-security-inline-feedback is-success' : 'identity-security-inline-feedback is-error';
		notice.setAttribute('role', success ? 'status' : 'alert');
	}

	function setBusy(panel, busy) {
		panel.toggleAttribute('aria-busy', busy);
		panel.querySelectorAll('button').forEach(function(button) {
			button.disabled = busy;
			button.toggleAttribute('aria-busy', busy);
		});
	}

	async function submit(form) {
		const panel = form.closest('#identity-security-mfa');
		if (!panel || panel.getAttribute('aria-busy') === 'true') return;
		setBusy(panel, true);
		const payload = {};
		new FormData(form).forEach(function(value, key) {
			payload[key] = value;
		});
		try {
			const settings = config();
			const response = await fetch(settings.endpoint, {
				method: 'POST',
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-WP-Nonce': settings.nonce || ''
				},
				body: JSON.stringify(payload)
			});
			const result = await response.json().catch(function() {
				return {};
			});
			if (!response.ok || !result.success) {
				throw result;
			}
			const replacement = document.createElement('div');
			replacement.innerHTML = result.data.html;
			const nextPanel = replacement.firstElementChild;
			if (!nextPanel) throw {};
			panel.replaceWith(nextPanel);
			if (typeof window.IdentitySecurityRenderAuthenticatorCodes === 'function') {
				window.IdentitySecurityRenderAuthenticatorCodes();
			}
			nextPanel.scrollIntoView({ behavior: document.body.classList.contains('pv-reduce-motion') ? 'auto' : 'smooth', block: 'nearest' });
			const focusTarget = nextPanel.querySelector('input[name="otp_code"], input[name="mfa_code"], input:not([type="hidden"]), button');
			if (focusTarget) focusTarget.focus({ preventScroll: true });
		} catch (error) {
			feedback(form, error.message || config().error, false);
			setBusy(panel, false);
		}
	}

	document.addEventListener('submit', function(event) {
		const form = event.target.closest('#identity-security-mfa form');
		if (!form || !config().endpoint) return;
		event.preventDefault();
		submit(form);
	});

	document.addEventListener('click', async function(event) {
		const button = event.target.closest('[data-isk-copy-recovery]');
		if (!button) return;
		const container = button.closest('[data-isk-recovery-codes]');
		const codes = Array.from(container.querySelectorAll('code')).map(function(code) {
			return code.textContent.trim();
		}).join('\n');
		try {
			await navigator.clipboard.writeText(codes);
			button.textContent = config().copied;
		} catch (error) {
			const selection = window.getSelection();
			const range = document.createRange();
			range.selectNodeContents(container.querySelector('ul'));
			selection.removeAllRanges();
			selection.addRange(range);
		}
	});
})();
