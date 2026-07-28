(function() {
	'use strict';

	function surface() {
		return document.querySelector('.identity-security-kit-admin, .identity-security-audit-admin');
	}

	function setBusy(form, busy) {
		form.toggleAttribute('aria-busy', busy);
		form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(function(button) {
			button.disabled = busy;
		});
	}

	function toast(message, success) {
		document.querySelectorAll('[data-isk-admin-toast]').forEach(function(item) {
			item.remove();
		});
		const notice = document.createElement('div');
		notice.className = 'isk-admin-runtime-toast ' + (success ? 'is-success' : 'is-error');
		notice.dataset.iskAdminToast = '';
		notice.setAttribute('role', success ? 'status' : 'alert');
		const text = document.createElement('span');
		text.textContent = message;
		notice.appendChild(text);
		const close = document.createElement('button');
		close.type = 'button';
		close.setAttribute('aria-label', 'Close notification');
		close.textContent = '\u00d7';
		close.addEventListener('click', function() {
			notice.remove();
		});
		notice.appendChild(close);
		document.body.appendChild(notice);
		window.setTimeout(function() {
			notice.remove();
		}, 7000);
	}

	async function refresh(url, options, historyMode) {
		const current = surface();
		const selector = current && current.classList.contains('identity-security-audit-admin')
			? '.identity-security-audit-admin'
			: '.identity-security-kit-admin';
		const response = await fetch(url, Object.assign({ credentials: 'same-origin' }, options || {}));
		const html = await response.text();
		const parsed = new DOMParser().parseFromString(html, 'text/html');
		const next = parsed.querySelector(selector);
		if (!response.ok || !current || !next) {
			throw new Error('The administration screen could not be refreshed.');
		}
		current.replaceWith(next);
		if (parsed.title) document.title = parsed.title;
		if (historyMode === 'push') window.history.pushState({ isk: true }, '', response.url);
		if (historyMode === 'replace') window.history.replaceState({ isk: true }, '', response.url);
		const message = next.querySelector('.notice p, .updated p, .error p');
		return message ? message.textContent.trim() : 'Changes saved.';
	}

	document.addEventListener('submit', async function(event) {
		const form = event.target;
		if (!(form instanceof HTMLFormElement) || !form.closest('.identity-security-kit-admin, .identity-security-audit-admin')) return;
		event.preventDefault();
		if (form.getAttribute('aria-busy') === 'true') return;
		setBusy(form, true);
		const method = (form.method || 'GET').toUpperCase();
		try {
			let url = form.action || window.location.href;
			let options = {};
			let historyMode = 'replace';
			if (method === 'GET') {
				url = url.split('?')[0] + '?' + new URLSearchParams(new FormData(form)).toString();
				historyMode = 'push';
			} else {
				options = { method: method, body: new FormData(form) };
			}
			const message = await refresh(url, options, historyMode);
			toast(message, true);
		} catch (error) {
			setBusy(form, false);
			toast(error.message || 'The operation could not be completed.', false);
		}
	});

	document.addEventListener('click', async function(event) {
		const link = event.target.closest('.identity-security-audit-admin .isk-admin-pagination a');
		if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
		event.preventDefault();
		try {
			await refresh(link.href, {}, 'push');
		} catch (error) {
			toast(error.message || 'The page could not be loaded.', false);
		}
	});

	window.addEventListener('popstate', async function() {
		if (!surface()) return;
		try {
			await refresh(window.location.href, {}, '');
		} catch (error) {
			window.location.reload();
		}
	});
})();
