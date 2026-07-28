(function() {
	'use strict';

	const config = window.IdentitySecurityUserActions || {};
	const labels = config.labels || {};
	let current = null;
	let selectedAction = null;

	const dialog = document.createElement('dialog');
	dialog.className = 'isk-user-security-dialog';
	dialog.innerHTML = '<div class="isk-user-security-dialog__header"><div><span>' + labels.eyebrow + '</span><h2></h2><p></p></div><button type="button" data-isk-close aria-label="' + labels.close + '">&times;</button></div>' +
		'<div class="isk-user-security-dialog__notice" data-isk-notice hidden></div>' +
		'<div class="isk-user-security-dialog__actions" data-isk-actions>' +
		'<button type="button" data-isk-action="resend_verification"><strong>' + labels.verify + '</strong><small>' + labels.verifyDescription + '</small></button>' +
		'<button type="button" data-isk-action="restart_grace"><strong>' + labels.grace + '</strong><small>' + labels.graceDescription + '</small></button>' +
		'<button type="button" class="is-danger" data-isk-action="reset_mfa"><strong>' + labels.reset + '</strong><small>' + labels.resetDescription + '</small></button>' +
		'</div>' +
		'<div class="isk-user-security-dialog__confirmation" data-isk-confirmation hidden>' +
		'<h3>' + labels.confirmTitle + '</h3><strong data-isk-confirmation-action></strong><p>' + labels.confirmText + '</p>' +
		'<div><button type="button" class="button" data-isk-cancel>' + labels.cancel + '</button><button type="button" class="button button-primary" data-isk-confirm>' + labels.confirm + '</button></div>' +
		'</div>';
	document.body.appendChild(dialog);

	const notice = dialog.querySelector('[data-isk-notice]');
	const actions = dialog.querySelector('[data-isk-actions]');
	const confirmation = dialog.querySelector('[data-isk-confirmation]');
	const confirmationAction = dialog.querySelector('[data-isk-confirmation-action]');

	function resetConfirmation() {
		selectedAction = null;
		actions.hidden = false;
		confirmation.hidden = true;
	}

	function setBusy(busy) {
		dialog.toggleAttribute('aria-busy', busy);
		dialog.querySelectorAll('button').forEach(function(button) {
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

	document.addEventListener('click', function(event) {
		const launcher = event.target.closest('[data-identity-user-security]');
		if (launcher) {
			current = {
				userId: launcher.dataset.userId,
				userName: launcher.dataset.userName,
				nonce: launcher.dataset.nonce
			};
			dialog.querySelector('h2').textContent = labels.title;
			dialog.querySelector('.isk-user-security-dialog__header p').textContent = current.userName;
			notice.hidden = true;
			resetConfirmation();
			dialog.showModal();
			return;
		}
		if (event.target.closest('[data-isk-close]')) {
			dialog.close();
			return;
		}
		if (event.target.closest('[data-isk-cancel]')) {
			resetConfirmation();
			return;
		}
		const actionButton = event.target.closest('[data-isk-action]');
		if (actionButton && current) {
			selectedAction = actionButton.dataset.iskAction;
			confirmationAction.textContent = actionButton.querySelector('strong').textContent;
			actions.hidden = true;
			confirmation.hidden = false;
			confirmation.querySelector('[data-isk-confirm]').focus();
			return;
		}
		if (!event.target.closest('[data-isk-confirm]') || !current || !selectedAction) {
			return;
		}

		setBusy(true);
		const body = new URLSearchParams({
			action: 'identity_security_user_action',
			security_action: selectedAction,
			user_id: current.userId,
			nonce: current.nonce
		});
		fetch(config.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		}).then(function(response) {
			return response.json().then(function(result) {
				if (!response.ok || !result.success) {
					throw result;
				}
				return result;
			});
		}).then(function(result) {
			showNotice(result.data.message, true);
		}).catch(function(error) {
			showNotice(error.data && error.data.message ? error.data.message : labels.error, false);
		}).finally(function() {
			setBusy(false);
			resetConfirmation();
		});
	});
})();
