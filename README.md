# Identity Security Kit

Identity Security Kit est un plugin WordPress reutilisable pour les flux d'identite: login, inscription, profil, reset password, verification email, politiques de base et audit securite.

## Responsabilites

- Gerer les formulaires frontend login/register/profile/forgot password.
- Isoler les modifications de profil (identite, avatar, telephone, email et mot de passe) afin qu'une action ne valide jamais les champs d'une autre.
- Valider les champs critiques cote serveur.
- Eviter l'enumeration sur les demandes de reset password.
- Creer et verifier les challenges de verification email.
- Appliquer les changements d'email uniquement apres mot de passe, confirmation de la nouvelle adresse et notification de l'ancienne.
- Creer et verifier des OTP email a usage unique avec expiration, verrouillage et anti-rejeu.
- Normaliser et rendre uniques les numeros internationaux E.164, puis verifier leur possession par OTP SMS.
- Fournir une abstraction SMS generique avec adaptateur Twilio optionnel et filtre pour providers externes.
- Enroler et verifier les facteurs TOTP, email et SMS, avec choix de methode au login.
- Afficher un QR code d'enrolement Authenticator genere localement, tout en conservant la cle manuelle et le lien `otpauth://` comme solutions de repli.
- Desactiver les facteurs TOTP, email et SMS apres re-authentification, sans permettre a un compte soumis au MFA de retirer son dernier facteur.
- Generer des recovery codes affiches une seule fois, stockes hashes et consommables une seule fois.
- Imposer une grace MFA configurable de 15 jours aux comptes portant des capabilities sensibles.
- Envoyer des rappels MFA J+1, J+7 et J+12 par cron borne et idempotent, puis reconciler les changements de roles et de politique.
- Rendre les emails de verification, reset, OTP, changement d'adresse, MFA et rappels en HTML responsive avec alternative texte multipart.
- Exposer le meme layout transactionnel aux integrations metier avec un `Reply-To` optionnel valide.
- Adapter aussi les notifications natives WordPress `Email Changed` et `Password Changed` sans les desactiver.
- Permettre le renvoi de verification email avec session + nonce.
- Journaliser les evenements d'identite sans stocker de secrets, reset keys ou IP brute.
- Exposer des reglages bornes cote serveur.

## Capabilities

- `identity_manage_settings`
- `identity_manage_security`
- `identity_view_security_audit`

Les capabilities sont ajoutees aux administrateurs a l'activation/upgrade.

## Tables

- `{$wpdb->prefix}identity_security_audit`
- `{$wpdb->prefix}identity_security_email_challenges`
- `{$wpdb->prefix}identity_security_email_otp`
- `{$wpdb->prefix}identity_security_otp_challenges`

## Options et user meta

- `identity_security_kit_settings`
  - `min_password_length`, `max_avatar_size_mb`, `max_avatar_dimension`
  - `email_verification_ttl_hours`, `email_verification_resend_minutes`
  - `login_attempts_per_window`, `registration_attempts_per_window`, `password_reset_attempts_per_window`, `email_resend_attempts_per_window`, `rate_limit_window_minutes`
  - `email_otp_ttl_minutes`, `email_otp_length`, `email_otp_max_attempts`, `email_otp_resend_minutes`
  - `sms_otp_ttl_minutes`, `sms_otp_length`, `sms_otp_max_attempts`, `sms_otp_resend_minutes`, `sms_provider`
  - `phone_required`, `mfa_enforcement_enabled`, `mfa_grace_days`, `mfa_attempts_per_window`
  - `mfa_required_capabilities`, `mfa_allowed_methods`
- `identity_security_kit_version`
- `identity_email_verified`
- `identity_email_verification_pending`
- `identity_phone_e164`, `identity_phone_verified`, `identity_phone_verified_hash`
- `identity_mfa_totp_secret`, `identity_mfa_totp_last_counter`, `identity_mfa_recovery_codes`
- `identity_mfa_email_enabled`, `identity_mfa_sms_enabled`, `identity_mfa_preferred_method`
- `identity_mfa_grace_started_at`, `identity_mfa_login_challenge`
- `identity_mfa_grace_reminders`
- `identity_pending_email_change` (adresse proposee chiffree, token hashe et expiration)
- `photovault_avatar_id`

## Actions admin-post

- `admin_post_nopriv_identity_security_kit_verify_email`
- `admin_post_identity_security_kit_verify_email`
- `admin_post_identity_security_kit_resend_email_verification`
- `admin_post_identity_security_kit_save_settings`
- `admin_post_identity_security_kit_email_otp_request`
- `admin_post_identity_security_kit_email_otp_verify`
- `admin_post_identity_security_kit_phone_otp_request`
- `admin_post_identity_security_kit_phone_otp_verify`
- `admin_post_identity_security_kit_totp_start`
- `admin_post_identity_security_kit_totp_confirm`
- `admin_post_identity_security_kit_totp_cancel`
- `admin_post_identity_security_kit_totp_disable`
- `admin_post_identity_security_kit_recovery_regenerate`
- `admin_post_identity_security_kit_channel_mfa_start`
- `admin_post_identity_security_kit_channel_mfa_confirm`
- `admin_post_identity_security_kit_channel_mfa_disable_start`
- `admin_post_identity_security_kit_channel_mfa_disable_confirm`
- `admin_post_identity_security_kit_mfa_preference`
- `admin_post_nopriv_identity_security_kit_confirm_email_change`
- `admin_post_identity_security_kit_confirm_email_change`
- `admin_post_identity_security_kit_cancel_email_change`

## Filtres publics

- `identity_security_kit_routes`
- `identity_security_kit_allowed_image_mimes`
- `identity_security_kit_max_avatar_size`
- `identity_security_kit_max_avatar_dimension`
- `identity_security_kit_registration_role`
- `identity_security_kit_avatar_meta_key`
- `identity_security_kit_email_verified_meta_key`
- `identity_security_kit_email_pending_meta_key`
- `identity_security_kit_normalized_phone`
- `identity_security_kit_phone_meta_key`
- `identity_security_kit_sms_provider`
- `identity_security_kit_sms_provider_available`
- `identity_security_kit_sms_delivery`
- `identity_security_kit_email_brand`
- `identity_security_kit_allowed_mfa_methods`
- `identity_security_kit_user_requires_mfa`
- `identity_security_kit_user_has_mfa`
- `identity_security_kit_mfa_reminder_days`
- `identity_security_kit_mfa_policy_batch_size`

## Cron

- `identity_security_kit_mfa_policy_cron`: traitement horaire borne a 200 comptes par defaut, avec curseur persistant et nettoyage a la desactivation.

## OTP email

Le shortcode identity_security_email_otp rend un flux authentifie de demande et verification. Son attribut purpose isole les usages.

Les fonctions identity_security_kit_create_email_otp_challenge() et identity_security_kit_verify_email_otp_challenge() permettent une integration applicative. Les actions identity_security_kit_email_otp_created et identity_security_kit_email_otp_verified notifient les integrations sans exposer le code brut.

Conception securite: random_int, wp_hash_password, wp_check_password, expiration courte, essais bornes, cooldown, nonce lie au purpose, consommation atomique et effacement du hash.

References: WordPress Nonces API https://developer.wordpress.org/apis/security/nonces/ ; wp_check_password https://developer.wordpress.org/reference/functions/wp_check_password/ ; NIST SP 800-63B https://pages.nist.gov/800-63-4/sp800-63b.html.

## Verification minimale

1. Activer le plugin et verifier les tables DB.
2. Tester inscription, verification email, connexion, profil et reset password.
3. Confirmer que le renvoi de verification exige session + nonce.
4. Confirmer que les reglages restent bornes avec des valeurs POST extremes.
5. Verifier que l'audit ne stocke pas mot de passe, reset key, token brut ou IP brute.
6. Executer `php tests/run.php`, `php tests/otp.php` et `php tests/sms-provider.php`.
7. Executer `wp eval-file tests/runtime-identity.php` dans WordPress pour verifier email, telephone, OTP, TOTP, recovery, login MFA, cycle de vie des facteurs, rappels et grace 15 jours.
8. Confirmer dans Mailpit la remise SMTP des emails de verification, OTP et notifications de securite.
9. Avec un provider SMS de staging, verifier livraison, refus, timeout et idempotence sans journaliser le code ou le numero complet.
10. Executer `wp eval-file tests/runtime-email-change.php` pour verifier re-authentification, stockage chiffre, expiration, anti-rejeu et revocation des anciennes preuves.
11. Executer `wp eval-file tests/runtime-email-templates.php` pour verifier layout responsive, sanitization, OTP, CTA, `AltBody` PHPMailer et remise SMTP.
12. Executer `wp eval-file tests/runtime-totp-qr.php` pour verifier URI locale, assets epingles, checksum fournisseur et repli manuel.
13. Executer `node tests/browser-totp-qr.js` avec les variables `IDENTITY_TEST_*` adaptees aux routes et selecteurs du projet pour verifier le canvas, ses pixels et les requetes same-origin.

## Reste majeur

- Validation des plans de numerotation par une librairie reconnue et UX pays/indicatif.
- Remplacement guide des facteurs et validation des changements concurrents en navigateur.
- Provider SMS reel valide en staging/production; les tests actuels utilisent l'adaptateur generique controle.
- Cas multisite et changement direct des capabilities d'un role hors API utilisateur.
- Tests navigateur du login natif et matrice d'autorisation wp-admin/AJAX.

## References officielles

- [WordPress Nonces](https://developer.wordpress.org/apis/security/nonces/)
- [WordPress Password Hashing API](https://developer.wordpress.org/reference/functions/wp_check_password/)
- [WordPress send_confirmation_on_profile_email](https://developer.wordpress.org/reference/functions/send_confirmation_on_profile_email/)
- [WordPress wp_enqueue_script](https://developer.wordpress.org/reference/functions/wp_enqueue_script/)
- [WordPress Scheduling WP-Cron Events](https://developer.wordpress.org/plugins/cron/scheduling-wp-cron-events/)
- [WordPress add_user_role hook](https://developer.wordpress.org/reference/hooks/add_user_role/)
- [RFC 6238 - TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [NIST SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [QRCode.js](https://github.com/davidshimjs/qrcodejs) - bibliotheque MIT embarquee au commit `04f46c6`; aucun secret TOTP n'est transmis a un service distant.
