# Identity Security Kit

Identity Security Kit est un plugin WordPress reutilisable pour les flux d'identite: login, inscription, profil, reset password, verification email, politiques de base et audit securite.

## Responsabilites

- Gerer les formulaires frontend login/register/profile/forgot password.
- Valider les champs critiques cote serveur.
- Eviter l'enumeration sur les demandes de reset password.
- Creer et verifier les challenges de verification email.
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

## Options et user meta

- `identity_security_kit_settings`
- `identity_security_kit_version`
- `identity_email_verified`
- `identity_email_verification_pending`
- `photovault_avatar_id`

## Actions admin-post

- `admin_post_nopriv_identity_security_kit_verify_email`
- `admin_post_identity_security_kit_verify_email`
- `admin_post_identity_security_kit_resend_email_verification`
- `admin_post_identity_security_kit_save_settings`

## Filtres publics

- `identity_security_kit_routes`
- `identity_security_kit_allowed_image_mimes`
- `identity_security_kit_max_avatar_size`
- `identity_security_kit_max_avatar_dimension`
- `identity_security_kit_registration_role`
- `identity_security_kit_avatar_meta_key`
- `identity_security_kit_email_verified_meta_key`
- `identity_security_kit_email_pending_meta_key`

## Verification minimale

1. Activer le plugin et verifier les tables DB.
2. Tester inscription, verification email, connexion, profil et reset password.
3. Confirmer que le renvoi de verification exige session + nonce.
4. Confirmer que les reglages restent bornes avec des valeurs POST extremes.
5. Verifier que l'audit ne stocke pas mot de passe, reset key, token brut ou IP brute.

## Reste majeur

- OTP email avec expiration, tentatives, anti-replay et rate limiting.
- OTP SMS/provider abstraction.
- TOTP/MFA.
- Recovery codes.
- Grace period MFA et enforcement wp-admin privilegie.
- Invalidation de sessions apres evenement sensible.
