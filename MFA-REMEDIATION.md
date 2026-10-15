# Remédiation MFA assistée — pilote auditor01

Le module remediate_mfa.py est séparé de l'auditeur read-only. Il modifie AWS uniquement après sélection explicite de auditor01 et confirmation dans le terminal. Tests locaux uniquement ; aucun MFA n'a été créé par l'assistant.

## Configuration AWS manuelle

Créer IAMMfaEnrollmentRole avec la même trust policy autorisant lab-admin à sts:AssumeRole que le rôle d'audit. Ajouter la policy inline mfa-enrollment-policy.json ; elle ne concerne que auditor01 à la racine IAM et l'appareil auditor01-assisted-mfa. Elle ne permet pas de désactiver ou supprimer un appareil. Le lab-admin doit également être autorisé à assumer ce rôle.

```powershell
aws configure set role_arn arn:aws:iam::391894613419:role/IAMMfaEnrollmentRole --profile iam-mfa
aws configure set source_profile lab-login --profile iam-mfa
aws configure set region eu-north-1 --profile iam-mfa
aws sts get-caller-identity --profile iam-mfa
.\.venv\Scripts\python.exe remediate_mfa.py --profile iam-mfa --expected-account 391894613419 --user auditor01
```

Confirmer auditor01 dans le terminal. Scanner le QR dans Authenticator, cliquer Continue, saisir deux codes successifs avec saisie masquée. Ne pas partager les secrets ou prendre de capture du QR. Le QR n'est pas enregistré sur disque. Une application Authenticator gérée par la propriétaire du lab est acceptable pour cette identité de test ; chaque utilisateur réel doit enregistrer son propre facteur.

## Vérification

Le module vérifie le rattachement avec ListMFADevices, sans attendre le cache du credential report. Tester ensuite une nouvelle connexion console de auditor01. L'enregistrement MFA ne prouve pas l'exigence MFA pour chaque appel API.

## Erreurs et interruption

Si une interruption survient après la création de l'appareil, son ARN est affiché. Vérifier dans IAM s'il est attaché avant de relancer. Aucun effacement automatique n'est effectué : une réponse réseau perdue ne prouve pas que l'activation a échoué. Si l'appareil est non assigné, le supprimer manuellement avant une nouvelle tentative avec le même nom. S'il est assigné, tester la connexion et conserver l'entrée Authenticator.

## APIs

GetCallerIdentity, GetUser, ListMFADevices (pagination), CreateVirtualMFADevice, EnableMFADevice. Référence : https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_cliapi.html
