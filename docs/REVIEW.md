# Revue des accès — preuves et état réel

## Périmètre et méthode

Lab d'un compte AWS, six IAM Users et une instance EC2 en eu-north-1. Démarche : collecte, analyse, contextualisation, correction manuelle, re-test. Les rapports bruts sont exclus de Git. Les captures sont facultatives et doivent être anonymisées ; aucun QR MFA ou code ne doit être conservé.

## Finding PRIV-01 : développeur avec policy administrateur

État : corrigé pour le contrôle couvert. Sévérité initiale HIGH. developer02 hérite de DeveloperPolicy via Developers mais avait également AWS AdministratorAccess attachée directement. IAM-006 a produit FAIL. Cela constitue un écart par rapport au RBAC attendu du lab, sans prétendre simuler les permissions effectives.

CloudTrail a montré AttachUserPolicy le 8 octobre 2026 à 21:09:37 UTC, par lab-admin, session MFA authentifiée, sans code d'erreur. La policy a été retirée manuellement. DetachUserPolicy du 15 octobre 2026 à 14:30:47 UTC, également par lab-admin, confirme l'opération. Le nouvel inventaire ne retrouve plus la policy directe et IAM-006 passe ; Developers et IAMUserChangePassword sont conservés.

## Findings MFA-01 à MFA-05

État : ouverts selon le dernier audit reçu. auditor01, auditor02, developer01, developer02, security01 : password_enabled=true et mfa_active=false. MEDIUM par défaut, à reclasser selon le besoin métier et les permissions. Root et lab-admin ont MFA. La remédiation assistée est un pilote séparé testé localement ; aucune activation réelle n'est confirmée.

## Workload EC2

IAM-009 PASS : iam-security-lab-ec2 possède un instance profile résolu vers EC2-S3-Role en eu-north-1. L'application, IMDS, les autorisations S3 et la policy du rôle ne sont pas testés. Aucune autre région n'est couverte.

## Validation Access Analyzer

Copies DeveloperPolicy v3 et AuditorPolicy v1 extraites du rapport, validées avec ValidatePolicy en IDENTITY_POLICY : findings=[] pour chacune. Cela couvre grammaire et contrôles de bonnes pratiques AWS, pas adéquation métier, analyse des accès externes/inutilisés ou calcul des permissions effectives. Aucune création d'analyseur, organisation ou clé KMS n'a été nécessaire.

## Reproduction via AWS CLI

Le rôle peut recevoir séparément cloudtrail:LookupEvents et access-analyzer:ValidatePolicy sur Resource "*" pour ces revues. Ces actions ne sont pas utilisées par auditor.py.

```powershell
aws cloudtrail lookup-events --profile iam-audit --region us-east-1 --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy --output json --no-cli-pager
aws cloudtrail lookup-events --profile iam-audit --region us-east-1 --lookup-attributes AttributeKey=EventName,AttributeValue=DetachUserPolicy --output json --no-cli-pager
aws accessanalyzer validate-policy --profile iam-audit --region eu-north-1 --policy-document file://reports/DeveloperPolicy.json --policy-type IDENTITY_POLICY --locale FR --output json --no-cli-pager
```

Dans chaque CloudTrailEvent, vérifier requestParameters.userName et policyArn, auteur, eventTime, eventID et absence de errorCode. responseElements=null ne prouve pas un échec. L'historique est limité aux événements de management des 90 derniers jours et à la région interrogée. Conserver les preuves originales localement et publier uniquement une synthèse anonymisée.

## Critères de livraison V1

- Tests locaux passants ; CI GitHub à confirmer après publication.
- Dernier audit avec inventaire détaillé des clés à exécuter ; complete=True ne signifie pas sans FAIL.
- Les cinq findings MFA restent documentés ouverts tant que la correction et le re-test ne sont pas prouvés.
- Authentification SSO abandonnée au profit de aws login + AssumeRole ; CSV/HTML et remédiation généralisée hors V1.
- Membership : inventaire et absence de groupe couverts, conformité de chaque nom de groupe au RBAC non automatisée.

## Références

- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-cli.html
- https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
