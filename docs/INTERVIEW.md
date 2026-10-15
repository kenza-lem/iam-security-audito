# Présentation au recruteur

## Descriptif

AWS IAM Security Auditor : outil Python/Boto3 qui automatise la collecte des credentials, utilisateurs, groupes, policies et rôles EC2 d'un compte lab. Authentification temporaire avec aws login puis STS AssumeRole. Résultats structurés console/JSON, contrôles séparant statut et sévérité, pagination et erreurs explicites. Le rôle d'audit ne peut pas corriger l'environnement. Un module MFA assisté séparé existe en pilote local.

## Formulation CV fidèle aux preuves disponibles

Développé un auditeur AWS IAM en Python/Boto3 avec authentification temporaire via STS, contrôles MFA, inventaire des permissions directes et héritées et vérification des rôles EC2 ; détecté puis corrigé une attribution AdministratorAccess à un développeur, tracé les changements avec CloudTrail et validé des policies avec IAM Access Analyzer.

## Questions d'entretien

**Pourquoi un rôle distinct ?** Pour séparer les permissions d'observation des permissions de modification et vérifier explicitement le compte et l'identité avant la collecte.

**Quel problème réel avez-vous trouvé ?** Une policy AWS AdministratorAccess directement attachée à developer02. Collecte, preuve CloudTrail, retrait manuel et re-test PASS sont documentés.

**Pourquoi les wildcards ne sont-elles pas toutes des failles ?** Leur portée dépend de l'action, des ressources, des conditions et du besoin métier. Certains appels ne permettent pas une restriction à un ARN. Les WARN du scanner servent de points de revue.

**Que prouve findings=[] ?** Aucune anomalie signalée par la validation Access Analyzer de la copie soumise. Cela ne prouve ni l'adéquation au poste ni le moindre privilège.

**Que prouve EC2 PASS ?** La résolution d'un instance profile vers un rôle, pas l'utilisation réelle de ce rôle ni la pertinence de ses permissions.

**Quelles limites ?** Credential report potentiellement ancien, activité partielle, pas de simulation globale des permissions effectives, SCPs/boundaries/resource policies hors analyse, régions EC2 explicites, cinq findings MFA encore ouverts. CloudTrail et Access Analyzer ont été utilisés séparément via CLI.

**Comment avez-vous testé ?** 30 tests locaux avec cas d'erreur, mocks et botocore Stubber pour la pagination ; audits IAM/EC2 réels sur le lab. La collecte des clés a aussi été exécutée sur les six utilisateurs du lab, tous sans clé. Les cas avec clés restent couverts localement et la remédiation MFA n'est pas validée sur AWS.
