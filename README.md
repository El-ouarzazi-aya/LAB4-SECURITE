# 🔍 Rapport d'Analyse Statique — APK Android 
### UnCrackable-Level1.apk | OWASP MAS Crackme | 25 avril 2026 | réalisée par El Ouarzazi Aya

---

## 📋 Informations générales

| Champ | Valeur |
|-------|--------|
| **APK analysé** | `UnCrackable-Level1.apk` |
| **Date d'analyse** | 25 avril 2026 |
| **Provenance** | [OWASP MAS Crackmes](https://mas.owasp.org/crackmes) |
| **Package** | `owasp.mstg.uncrackable1` / `sg.vantagepoint.uncrackable1` |
| **Version** | 1.0 (versionCode 1) |
| **minSdk / targetSdk** | 19 (Android 4.4) / 28 (Android 9) |
| **SHA-256** | `1DA8BF57D266109F9A07C01BF7111A1975CE01F190B9D914BCD3AE3DBEF96F21` |
| **Taille** | 66 Ko |
| **Outils utilisés** | JADX GUI v1.5.5 · dex2jar v2.4 · JD-GUI v1.6.6 |

---

## 🗂️ Structure de l'APK

Vérification des magic bytes (`50 4B` = signature ZIP valide) et contenu de l'archive :

> Les 4 premiers octets `50 4B 03 04` confirment que l'APK est une archive ZIP valide.

> Hash SHA-256 calculé pour la traçabilité de l'analyse.

> Contenu listé : `AndroidManifest.xml`, `classes.dex`, ressources, signature `META-INF/`.  
> Un seul fichier DEX → application simple, pas de multi-dex.

---

## 🗺️ Analyse du AndroidManifest.xml


### Informations extraites

```xml
package          = owasp.mstg.uncrackable1
versionName      = 1.0
minSdkVersion    = 19
targetSdkVersion = 28
android:allowBackup = "true"   ← ⚠️ VULNÉRABILITÉ
```

### Permissions déclarées

> ✅ Aucune permission `uses-permission` déclarée — surface d'attaque réseau/stockage minimale.

### Composants exportés

| Composant | Nom complet | Exported | Risque |
|-----------|-------------|----------|--------|
| `Activity` | `sg.vantagepoint.uncrackable1.MainActivity` | `true` (intent-filter MAIN/LAUNCHER) | Faible — point d'entrée normal |

> ℹ️ Aucun Service, Receiver ni ContentProvider exposé. Surface d'attaque via composants minimale.

---

## 🔎 Analyse du code source (JADX GUI)

### Classe `a` — Mécanisme de vérification du secret


```java
// Clé AES hardcodée en hexadécimal
bArrA = sg.vantagepoint.a.a.a(
    b("8d127684cbc37c17616d806cf50473cc"),              // ← clé AES en dur
    Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0)  // ← texte chiffré
);
return str.equals(new String(bArrA));  // compare avec la saisie utilisateur
```

> 🔓 **Secret déchiffré : `"I want to believe"`**  
> La clé et le texte chiffré étant tous deux dans l'APK, n'importe qui peut déchiffrer le secret.

---

## 🔍 Recherche de chaînes sensibles (Task 4)

| Pattern recherché | Résultats | Analyse |
|-------------------|-----------|---------|
| `http` | 3 | Namespace XML Android standard — aucun risque |
| `Log.d` | 1 | Log d'erreur AES en debug — risque moyen |
| `password` | 0 | Aucun mot de passe en clair — OK |
| `secret` | 5 | SecretKeySpec + clé hardcodée — risque élevé |
| `AES` | 3 | Mode ECB détecté — risque élevé |

> `Log.d("CodeCheck", "AES error:" + e.getMessage())` — messages d'erreur cryptographiques loggés en debug.

> `SecretKeySpec` utilisé avec une clé hardcodée dans le code source.

> `Cipher.getInstance("AES")` → utilise AES/ECB par défaut — mode cryptographique faible.

---

## 🔄 Conversion DEX → JAR (dex2jar)


```
classes.dex (bytecode Android) → app.jar (bytecode Java standard)
Taille du JAR généré : 5 968 octets
```

---

## ⚖️ Comparaison JADX GUI vs JD-GUI


| Aspect | JADX GUI v1.5.5 | JD-GUI v1.6.6 |
|--------|-----------------|----------------|
| **Format d'entrée** | APK directement | JAR uniquement (nécessite dex2jar) |
| **Ressources Android** | ✅ Manifeste, XML, assets | ❌ Aucun accès |
| **Noms de variables** | Reconstruits (`str`, `view`) | Génériques (`paramString`, `paramView`) |
| **Références R.\*** | Résolues (`R.layout.activity_main`) | Brutes (`2130903040`) |
| **Mode AES révélé** | Partiel (`"AES"`) | Complet (`"AES/ECB/PKCS7Padding"`) ✅ |
| **Verdict** | ⭐ Outil principal recommandé | Utile en complément pour croiser |

> 💡 **Conclusion** : JADX est supérieur pour l'analyse Android complète. JD-GUI reste utile pour croiser les résultats — ici il a révélé le mode cryptographique complet `AES/ECB/PKCS7Padding` que JADX affichait de façon incomplète.

---

## 🚨 Constats de sécurité

### Constat #1 — Clé AES et texte chiffré codés en dur

| | |
|---|---|
| **Sévérité** | 🔴 Élevée |
| **Localisation** | `sg.vantagepoint.uncrackable1.a` — méthode `a(String str)` |
| **Description** | La clé AES 128 bits (`8d127684cbc37c17616d806cf50473cc`) et le texte chiffré Base64 sont codés en dur dans le code source. Toute personne décompilant l'APK peut extraire et déchiffrer le secret en quelques minutes. |
| **Impact** | Extraction complète du secret (`"I want to believe"`) sans exécuter l'app. Perte totale de confidentialité. |
| **Remédiation** | Utiliser **Android Keystore System** pour stocker les clés. Déplacer la vérification côté serveur. Ne jamais inclure de secrets dans le code source. |

---

### Constat #2 — Mode cryptographique AES/ECB sans vecteur d'initialisation

| | |
|---|---|
| **Sévérité** | 🔴 Élevée |
| **Localisation** | `sg.vantagepoint.a.a` — `new SecretKeySpec(..., "AES/ECB/PKCS7Padding")` |
| **Description** | L'application utilise AES en mode ECB — le mode le plus faible. Chaque bloc de 16 octets est chiffré indépendamment, sans vecteur d'initialisation (IV). Des blocs identiques produisent des textes chiffrés identiques, rendant l'analyse de fréquence possible. |
| **Impact** | Un attaquant peut déduire des informations sur le texte clair sans connaître la clé. Mode non recommandé par les standards cryptographiques modernes (NIST). |
| **Remédiation** | Remplacer par **AES/GCM/NoPadding** avec un IV aléatoire de 12 octets généré à chaque chiffrement : `Cipher.getInstance("AES/GCM/NoPadding")` |

---

### Constat #3 — `android:allowBackup="true"` activé

| | |
|---|---|
| **Sévérité** | 🟠 Moyenne |
| **Localisation** | `AndroidManifest.xml` — balise `<application>` |
| **Description** | L'attribut `allowBackup="true"` autorise la sauvegarde complète des données de l'app via ADB sans root ni déverrouillage. |
| **Impact** | Accès physique momentané + câble USB = extraction de toutes les données (BDD, SharedPreferences, fichiers internes) avec `adb backup`. |
| **Remédiation** | Définir `android:allowBackup="false"`. Si backup partiel nécessaire, utiliser `android:fullBackupContent` avec règles d'exclusion pour les données sensibles. |

---

### Constat #4 — Détection root et debug contournable
| | |
|---|---|
| **Sévérité** | 🟠 Moyenne |
| **Localisation** | `sg.vantagepoint.uncrackable1.MainActivity` — méthode `onCreate()` |
| **Description** | L'app vérifie si le téléphone est rooté via `c.a()`, `c.b()`, `c.c()` et se ferme si positif. Ces vérifications sont trivialement contournables avec Frida en hookant les méthodes pour qu'elles retournent `false`. |
| **Impact** | Fausse impression de sécurité. Un attaquant contourne ces protections en moins de 5 minutes. |
| **Remédiation** | Ne pas fonder la sécurité sur ces mécanismes. Utiliser une vérification d'intégrité côté serveur. La sécurité doit être indépendante de l'environnement d'exécution. |

---

## 📊 Résumé des risques

```
🔴 Élevée  ██████████  2 constats  (#1 Clé AES hardcodée, #2 AES/ECB)
🟠 Moyenne ██████████  2 constats  (#3 allowBackup, #4 Détection root)
🟢 Faible  ░░░░░░░░░░  0 constat
```

**Niveau de risque global : 🔴 ÉLEVÉ**

---

## ✅ Actions prioritaires

1. **Immédiat** — Supprimer la clé AES du code source → utiliser Android Keystore
2. **Immédiat** — Remplacer AES/ECB par AES/GCM avec IV aléatoire
3. **Avant prod** — Définir `android:allowBackup="false"` dans le Manifeste
