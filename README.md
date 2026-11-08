# Overjeno šifriranje

Laboratorijska vaja pri predmetu Varnost podatkov je namenjena učenju uporabe
AES-GCM v Pythonu in Javi, izpeljavi ključa iz gesla, zaščiti telefonskega
imenika ter implementaciji šifre Fernet.

## Priprava okolja

Potrebujete Python in pakete iz `requirements.txt`. V korenu repozitorija jih
namestite z:

```sh
python -m pip install -r requirements.txt
```

Če uporabljate Nix, lahko okolje pripravite z `nix develop`. Nato iz korena
repozitorija odprite zvezek:

```sh
jupyter lab assignments.ipynb
```

Za javanske naloge potrebujete JDK 17 ali novejši in Maven. Projekt odprite v
razvojnem okolju kot **Mavenov projekt**, tako da izberete korensko datoteko
`pom.xml`. Programe zaganjajte iz korena repozitorija, da bodo relativne poti do
datotek v `data/` pravilne.

## Delo z nalogo

- Navodila in prostor za rešitve v Pythonu so v `assignments.ipynb`. Dopolnite
  celice z oznako `# VAŠA REŠITEV` ter ohranite podpise funkcij, priložene teste
  in metapodatke celic.
- Pri nalogi 2 dopolnite `src/main/java/fri/vp/CommunicationExampleGCM.java`.
  V pomoč je primer `GCMExample.java` v isti mapi.
- Pri nalogi 4 dopolnite `pb.py`. Ustvarjeno datoteko telefonskega imenika
  potrebujete tudi pri nalogi 5.
- Pri nalogi 5 dopolnite `src/main/java/fri/vp/ReadPhoneBookFile.java`. Primer
  izpeljave ključa je v `KeyDerivation.java` v isti mapi.
- Rešitve preverjajte s priloženimi testi in lastnimi primeri. Pred oddajo znova
  zaženite jedro zvezka in izvedite celice po vrsti. `NotImplementedError` v
  nedopolnjeni funkciji pomeni, da jo morate še napisati.

## Oddaja

Oddajte izpolnjeni `assignments.ipynb`, spremenjeni `pb.py` ter javanski datoteki
`src/main/java/fri/vp/CommunicationExampleGCM.java` in
`src/main/java/fri/vp/ReadPhoneBookFile.java`. Če rešitev uporablja dodatne
pomožne datoteke, oddajte tudi te in ohranite strukturo projekta. Razvojnega
okolja in ustvarjene datoteke telefonskega imenika ni treba oddajati.
