# TimeFabric alapú elektronikus szavazási Rendszer - Kutatási Prototípus

Decentralizált, nyilvánosan ellenőrizhető és adatvédelmet biztosító elektronikus választási prototípus **Hyperledger Fabric v1.4** blokklánc-alapon.

Ez a repo egy tudományos kutatáshoz kifejlesztett kísérleti prototípus megvalósítását tartalmazza. A rendszer demonstrálja a **küszöbértékes elliptikus görbe kriptográfia (EC-ElGamal)**, a **nullaismeretű bizonyítások (NIZKP)** és az **engedélyköteles (permissioned) blokklánc** együttes alkalmazását a választási folyamat teljes életciklusában.

---

## A prototípus elméleti és kutatási háttere

A megvalósítás az alábbi elméleti pillérekre és matematikai primitívekre épül:

| Kutatási terület | Téma | Megvalósítás |
|---|---|---|
| **Kriptográfiai primitívek** | NIST P-256 görbe, SEC 1 ponttömörítés, additív homomorf EC-ElGamal titkosítás, 1-a-$\rho$-ból Chaum-Pedersen NIZKP (Fiat-Shamir heurisztikával), Chaum-Pedersen DLEQ bizonyítások, választói ECDSA aláírások. | `chaincode/voting.go`, `client/crypto/crypto.go` |
| **Megbízható időkezelés** | Időbélyeg-ellenőrzés a szavazási idősáv betartásához (TimeFabric `GetTimenow()` felület és Fabric tranzakciós időbélyeg tartalék megoldás). | `chaincode/voting.go:getTrustedTime` |
| **Választási protokoll-életciklus** | 5 fázisú folyamat: Inicializálás és DKG kulcsmegosztás, Választói regisztráció, Névtelen szavazatleadás és kettős szavazás megakadályozása, Láncon végzett homomorf összegzés, Küszöbértékes visszafejtés Lagrange-interpolációval. | `chaincode/voting.go`, `client/` programok |
| **Adatméret és sávszélesség-optimalizáció** | SEC 1 33 bájtos tömörített elliptikus pontok és 32 bájtos skalárok használata, minimálisra csökkentve a tranzakcióméretet (~618 bájt $\rho=3$ jelölt esetén). | `chaincode/voting.go`, `client/crypto/types.go` |
| **Bizánci hibatűrés (BFT)** | 6 tagú Választási Bizottság (Election Authority, $n=6, f=1, t=f+1=2$) több-peer jóváhagyási (endorsement) és küszöbértékes visszafejtési modellel. | `docker-compose.yaml`, `ColdBoot.sh`, `client/connection.yaml` |


## A választási protokoll működési lépései

1. **0. fázis: Előkészítés és DKG kulcsmegosztás (`client setup`)**
   - Szimulálja a Joint-Feldman elosztott kulcsgenerálást (DKG) a $n=6$ bizottsági tag között.
   - Létrejön a közös választási publikus kulcs ($Y = x \cdot G$), és minden tag megkapja a saját titkos kulcsrészét ($s_i$), valamint a hozzá tartozó ellenőrző kulcsot ($Y_i = s_i \cdot G$).
   - Rögzíti a választási paramétereket, jelölteket és a $t=2$ küszöbértéket a blokkláncon (`initElection`).

2. **1. fázis: Választói regisztráció (`client vote` -> `registerVoter`)**
   - A választók saját P-256 ECDSA kulcspárt generálnak.
   - A nyilvános kulcsokat a láncon regisztrálják tömörített 33 bájtos SEC 1 formátumban.
   - Az okosszerződés ellenőrzi a jogosultságot és kizárja a többszörös regisztrációt.

3. **2. fázis: Névtelen szavazatleadás (`client vote` -> `castBallot`)**
   - A választó a kiválasztott jelölthöz egy One-Hot vektort képez: $(v_0, \dots, v_{\rho-1})$.
   - Minden komponenst additív ElGamal-lal titkosít: $A_i = r_i \cdot G$, $B_i = v_i \cdot G + r_i \cdot Y$.
   - Generál egy 1-a-$\rho$-ból Chaum-Pedersen nem-interaktív nullaismeretű bizonyítást (NIZKP), igazolva a szavazat érvényességét a titkosítás feloldása nélkül.
   - A szavazat kriptográfiai lenyomatát aláírja a saját ECDSA privát kulcsával.
   - Az okosszerződés ellenőrzi az aláírást, az időablakot, a NIZKP-t és a kettős szavazás kizárását, majd rögzíti a szavazatot.

4. **3. fázis: Láncon végzett homomorf összesítés (`tallyVotes`)**
   - Az okosszerződés komponensenként összeadja az összes elfogadott rejtjelszöveget anélkül, hogy az egyes szavazatokat feloldaná:
     $$C_{1,j}^* = \sum_{k} A_{k,j}, \quad C_{2,j}^* = \sum_{k} B_{k,j}$$

5. **4. fázis: Küszöbértékes visszafejtés és ellenőrzés (`client tally`)**
   - Legalább $t=2$ független hatóság kiszámítja a részleges visszafejtési pontokat ($D_{i,j} = s_i \cdot C_{1,j}^*$), és Chaum-Pedersen DLEQ bizonyítást csatol hozzá.
   - A részleges visszafejtéseket az okosszerződés ellenőrzi és rögzíti (`submitDecryptionShare`).
   - Lagrange-interpolációval előáll az összesített tiszta pont:
     $$M_j^* = C_{2,j}^* - \sum_{i \in S} \lambda_i D_{i,j} = T_j \cdot G$$
   - Diszkrét logaritmus kereséssel meghatározásra kerül az egyes jelöltek szavazatszáma ($T_j$), amelyet az okosszerződés hitelesít és közzétesz (`finalizeTally`).

---

## Repozitórium struktúra

```
.
├── ColdBoot.sh                 # Teljes hálózatindító script
├── UpgradeChaincode.sh         # Chaincode frissítő script
├── ReInitElection.sh           # Választási állapot alaphelyzetbe állítása
├── clearVotes.sh               # Parancssori törlés
├── docker-compose.yaml         # Docker topológia, Orderer + 6 EA Peer konténer
├── configtx.yaml               # Fabric csatorna és genesis blokk konfiguráció
├── crypto-config.yaml          # MSP kriptográfiai generátor specifikáció
├── core.yaml / orderer.yaml    # Peer és Orderer konfigurációs sablonok
├── .gitignore                  # Gitignore
├── README.md                   # Rendszerdokumentáció
├── bin/                        # Hyperledger Fabric bináris eszközök
│   ├── cryptogen
│   ├── configtxgen
│   └── peer
├── chaincode/                  # Okosszerződés 
│   ├── voting.go               # Fő szavazási okosszerződés
│   └── voting_test.go          # Teljes életciklus teszt
└── client/                     # Go kliensprogramok és könyvtárak
    ├── connection.yaml         # Fabric Go SDK kapcsolati profil
    ├── go.mod, go.sum          # Kliens függőségek leírása
    ├── run_demo.sh             # Teljes szimulációt futtató szkript
    ├── benchmark.sh            # Teljesítmény- és kapacitásmérő script
    ├── main.go                 # Egységes kliens CLI (setup, vote, tally, demo, clear)
    ├── benchmark.go            # Párhuzamos terheléstesztelő
    └── crypto/                 # Kriptográfiai könyvtár
        ├── crypto.go           # ElGamal, NIZKP, DLEQ, Lagrange, SEC 1 műveletek
        └── types.go            # Adatstruktúrák és JSON szerializáció
```

---

## Futtatás és tesztelés

### Rendszerkövetelmények
- Linux vagy Windows WSL2 környezet
- Docker és Docker Compose
- Szükséges Docker image-ek:
  - `hyperledger/fabric-peer:1.4.12`
  - `hyperledger/fabric-orderer:1.4.12`
  - `hyperledger/fabric-tools:1.4.12`
  - `hyperledger/fabric-ccenv:1.4`
  - `golang:1.19`

### 1. Hálózat indítása (Cold Boot)
A gyökérkönyvtárból futtatva letakarítja az esetleges korábbi konténereket, legenerálja a tanúsítványokat, elindítja a 6 peert és az orderert, létrehozza a csatornát, majd telepíti az okosszerződést:

```bash
./ColdBoot.sh
```

### 2. Okosszerződés egységteszt futtatása
A teszt az okosszerződés teljes matematikai és logikai életciklusát ellenőrzi Fabric mock környezetben:

```bash
docker run --rm \
  -v $(pwd)/chaincode:/chaincode \
  -w /chaincode \
  hyperledger/fabric-ccenv:1.4 \
  go test -v .
```

### 3. Teljes választási szimuláció futtatása
Lefuttatja a teljes folyamatot a DKG beállítástól a szavazatleadáson és kettős szavazás ellenőrzésen át a hitelesített végeredmény kihirdetéséig:

```bash
cd client
./run_demo.sh
```

### 4. Terhelés- és kapacitásmérés (Benchmark)
A szavazatleadási áteresztőképesség (TPS), késleltetés és kriptográfiai időigények mérésére:

```bash
cd client
# 1000 szavazó, 25 párhuzamos szál, végén összegzéssel:
./benchmark.sh -n 1000 -c 25 --tally

# Tömeges regisztrációval (100 szavazó/tranzakció):
./benchmark.sh -n 1000 -c 25 --batch --tally

# 10 000 szavazó, 10 jelölt (50 párhuzamos szál, kötegelt regisztráció, automatikus összegzés):
./benchmark.sh -n 10000 -k 10 -c 50 --batch --tally
```

---

## Karbantartási segédeszközök

- **Választás újraindítása**: Törli a szavazatokat és választói rekordokat Docker újraindítás nélkül:
  ```bash
  ./ReInitElection.sh
  ```
- **Chaincode frissítése**: Újracsomagolja és feltelepíti a chaincode-ot a következő verziószámmal:
  ```bash
  ./UpgradeChaincode.sh
  ```
- **Főkönyvi szavazatok törlése**: Parancssori közvetlen törlés:
  ```bash
  ./clearVotes.sh
  ```

---

## Kriptográfiai paraméterek összefoglalása

- **Görbe típusa**: NIST P-256 ($y^2 = x^3 - 3x + b \pmod p$).
- **Pontok ábrázolása**: SEC 1 szabvány szerinti 33 bájtos tömörített hex formátum (`0x02` / `0x03` előtaggal).
- **Skalárok ábrázolása**: 32 bájtos big-endian hex sztringek.
- **Küszöbérték-rendszer**: Shamir titokmegosztás $\mathbb{F}_q$ felett ($n=6, t=2$, $f=1$ hibás csomópont tolerálásával).
- **Nullaismeretű bizonyítás**: Nem-interaktív Chaum-Pedersen OR kompozíció Fiat-Shamir heurisztikával ($1$-a-$\rho$-ból).
- **Digitális aláírás**: ECDSA P-256 görbén SHA-256 lenyomattal.
