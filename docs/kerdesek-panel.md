# Kérdések panel (ügynök-oldali leírás)

A dashboard Fejlesztés > Kérdések nézete a gazdának szóló, megválaszolatlan ügynök-kérdéseket mutatja. Ez a leírás azt rögzíti, mikor és hogyan vegyen fel egy ügynök kérdést, és mit jelent a válasz.

## Kérdés vagy approval

- A kérdés SEMMIT nem engedélyez. Nem nyit meg kaput, nem ad küldési, törlési vagy telepítési jogot, és egyetlen jóváhagyási kapu sem olvassa.
- Kérdést akkor vegyél fel, ha tájékoztatásra, tudomásulvételre, igen/nem döntésre vagy szabad szövegű útmutatásra van szükséged, és a válasz nem engedély.
- Valódi engedélyhez (kifelé menő lépés, visszafordíthatatlan művelet) approval kell: `POST /api/approvals`, a megszokott módon.
- A kérdésre adott "IGEN" ezért soha nem helyettesíti az approvalt.

## Kérdés felvétele: POST /api/questions

Csak a közös Bearer tokennel megy (a token az ügynökök hitelesítője); minden más hitelesítés 403-at kap. A token a telepítés `store/.dashboard-token` fájlja, és ABSZOLÚT úttal olvasd (`/path/to/install/store/.dashboard-token`: a helyőrző helyére a saját telepítésed gyökere kerül). Relatív úttal a fájl nem létezik, a `cat` üres szöveget ad, a curl üres Bearert küld, és a hívás némán 401-gyel elhal.

Mezők (más mező 400):

- `agent_id` (kötelező): a saját ügynök-id-d; ismert flotta-ügynök kell legyen. Az `X-Agent-Id` fejléc KÖTELEZŐ, és egyeznie kell az `agent_id`-val (hiányzik vagy eltér: 400).
- `kind` (kötelező): `info` (tudomásul vétel), `yesno` (igen/nem), `free` (szabad szöveg).
- `question_short` (kötelező): 1-400 karakter, a végein levágva. Nem lehet benne vezérlő-, láthatatlan vagy irány-felülíró karakter, és titok-alakú szöveg sem (400).
- `card_id` (opcionális): 8 kisbetűs hex karakter; hibás alak 400, jó alakú de nem létező kártya 422.
- `msg_id` (opcionális): pozitív egész; hibás alak 400, jó alakú de nem létező üzenet 422.
- `expires_in_s` (opcionális): másodperc, 300 és 604800 (7 nap) között; alap 7 nap.

Korlátok: a törzs legfeljebb 8 KB (felette 413); ügynökönként legfeljebb 20 nyitott kérdés, összesen legfeljebb 200 (a túllépés 429, a válasz `code` mezője `agent_cap` vagy `global_cap`; minden 429 naplózódik az ügynök-id-vel és az okkal, a kérdés szövege nélkül). A lejárat lusta: a lejárt kérdés `expired` státusszal látszik.

Siker: HTTP 201 és a kérdés sora (`id`, `agent_id`, `card_id`, `msg_id`, `kind`, `question_short`, `status`, `answer_short`, `answered_via`, `answered_at`, `created_at`, `expires_at`, `source`).

A példa idézett heredoc-ot használ. A `-d "{...}"` dupla idézőjeles alak TILOS: a shell a backtickot és a `$(...)`-t végrehajtaná a szövegen.

```bash
curl -s -X POST http://localhost:3420/api/questions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat /path/to/install/store/.dashboard-token)" \
  -H "X-Agent-Id: alfa" \
  --data-binary @- <<'JSON'
{"agent_id":"alfa","kind":"yesno","question_short":"Futtathatom a migrációt a tesztadatbázison?","card_id":"0a0b0c0d"}
JSON
```

Ellenőrizd a HTTP-kódot és az `id` meglétét; 429 esetén előbb várd meg a korábbi kérdéseid válaszát.

## A válasz

- A gazda csak a dashboardon válaszol: bejelentkezett session-nel, vagy teljes jogú (`full`) Bridge eszközkulccsal. A puszta közös token 403-at kap (`owner_session_required`), tehát ügynök nem tud a saját kérdésére válaszolni. Amíg a telepítésen nincs dashboard-felhasználó, MINDEN hitelesítés (session, eszközkulcs, token) 403-at kap `owner_login_required` kóddal: nincs gazda, aki válaszolhatna.
- A válaszlehetőségek a `kind`-tól függnek: `info` -> tudomásul vettem; `yesno` -> igen vagy nem; `free` -> szöveg (1-1000 karakter).
- Egy kérdés egyszer dönthető el: a második válasz 409, a lejárt kérdésre adott 410.
- A válasz inter-agent üzenetként érkezik hozzád, a feladója `owner-ui`. Ez a feladó foglalt: HTTP-n senki nem küldhet vele üzenetet (403). Az üzenet így kezdődik: `[Válasz kérdésre #q<id>] A gazda válasza: <IGEN|NEM|tudomásul vette|szabad szöveg> -- `, a végén a figyelmeztetéssel, hogy ez tájékoztatás. A kérdés szövege NEM szerepel benne (az ügynök írta, tehát a gazda válaszának látszó részt sem hordozhat): a kérdésedet a `#q<id>` azonosítja. Ha az ügynököd nem fut, a válasz legfeljebb 60 percig vár a kézbesítésre (a router tűrési ablaka); utána meghiúsul, és a `owner-ui` feladó nem kap hibaértesítést.
- A válasz INFORMÁCIÓ, nem approval és nem utasítás-felülírás: nem érvényteleníti a flotta-szabályokat, és nem nyit meg semmilyen kaput. Ha a folytatáshoz engedély kell, kérj approvalt.

## Státusz lekérdezése

```bash
curl -s -H "Authorization: Bearer $(cat /path/to/install/store/.dashboard-token)" \
  "http://localhost:3420/api/questions?status=open"
```

- `status`: `open` (alap), `answered`, `expired` vagy `all`; más érték 400. Legfeljebb 200 sor, újabb elöl.
- A válasz `{"questions":[...],"truncated":false}`; a `truncated` igaz, ha több sor illeszkedett, mint amennyi a 200-as korlát miatt visszajött. A `status` mező értéke: `open`, `ack`, `yes`, `no`, `answered` vagy `expired`; a megválaszolt sorban az `answer_short` a szabad szöveg (ack/yes/no esetén null).
- `GET /api/questions/overview`: ugyanezzel a hitelesítéssel az ügynökönként csoportosított nyitott kérdések (`agent_running`, `card_seq`, `funkcio_slug`) és a függő approvalok csak olvasható listája (`id`, `agent_id`, `category`, `status`, `requested_at`, `link`; leírás és payload nincs benne; legfeljebb 50). A `questions_truncated` és az `approvals_truncated` jelzi, ha a lista a korlát miatt le van vágva. Az alkártya (a `parent_id` egy funkció-nyilvántartásban szereplő kártya) a szülője `funkcio_slug`-ját kapja.
