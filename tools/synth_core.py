# -*- coding: utf-8 -*-
"""
synth_core.py — Génération d'entités 100 % fictives + validateurs (IBAN mod-97, AHV EAN-13, Luhn)
et table de pseudonymisation cohérente. Utilisé par generate_dataset.py.

Toute personne, adresse, numéro ou identifiant produit ici est synthétique.
Les numéros de carte sont des numéros de TEST publics (Stripe/Braintree docs), les e-mails
utilisent des domaines réservés (example.ch / example.com / exemple.fr — RFC 2606 / AFNIC).
"""
import random
import datetime as dt
import string

# ----------------------------------------------------------------------------
# Validateurs / générateurs de formats
# ----------------------------------------------------------------------------

def _iban_to_numeric(s: str) -> str:
    out = []
    for ch in s:
        if ch.isdigit():
            out.append(ch)
        else:
            out.append(str(ord(ch.upper()) - 55))  # A=10 ... Z=35
    return "".join(out)


def iban_check_digits(country: str, bban: str) -> str:
    numeric = _iban_to_numeric(bban + country + "00")
    return "%02d" % (98 - int(numeric) % 97)


def iban_is_valid(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if len(s) < 15 or not s[:2].isalpha():
        return False
    rearranged = s[4:] + s[:4]
    return int(_iban_to_numeric(rearranged)) % 97 == 1


def iban_format(iban_compact: str) -> str:
    s = iban_compact.replace(" ", "")
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4))


def gen_iban(rng: random.Random, country: str) -> str:
    """Retourne un IBAN compact valide (mod-97) pour CH / DE / FR / AT, comptes fictifs."""
    if country == "CH":
        bank = "%05d" % rng.randint(80000, 89999)          # clearing fictif
        acct = "".join(rng.choice(string.digits) for _ in range(12))
        bban = bank + acct
    elif country == "DE":
        blz = "%08d" % rng.randint(10000000, 99999999)
        acct = "%010d" % rng.randint(1, 9999999999)
        bban = blz + acct
    elif country == "FR":
        bank = "%05d" % rng.randint(10000, 99999)
        branch = "%05d" % rng.randint(10000, 99999)
        acct = "%011d" % rng.randint(1, 99999999999)
        key = 97 - ((89 * int(bank) + 15 * int(branch) + 3 * int(acct)) % 97)
        bban = bank + branch + acct + "%02d" % key
    elif country == "AT":
        bank = "%05d" % rng.randint(10000, 99999)
        acct = "%011d" % rng.randint(1, 99999999999)
        bban = bank + acct
    else:
        raise ValueError(country)
    return country + iban_check_digits(country, bban) + bban


def gen_invalid_iban_like(rng: random.Random) -> str:
    """Leurre : ressemble à un IBAN CH mais checksum mod-97 volontairement fausse."""
    while True:
        good = gen_iban(rng, "CH")
        cd = int(good[2:4])
        bad = good[:2] + "%02d" % ((cd + rng.randint(1, 96)) % 97 or 1) + good[4:]
        if not iban_is_valid(bad):
            return bad


def ean13_check_digit(d12: str) -> str:
    total = 0
    for i, ch in enumerate(d12):
        n = int(ch)
        total += n if i % 2 == 0 else 3 * n
    return str((10 - total % 10) % 10)


def gen_ahv(rng: random.Random) -> str:
    """N° AVS/AHV suisse fictif : 756.XXXX.XXXX.XX avec chiffre de contrôle EAN-13 correct."""
    d12 = "756" + "".join(rng.choice(string.digits) for _ in range(9))
    d13 = d12 + ean13_check_digit(d12)
    return "%s.%s.%s.%s" % (d13[0:3], d13[3:7], d13[7:11], d13[11:13])


def ahv_is_valid(ahv: str) -> bool:
    d = ahv.replace(".", "")
    return len(d) == 13 and d.startswith("756") and ean13_check_digit(d[:12]) == d[12]


def gen_invalid_ahv_like(rng: random.Random) -> str:
    good = gen_ahv(rng).replace(".", "")
    bad_cd = str((int(good[12]) + rng.randint(1, 9)) % 10)
    d13 = good[:12] + bad_cd
    return "%s.%s.%s.%s" % (d13[0:3], d13[3:7], d13[7:11], d13[11:13])


def luhn_is_valid(num: str) -> bool:
    d = [int(c) for c in num.replace(" ", "")]
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def gen_non_luhn_16(rng: random.Random) -> str:
    while True:
        s = "".join(rng.choice(string.digits) for _ in range(16))
        if not luhn_is_valid(s):
            return " ".join(s[i:i + 4] for i in range(0, 16, 4))


# Numéros de carte de TEST publics (documentation Stripe / Braintree / PayPal). Jamais des cartes réelles.
TEST_CARDS = [
    ("Visa", "4242 4242 4242 4242"),
    ("Visa", "4012 8888 8888 1881"),
    ("Visa", "4000 0566 5566 5556"),
    ("Visa", "4111 1111 1111 1111"),
    ("Mastercard", "5555 5555 5555 4444"),
    ("Mastercard", "5200 8282 8282 8210"),
    ("Mastercard", "5105 1051 0510 5100"),
    ("Mastercard", "2223 0031 2200 3222"),
    ("Amex", "3782 822463 10005"),
    ("Amex", "3714 496353 98431"),
    ("Discover", "6011 1111 1111 1117"),
    ("Discover", "6011 0009 9013 9424"),
]
# Pool DISJOINT de numéros de TEST publics (Stripe) pour les substitutions -> aucune collision original/substitution
TEST_CARDS_PSEUDO = [
    ("Visa", "4000 0075 6000 0009"),   # test CH
    ("Visa", "4000 0027 6000 0016"),   # test DE
    ("Visa", "4000 0025 0000 0003"),   # test FR
    ("Visa", "4000 0004 0000 0008"),   # test AT
    ("Visa", "4000 0082 6000 0000"),   # test GB
    ("Visa", "4000 0000 0000 0077"),
    ("Visa", "4000 0000 0000 0093"),
    ("Visa", "4000 0025 0000 3155"),
    ("Visa", "4000 0000 0000 3220"),
    ("Visa", "4000 0000 0000 9995"),
    ("JCB", "3566 0020 2036 0505"),
    ("Diners", "3056 9300 0902 0004"),
    ("UnionPay", "6200 0000 0000 0005"),
]

# ----------------------------------------------------------------------------
# Pools de noms (originaux) et pools de pseudonymes (DISJOINTS)
# ----------------------------------------------------------------------------
FIRST_M_ORIG = ["Eduard", "Julien", "Nicolas", "Pierre-Alain", "Laurent", "Mathieu", "Sébastien", "Olivier",
                "Frédéric", "Yann", "Cédric", "Thierry", "Romain", "Fabien", "Loïc", "Xavier",
                "Lukas", "Matthias", "Stefan", "Andreas", "Thomas", "Markus", "Reto", "Urs", "Beat",
                "Christoph", "Daniel", "Florian", "Simon", "Tobias", "Jonas", "Luca", "Alexandre", "Benoît", "Christian",
                "David", "Étienne", "Grégoire", "Hansruedi", "Jean-Marc", "Kevin", "Lionel", "Michael", "Norbert", "Philippe",
                "Rolf", "Stéphane", "Tristan", "Valentin", "Werner", "Yannick", "Adrian", "Bernhard", "Claude", "Dominik", "Erwin",
                "Gabriel", "Heinz", "Jérémie", "Kurt", "Ludovic", "Manuel", "Nathan", "Pascal-André", "Raphaël-Louis", "Sven"]
FIRST_F_ORIG = ["Anne-Sophie", "Camille", "Chloé", "Céline", "Nathalie", "Isabelle", "Valérie", "Sandrine",
                "Émilie", "Aurélie", "Maëlle", "Sophie", "Delphine", "Laetitia", "Christelle", "Mélanie",
                "Sandra", "Nicole", "Petra", "Claudia", "Barbara", "Andrea", "Friederike", "Regula", "Silvia",
                "Katrin", "Manuela", "Corinne", "Ursula", "Heidi", "Lena", "Giulia", "Amélie", "Béatrice-Anne", "Charlotte",
                "Doris", "Elisabeth", "Fabienne", "Gabrielle", "Hanna", "Ingrid", "Jacqueline", "Karine", "Laurence", "Marianne",
                "Nadine", "Odile", "Patricia", "Rachel", "Séverine", "Tatiana", "Véronique", "Yolande", "Anja", "Bettina", "Cornelia",
                "Denise", "Esther", "Florence", "Gerda", "Helena", "Irène", "Judith", "Lorena", "Monika", "Ruth"]
LAST_ORIG = ["Weber", "Bianchi", "Dupont", "Rochat", "Favre", "Müller", "Meier", "Schneider", "Huber", "Brunner",
             "Zimmermann", "Gerber", "Fischer", "Baumann", "Steiner", "Moser", "Widmer", "Frei", "Kaufmann", "Bovet",
             "Chevalley", "Ducret", "Pittet", "Jaquet", "Perrin", "Morel", "Girard", "Rossi", "Ferrari", "Conti",
             "Martin", "Bernard", "Roux", "Blanc", "Mercier", "Müller-Rey", "Da Silva", "Rey-Bellet", "Schmid",
             "Hofmann", "Graf", "Wyler", "Lambert", "Gauthier", "Vuilleumier", "Berthoud", "Ammann", "Stucki",
             "Arnold", "Bachmann", "Bissig", "Bosshard", "Burri", "Carrel", "Christen", "Crausaz", "Dessibourg", "Dietrich",
             "Fankhauser", "Flückiger", "Gafner", "Gilliéron", "Häfliger", "Hess", "Iten", "Jäggi", "Kaiser", "Kessler",
             "Kohler", "Leuenberger", "Locher", "Maillard", "Meyer", "Michel", "Nicolet", "Oppliger", "Pasquier", "Peter",
             "Progin", "Rausis", "Riedo", "Roth", "Ryser", "Schaller", "Sieber", "Studer", "Thürler", "Troillet",
             "Vonlanthen", "Waeber", "Wicht", "Zaugg", "Zehnder", "Zwahlen", "Bertschy", "Clément", "Genoud", "Pellet"]

FIRST_M_PSEUDO = ["Franz", "Anton", "Bruno", "Cyrille", "Damien", "Emil", "Gaspard", "Hugo", "Ivan", "Jérôme",
                  "Konrad", "Leandro", "Marcel", "Noé", "Oscar", "Paulin", "Quentin", "Ruben", "Silvan", "Théo",
                  "Ulrich", "Vincent", "Walter", "Yves", "Adrien", "Basile", "Colin", "Dorian", "Elias", "Fabrice",
                  "Gilles", "Hervé", "Kilian", "Loris", "Maxime", "Nils", "Patrick", "Robin", "Samuel", "Timo",
                  "Aurèle", "Baptiste", "Célestin", "Didier", "Edgar", "Félix", "Gérard", "Hippolyte", "Ignace", "Joris",
                  "Kaspar", "Lorenz", "Matteo", "Nino", "Ovide", "Pierrick", "Rémy", "Sacha", "Thibault", "Vital",
                  "Wendelin", "Xaver", "Yoann", "Zacharie", "Alban", "Barnabé", "Corentin"]
FIRST_F_PSEUDO = ["Alina", "Berthe", "Clara", "Dagmar", "Elodie", "Fanny", "Gisèle", "Hélène", "Iris", "Joëlle",
                  "Kristin", "Léa", "Margaux", "Nadia", "Océane", "Pauline", "Rahel", "Salomé", "Tamara", "Ulla",
                  "Viviane", "Yasmine", "Zoé", "Agnès", "Brigitte", "Colette", "Dalia", "Estelle", "Flavia",
                  "Géraldine", "Ines", "Jasmin", "Livia", "Mirjam", "Noémie", "Priska", "Romane", "Selina", "Tania", "Vera",
                  "Adèle", "Bérénice", "Capucine", "Diane", "Eliane", "Fleur", "Gwendoline", "Héloïse", "Ilona", "Justine",
                  "Klara", "Lucie", "Maude", "Ninon", "Ophélie", "Prune", "Rosalie", "Sibylle", "Thaïs", "Ulrike",
                  "Léonie", "Wanda", "Ysaline", "Zélie", "Anouk", "Bluette", "Clémence"]
LAST_PSEUDO = ["Keller", "Aebischer", "Berset", "Cuche", "Dubois", "Egger", "Fontana", "Gasser", "Hofer", "Imhof",
               "Jenni", "Koller", "Lüthi", "Mabillard", "Nussbaumer", "Oberholzer", "Portmann", "Ramseier", "Schär", "Tanner",
               "Uhlmann", "Vogel", "Wyss", "Zbinden", "Amrein", "Bühler", "Cattin", "Dähler", "Erni", "Fasel",
               "Grandjean", "Hürlimann", "Jeanneret", "Kunz", "Lehmann", "Monney", "Nyffeler", "Odermatt", "Pfister",
               "Ruffieux", "Suter", "Thalmann", "Vuadens", "Wenger", "Zürcher", "Bapst", "Chappuis", "Deillon", "Gremaud",
               "Kolly", "Maradan", "Python", "Ropraz", "Sudan", "Villoz", "Aeby", "Balmer", "Brügger", "Castella", "Cotting",
               "Dafflon", "Dorthe", "Feuz", "Gachet", "Gobet", "Grangier", "Hayoz", "Jungo", "Käser", "Lauper",
               "Mauron", "Mettraux", "Niederhauser", "Overney", "Pochon", "Raemy", "Repond", "Rime", "Rotzetter", "Sallin",
               "Schmutz", "Schouwey", "Sturny", "Tinguely", "Ulrich", "Vial", "Bise", "Wider", "Yerly", "Zosso",
               "Andrey", "Bongard", "Chassot", "Dénervaud", "Roulin", "Fragnière", "Gendre", "Humbert", "Jaquier", "Longchamp"]

assert not set(FIRST_M_ORIG) & set(FIRST_M_PSEUDO)
assert not set(FIRST_F_ORIG) & set(FIRST_F_PSEUDO)
assert not set(LAST_ORIG) & set(LAST_PSEUDO)

STREETS_ORIG = ["Chemin du Lac-Bleu", "Rue des Trois-Sapins", "Avenue de la Colline-Verte", "Route du Vieux-Moulin",
                "Impasse des Lilas-Blancs", "Sentier de la Roselière", "Place du Petit-Marché", "Rue de la Fontaine-Ronde",
                "Chemin des Vignes-Hautes", "Allée des Cerisiers-Roses", "Bergstrasse", "Sonnenhaldenweg", "Lindenhofstrasse",
                "Am Mühlebach", "Rebenweg", "Feldblumenstrasse", "Tannenrainstrasse", "Seeblickweg", "Birkenhofstrasse",
                "Alte Landstrasse", "Via dei Castagni Fioriti", "Via Monte Chiaro"]
STREETS_PSEUDO = ["Rue du Grand-Pré", "Chemin de la Combe-Fleurie", "Avenue des Platanes-Gris", "Route de la Sauge",
                  "Impasse du Ruisseau-Clair", "Sentier des Ormes", "Place de l'Ancienne-Gare", "Rue du Four-Banal",
                  "Chemin des Noyers-Verts", "Allée des Tilleuls-d'Or", "Hügelweg", "Wiesenbachstrasse", "Ahornhofstrasse",
                  "Im Sonnenfeld", "Kirschbaumweg", "Rosengartenstrasse", "Buchenrainweg", "Talblickstrasse", "Eichenhofweg",
                  "Neue Dorfstrasse", "Via delle Querce Alte", "Via Colle Sereno"]
CITIES = [("1201", "Genève"), ("1205", "Genève"), ("1003", "Lausanne"), ("1007", "Lausanne"), ("1260", "Nyon"),
          ("1800", "Vevey"), ("1820", "Montreux"), ("1400", "Yverdon-les-Bains"), ("1700", "Fribourg"),
          ("2000", "Neuchâtel"), ("2502", "Biel/Bienne"), ("1950", "Sion"), ("3011", "Bern"), ("3600", "Thun"),
          ("4051", "Basel"), ("4600", "Olten"), ("6003", "Luzern"), ("6300", "Zug"), ("8001", "Zürich"),
          ("8004", "Zürich"), ("8400", "Winterthur"), ("9000", "St. Gallen"), ("7000", "Chur"), ("6900", "Lugano"),
          ("6500", "Bellinzona"), ("1870", "Monthey")]

INSURERS = ["Alpina Assurances Fictives SA", "Helvetia-Nord Krankenkasse (fiktiv)", "Mutuelle du Léman Fictive",
            "Caisse-Maladie Jura-Fictive", "Sanitas-Süd Versicherung (fiktiv)"]

# Diagnostics (code ICD-10, libellé FR, libellé DE, généralisation "stricte" = chapitre)
DIAGNOSES = [
    ("E11.9", "Diabète sucré de type 2 sans complication", "Diabetes mellitus Typ 2 ohne Komplikationen", "E00-E90 Maladies endocriniennes"),
    ("I10", "Hypertension essentielle", "Essentielle Hypertonie", "I00-I99 Maladies de l'appareil circulatoire"),
    ("J45.9", "Asthme, sans précision", "Asthma bronchiale, nicht näher bezeichnet", "J00-J99 Maladies de l'appareil respiratoire"),
    ("F32.1", "Épisode dépressif moyen", "Mittelgradige depressive Episode", "F00-F99 Troubles mentaux et du comportement"),
    ("M54.5", "Lombalgie basse", "Kreuzschmerz", "M00-M99 Maladies du système ostéo-articulaire"),
    ("C50.9", "Tumeur maligne du sein, sans précision", "Bösartige Neubildung der Brustdrüse", "C00-D48 Tumeurs"),
    ("K21.0", "Reflux gastro-œsophagien avec œsophagite", "Gastroösophageale Refluxkrankheit mit Ösophagitis", "K00-K93 Maladies de l'appareil digestif"),
    ("G40.9", "Épilepsie, sans précision", "Epilepsie, nicht näher bezeichnet", "G00-G99 Maladies du système nerveux"),
    ("N18.3", "Maladie rénale chronique, stade 3", "Chronische Nierenkrankheit, Stadium 3", "N00-N99 Maladies de l'appareil génito-urinaire"),
    ("B20", "Maladie par VIH", "HIV-Krankheit", "A00-B99 Maladies infectieuses"),
    ("I25.1", "Cardiopathie athéroscléreuse", "Atherosklerotische Herzkrankheit", "I00-I99 Maladies de l'appareil circulatoire"),
    ("F10.2", "Troubles mentaux liés à l'alcool, syndrome de dépendance", "Alkoholabhängigkeitssyndrom", "F00-F99 Troubles mentaux et du comportement"),
]
# Médications associées (nom + posologie, classe ATC pour la généralisation stricte)
MEDS_BY_DX = {
    "E11.9": [("Metformine 850 mg 2x/j", "Antidiabétique oral (A10B)"), ("Insuline glargine 20 UI le soir", "Insuline (A10AE)")],
    "I10": [("Lisinopril 10 mg 1x/j", "Inhibiteur de l'ECA (C09A)"), ("Amlodipine 5 mg 1x/j", "Inhibiteur calcique (C08CA)")],
    "J45.9": [("Salbutamol 100 µg inhalateur, 2 bouffées au besoin", "Bronchodilatateur (R03A)")],
    "F32.1": [("Sertraline 50 mg 1x/j", "Antidépresseur ISRS (N06AB)")],
    "M54.5": [("Ibuprofène 400 mg 3x/j", "AINS (M01A)")],
    "C50.9": [("Tamoxifène 20 mg 1x/j", "Antiestrogène (L02BA)")],
    "K21.0": [("Pantoprazole 40 mg 1x/j", "Inhibiteur de la pompe à protons (A02BC)")],
    "G40.9": [("Lévétiracétam 500 mg 2x/j", "Antiépileptique (N03AX)")],
    "N18.3": [("Lisinopril 5 mg 1x/j", "Inhibiteur de l'ECA (C09A)")],
    "B20": [("Emtricitabine/Ténofovir 200/245 mg 1x/j", "Antirétroviral (J05AR)")],
    "I25.1": [("Atorvastatine 20 mg 1x/j", "Hypolipémiant statine (C10AA)")],
    "F10.2": [("Acamprosate 333 mg 3x/j", "Traitement de la dépendance alcoolique (N07BB)")],
}

# ----------------------------------------------------------------------------
# Substitutions DÉTERMINISTES par valeur (une même valeur originale -> toujours la même substitution)
# ----------------------------------------------------------------------------
import hashlib as _hashlib

_CITY_SHIFT = 7  # dérangement : rotation de 7 sur 26 villes => aucune ville ne se substitue à elle-même


def pseudo_city(npa: str, city: str):
    idx = [i for i, c in enumerate(CITIES) if c == (npa, city)][0]
    return CITIES[(idx + _CITY_SHIFT) % len(CITIES)]


def pseudo_street(street_with_number: str) -> str:
    name, num = street_with_number.rsplit(" ", 1)
    idx = STREETS_ORIG.index(name)
    n = int(num)
    return "%s %d" % (STREETS_PSEUDO[idx], ((n * 7) % 120) + 1)   # 6n ≡ -1 (mod 120) impossible => jamais identique


def pseudo_dob(d: dt.date) -> dt.date:
    h = int(_hashlib.md5(d.isoformat().encode()).hexdigest(), 16)
    shift = 40 + (h % 280)
    return d + dt.timedelta(days=shift if (h >> 8) % 2 == 0 else -shift)


MONTHS_FR = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"]
MONTHS_DE = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"]


def fmt_date(d: dt.date, style: str = "dotted") -> str:
    if style == "dotted":
        return d.strftime("%d.%m.%Y")
    if style == "iso":
        return d.isoformat()
    if style == "long_fr":
        return "%d %s %d" % (d.day, MONTHS_FR[d.month - 1], d.year)
    if style == "long_de":
        return "%d. %s %d" % (d.day, MONTHS_DE[d.month - 1], d.year)
    raise ValueError(style)


def strip_accents_simple(s: str) -> str:
    table = str.maketrans("àâäéèêëîïôöùûüçÀÂÄÉÈÊËÎÏÔÖÙÛÜÇœŒ", "aaaeeeeiioouuucAAAEEEEIIOOUUUCoO")
    return s.translate(table)


def email_for(first: str, last: str, rng: random.Random) -> str:
    f = strip_accents_simple(first).lower().replace("-", ".").replace(" ", "")
    l = strip_accents_simple(last).lower().replace("-", "").replace(" ", "")
    dom = rng.choice(["example.ch", "example.com", "exemple.fr", "example.org"])
    return "%s.%s@%s" % (f, l, dom)


def phone_ch(rng: random.Random, mobile: bool) -> str:
    # Numéros synthétiques : blocs "000" improbables ; voir README.
    if mobile:
        return "+41 79 000 %02d %02d" % (rng.randint(0, 99), rng.randint(0, 99))
    return "+41 %s 000 %02d %02d" % (rng.choice(["21", "22", "24", "26", "27", "31", "32", "44", "61", "71"]),
                                    rng.randint(0, 99), rng.randint(0, 99))


def phone_fr_fiction(rng: random.Random) -> str:
    # Tranche réservée par l'ARCEP aux œuvres de fiction : 06 39 98 xx xx
    return "+33 6 39 98 %02d %02d" % (rng.randint(0, 99), rng.randint(0, 99))


# ----------------------------------------------------------------------------
# Entités
# ----------------------------------------------------------------------------
class Person(dict):
    """dict avec accès attribut."""
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError as e:
            raise AttributeError(k) from e


def build_entities(seed: int, n_patients: int = 64, n_physicians: int = 8, n_staff: int = 4, n_relatives: int = 16):
    rng = random.Random(seed)
    used_first_orig = set()
    used_last_orig = set()
    used_first_ps = set()
    used_last_ps = set()
    used_pat_ids = set()
    used_ins = set()
    used_ahv = set()
    used_iban = set()

    def pick_unique(pool, used):
        cand = [x for x in pool if x not in used]
        if not cand:
            raise RuntimeError("Pool de noms épuisé — agrandir les listes dans synth_core.py")
        x = rng.choice(cand)
        used.add(x)
        return x

    used_phones = set()

    def unique_phone(fn, *args):
        while True:
            v = fn(*args)
            if v not in used_phones:
                used_phones.add(v)
                return v

    def new_pat_id():
        while True:
            pid = "PAT-2026-%05d" % rng.randint(100, 99999)
            if pid not in used_pat_ids:
                used_pat_ids.add(pid)
                return pid

    def new_ins():
        while True:
            s = "80756" + "%05d" % rng.choice([1599, 1602, 1611, 1643, 1688]) + "%010d" % rng.randint(0, 9999999999)
            if s not in used_ins:
                used_ins.add(s)
                return " ".join(s[i:i + 5] for i in range(0, 20, 5))

    def new_ahv():
        while True:
            a = gen_ahv(rng)
            if a not in used_ahv:
                used_ahv.add(a)
                return a

    def new_iban(country):
        while True:
            i = gen_iban(rng, country)
            if i not in used_iban:
                used_iban.add(i)
                return i

    def make_address():
        """Adresse originale + pseudo-adresse dérivée de façon DÉTERMINISTE (même valeur -> même substitution)."""
        si = rng.randrange(len(STREETS_ORIG))
        num = rng.randint(1, 120)
        ci = rng.randrange(len(CITIES))
        npa, city = CITIES[ci]
        ps_npa, ps_city = pseudo_city(npa, city)
        return {"street": "%s %d" % (STREETS_ORIG[si], num), "npa": npa, "city": city,
                "ps_street": pseudo_street("%s %d" % (STREETS_ORIG[si], num)), "ps_npa": ps_npa, "ps_city": ps_city}

    persons = []

    def make_person(role, idx, forced=None):
        gender = rng.choice(["M", "F"])
        lang = rng.choice(["fr", "fr", "de"])
        if forced:
            gender, lang = forced["gender"], forced["lang"]
        first_pool = FIRST_M_ORIG if gender == "M" else FIRST_F_ORIG
        ps_first_pool = FIRST_M_PSEUDO if gender == "M" else FIRST_F_PSEUDO
        first = forced["first"] if forced else pick_unique(first_pool, used_first_orig)
        last = forced["last"] if forced else pick_unique(LAST_ORIG, used_last_orig)
        used_first_orig.add(first); used_last_orig.add(last)
        ps_first = forced["ps_first"] if forced else pick_unique(ps_first_pool, used_first_ps)
        ps_last = forced["ps_last"] if forced else pick_unique(LAST_PSEUDO, used_last_ps)
        used_first_ps.add(ps_first); used_last_ps.add(ps_last)
        if role == "patient":
            dob = dt.date(rng.randint(1938, 2004), rng.randint(1, 12), rng.randint(1, 28))
        else:
            dob = dt.date(rng.randint(1960, 1992), rng.randint(1, 12), rng.randint(1, 28))
        if forced and forced.get("dob"):
            dob = forced["dob"]
        ps_dob = pseudo_dob(dob)
        addr = make_address()
        country = rng.choices(["CH", "DE", "FR", "AT"], weights=[60, 15, 15, 10])[0]
        use_fr_phone = (lang == "fr" and rng.random() < 0.25)
        p = Person(
            entity_id="%s%03d" % ({"patient": "P", "physician": "D", "staff": "S", "relative": "R"}[role], idx),
            role=role, gender=gender, lang=lang,
            first=first, last=last, ps_first=ps_first, ps_last=ps_last,
            dob=dob, ps_dob=ps_dob,
            street=addr["street"], npa=addr["npa"], city=addr["city"],
            ps_street=addr["ps_street"], ps_npa=addr["ps_npa"], ps_city=addr["ps_city"],
            email=email_for(first, last, rng), ps_email=email_for(ps_first, ps_last, rng),
            phone=(unique_phone(phone_fr_fiction, rng) if use_fr_phone else unique_phone(phone_ch, rng, rng.random() < 0.6)),
            ps_phone=unique_phone(phone_ch, rng, rng.random() < 0.6),
        )
        if role == "patient":
            p["patient_id"] = new_pat_id(); p["ps_patient_id"] = new_pat_id()
            p["ahv"] = new_ahv(); p["ps_ahv"] = new_ahv()
            p["insurer"] = rng.choice(INSURERS)
            p["insurance_no"] = new_ins(); p["ps_insurance_no"] = new_ins()
            p["iban_country"] = country
            p["iban"] = new_iban(country); p["ps_iban"] = new_iban(country)
            dx = rng.choice(DIAGNOSES)
            if gender == "M" and dx[0] == "C50.9":
                dx = DIAGNOSES[0]
            p["dx_code"], p["dx_fr"], p["dx_de"], p["dx_strict"] = dx
            med = rng.choice(MEDS_BY_DX[dx[0]])
            p["med"], p["med_strict"] = med
            p["card"] = None
        elif role == "relative":
            p["relation"] = rng.choice(["conjoint(e)", "fils", "fille", "frère", "sœur", "partenaire"])
        else:
            p["title"] = "Dr" if role == "physician" else ""
            p["function"] = rng.choice(["Médecin-chef", "Médecin adjoint", "Cheffe de clinique", "Médecin assistant"]) if role == "physician" \
                else rng.choice(["Responsable facturation", "Secrétaire médicale", "Gestionnaire admissions", "Responsable qualité"])
        persons.append(p)
        return p

    # Persona pivot demandée : Eduard Weber -> Franz Keller (cohérence inter-documents)
    weber = make_person("patient", 1, forced={"gender": "M", "lang": "de", "first": "Eduard", "last": "Weber",
                                                 "ps_first": "Franz", "ps_last": "Keller", "dob": dt.date(1962, 3, 14)})
    for i in range(2, n_patients + 1):
        make_person("patient", i)
    for i in range(1, n_physicians + 1):
        make_person("physician", i)
    for i in range(1, n_staff + 1):
        make_person("staff", i)
    for i in range(1, n_relatives + 1):
        make_person("relative", i)

    patients = [p for p in persons if p.role == "patient"]
    physicians = [p for p in persons if p.role == "physician"]
    staff = [p for p in persons if p.role == "staff"]
    relatives = [p for p in persons if p.role == "relative"]

    # Cartes de test : 10 patients, mapping carte->carte distinct
    cards = list(TEST_CARDS)
    rng.shuffle(cards)
    ps_cards = list(TEST_CARDS_PSEUDO)
    rng.shuffle(ps_cards)
    card_patients = rng.sample(patients[1:], 9)
    card_patients.insert(0, weber)
    for i, p in enumerate(card_patients):
        p["card_brand"], p["card"] = cards[i]
        p["ps_card_brand"], p["ps_card"] = ps_cards[i]

    # Médecin traitant et contact d'urgence par patient
    for p in patients:
        p["physician"] = rng.choice(physicians).entity_id
        p["relative"] = rng.choice(relatives).entity_id

    return rng, patients, physicians, staff, relatives


def person_by_id(persons, eid):
    for p in persons:
        if p.entity_id == eid:
            return p
    raise KeyError(eid)


def honorific(p: Person, lang: str = "fr") -> str:
    if lang == "de":
        return "Herr" if p.gender == "M" else "Frau"
    return "M." if p.gender == "M" else "Mme"


def mapping_rows(persons):
    """Table de pseudonymisation (entity_id, role, field, original, replacement)."""
    rows = []
    for p in persons:
        base = [
            ("FIRST_NAME", p.first, p.ps_first),
            ("LAST_NAME", p.last, p.ps_last),
            ("DATE_OF_BIRTH", fmt_date(p.dob), fmt_date(p.ps_dob)),
            ("STREET_ADDRESS", p.street, p.ps_street),
            ("POSTAL_CITY", "%s %s" % (p.npa, p.city), "%s %s" % (p.ps_npa, p.ps_city)),
            ("EMAIL", p.email, p.ps_email),
            ("PHONE", p.phone, p.ps_phone),
        ]
        if p.role == "patient":
            base += [
                ("PATIENT_ID", p.patient_id, p.ps_patient_id),
                ("AHV_NUMBER", p.ahv, p.ps_ahv),
                ("INSURANCE_CARD_NUMBER", p.insurance_no, p.ps_insurance_no),
                ("IBAN", iban_format(p.iban), iban_format(p.ps_iban)),
            ]
            if p.card:
                base.append(("CREDIT_CARD", p.card, p.ps_card))
        for field, o, r in base:
            rows.append({"entity_id": p.entity_id, "role": p.role, "field": field, "original": o, "replacement": r})
    return rows
