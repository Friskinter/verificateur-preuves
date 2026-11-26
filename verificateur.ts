// Vérificateur des preuves signées des versions du document unique produites par Frisk Plateforme
// (format décrit dans le README). Il ne lit aucune base de données : il reçoit un fichier de preuve, la
// liste des clés de confiance et, si on les a, l'instantané, l'entrée du registre et le PDF.
//
// Volontairement autonome : il ne dépend que de node:crypto, pour pouvoir être lancé seul
// (verifier-preuve.mts) et relu indépendamment. Sa propre écriture RFC 8785 est comparée par les tests
// à celle qu'utilise Frisk Plateforme pour enregistrer les versions (tests/canonique.ts).
//
// Syntaxe TypeScript « effaçable » seulement (pas d'enum, pas de propriété de paramètre) : Node.js
// l'exécute directement.

import { createHash, createPublicKey, verify } from "node:crypto";

export const FORMAT_MANIFESTE = "frisk-preuve-version-1";
export const FORMAT_FICHIER = "frisk-preuve-fichier-1";
export const FORMAT_LISTE_CLES = "frisk-cles-preuve-1";
export const FORMAT_ENTREE = "frisk-registre-versions-1";
// Séparation de domaine (spécification, point 3) : préfixe ASCII puis un octet nul.
export const PREFIXE_SIGNATURE = "FRISK-PREUVE-VERSION-1";

export type Resultat = "conforme" | "non_conforme" | "cle_non_approuvee" | "verification_impossible";

export type Verdict = {
  resultat: Resultat;
  motif: string | null;
  compteRendu: string[];
};

export type Manifeste = {
  format: string;
  entreprise: string;
  numero: number;
  version_creee_le: string;
  format_entree: string;
  algorithme_empreinte: string;
  empreinte_instantane: string;
  empreinte_entree: string;
  empreinte_precedente: string | null;
  pdf: { algorithme: string; empreinte: string; octets: number } | null;
  cle: string;
  preuve_creee_le: string;
};

export type ClePreuve = {
  identifiant: string;
  algorithme: string;
  cle_publique: string;
  debut: string;
  fin: string | null;
  revocation: { le: string; motif: string } | null;
};

export type ListeCles = { format: string; cles: ClePreuve[] };

// Champs d'une entrée du registre des versions, dans l'ordre du format frisk-registre-versions-1, avec
// les types et contraintes de la base de Frisk Plateforme, contrôlés par entreeBienFormee.
export type EntreeRegistre = {
  entreprise_id: string; // uuid, non nul
  numero: number; // integer, non nul, ≥ 1
  created_at: string; // déjà au format AAAA-MM-JJTHH:MM:SS.uuuuuuZ, tel que la base l'écrit
  created_by: string | null; // uuid, ou nul (compte supprimé)
  auteur_email_hmac: string; // 64 hexadécimaux (contrainte versions_auteur_email_hmac)
  auteur_email_hmac_version: number; // ≥ 1 (même contrainte)
  auteur_role: string | null; // texte, sans contrainte
  requete: string | null; // uuid, ou nul
  motif: string; // texte, non nul
  auteur: string; // texte, non nul (vide par défaut)
  empreinte_instantane: string; // 64 hexadécimaux (contrainte versions_registre_complet)
  empreinte_precedente: string | null; // 64 hexadécimaux, ou nul s'il n'y a pas d'entrée précédente
};

export type ElementsFournis = {
  instantane?: string | Uint8Array; // texte canonique de l'instantané, tel qu'enregistré
  entree?: EntreeRegistre;
  pdf?: Uint8Array;
};

// ---------------------------------------------------------------------------------------------------
// Écriture RFC 8785 (JSON Canonicalization Scheme)
// ---------------------------------------------------------------------------------------------------

// Mêmes refus que l'écriture de Frisk Plateforme (tests/canonique.ts) : U+0000, impossible à stocker dans PostgreSQL, et
// demi-codet UTF-16 isolé, interdit par RFC 8785 (§ 3.2.2.2).
const DEMI_CODET_ISOLE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
function texteValide(t: string) {
  return !t.includes("\u0000") && !DEMI_CODET_ISOLE.test(t);
}

function chaineRfc8785(t: string) {
  if (!texteValide(t)) throw new Error("chaine_invalide");
  return JSON.stringify(t);
}

export function texteCanoniqueRfc8785(v: unknown): string {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") return chaineRfc8785(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("nombre_non_fini");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(texteCanoniqueRfc8785).join(",")}]`;
  if (typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    const o = v as Record<string, unknown>;
    // Tri par unités de code UTF-16 : tri par défaut de Array.prototype.sort.
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${chaineRfc8785(k)}:${texteCanoniqueRfc8785(o[k])}`)
      .join(",")}}`;
  }
  throw new Error("valeur_non_json");
}

// ---------------------------------------------------------------------------------------------------
// Contrôles de forme
// ---------------------------------------------------------------------------------------------------

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const IDENTIFIANT_CLE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DATE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.\d{6}Z$/;

function estObjetSimple(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function clesExactes(o: Record<string, unknown>, attendues: string[]) {
  const presentes = Object.keys(o).sort();
  const voulues = [...attendues].sort();
  return presentes.length === voulues.length && presentes.every((k, i) => k === voulues[i]);
}

// Date au format de la spécification, et date réelle (pas de 31 février).
function estDate(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const m = DATE.exec(v);
  if (!m) return false;
  const [, a, mo, j, h, mi, s] = m.map(Number);
  const d = new Date(Date.UTC(a, mo - 1, j, h, mi, s));
  return d.getUTCFullYear() === a && d.getUTCMonth() === mo - 1 && d.getUTCDate() === j && h < 24 && mi < 60 && s < 60;
}

function estEntierPositif(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
}

// Colonne integer de PostgreSQL : au plus 2 147 483 647.
function estEntierInt4(v: unknown): v is number {
  return estEntierPositif(v) && v <= 2147483647;
}

const CHAMPS_MANIFESTE = [
  "format",
  "entreprise",
  "numero",
  "version_creee_le",
  "format_entree",
  "algorithme_empreinte",
  "empreinte_instantane",
  "empreinte_entree",
  "empreinte_precedente",
  "pdf",
  "cle",
  "preuve_creee_le",
];

// Renvoie le nom du premier champ invalide, ou null si le manifeste est bien formé.
export function champInvalideManifeste(m: unknown): string | null {
  if (!estObjetSimple(m)) return "manifeste";
  if (!clesExactes(m, CHAMPS_MANIFESTE)) return "liste_des_champs";
  if (m.format !== FORMAT_MANIFESTE) return "format";
  if (typeof m.entreprise !== "string" || !UUID.test(m.entreprise)) return "entreprise";
  if (!estEntierPositif(m.numero)) return "numero";
  if (!estDate(m.version_creee_le)) return "version_creee_le";
  if (m.format_entree !== FORMAT_ENTREE) return "format_entree";
  if (m.algorithme_empreinte !== "sha-256") return "algorithme_empreinte";
  if (typeof m.empreinte_instantane !== "string" || !HEX64.test(m.empreinte_instantane)) return "empreinte_instantane";
  if (typeof m.empreinte_entree !== "string" || !HEX64.test(m.empreinte_entree)) return "empreinte_entree";
  // Nulle pour la version 1. Au-delà : l'empreinte de l'entrée précédente, ou nulle si la version
  // précédente a été figée avant le registre (migration 029) et n'a donc pas d'empreinte.
  const precedente = m.empreinte_precedente;
  if (m.numero === 1 ? precedente !== null : precedente !== null && (typeof precedente !== "string" || !HEX64.test(precedente)))
    return "empreinte_precedente";
  if (m.pdf !== null) {
    const p = m.pdf;
    if (!estObjetSimple(p) || !clesExactes(p, ["algorithme", "empreinte", "octets"])) return "pdf";
    if (p.algorithme !== "sha-256" || typeof p.empreinte !== "string" || !HEX64.test(p.empreinte) || !estEntierPositif(p.octets))
      return "pdf";
  }
  if (typeof m.cle !== "string" || !IDENTIFIANT_CLE.test(m.cle)) return "cle";
  if (!estDate(m.preuve_creee_le)) return "preuve_creee_le";
  return null;
}

export function listeClesValide(l: unknown): l is ListeCles {
  if (!estObjetSimple(l) || !clesExactes(l, ["format", "cles"]) || l.format !== FORMAT_LISTE_CLES || !Array.isArray(l.cles)) return false;
  const vus = new Set<string>();
  for (const c of l.cles) {
    if (!estObjetSimple(c) || !clesExactes(c, ["identifiant", "algorithme", "cle_publique", "debut", "fin", "revocation"])) return false;
    if (typeof c.identifiant !== "string" || !IDENTIFIANT_CLE.test(c.identifiant) || vus.has(c.identifiant)) return false;
    vus.add(c.identifiant);
    if (c.algorithme !== "ed25519" || typeof c.cle_publique !== "string" || !HEX64.test(c.cle_publique)) return false;
    if (!estDate(c.debut) || (c.fin !== null && (!estDate(c.fin) || c.fin < c.debut))) return false;
    if (c.revocation !== null) {
      const r = c.revocation;
      if (!estObjetSimple(r) || !clesExactes(r, ["le", "motif"]) || !estDate(r.le) || typeof r.motif !== "string" || !r.motif.trim()) return false;
    }
  }
  return true;
}

const CHAMPS_ENTREE = [
  "entreprise_id",
  "numero",
  "created_at",
  "created_by",
  "auteur_email_hmac",
  "auteur_email_hmac_version",
  "auteur_role",
  "requete",
  "motif",
  "auteur",
  "empreinte_instantane",
  "empreinte_precedente",
];

// Une entrée fournie (souvent lue dans un fichier) doit avoir exactement les champs du format.
export function entreeBienFormee(e: unknown): e is EntreeRegistre {
  if (!estObjetSimple(e) || !clesExactes(e, CHAMPS_ENTREE)) return false;
  const uuidOuNul = (v: unknown) => v === null || (typeof v === "string" && UUID.test(v));
  const texte = (v: unknown) => typeof v === "string" && texteValide(v);
  return (
    typeof e.entreprise_id === "string" &&
    UUID.test(e.entreprise_id) &&
    estEntierInt4(e.numero) &&
    estDate(e.created_at) &&
    uuidOuNul(e.created_by) &&
    typeof e.auteur_email_hmac === "string" &&
    HEX64.test(e.auteur_email_hmac) &&
    estEntierInt4(e.auteur_email_hmac_version) &&
    (e.auteur_role === null || texte(e.auteur_role)) &&
    uuidOuNul(e.requete) &&
    texte(e.motif) &&
    texte(e.auteur) &&
    typeof e.empreinte_instantane === "string" &&
    HEX64.test(e.empreinte_instantane) &&
    (e.empreinte_precedente === null || (typeof e.empreinte_precedente === "string" && HEX64.test(e.empreinte_precedente)))
  );
}

// ---------------------------------------------------------------------------------------------------
// Empreintes
// ---------------------------------------------------------------------------------------------------

const sha256 = (octets: Uint8Array | string) => createHash("sha256").update(octets).digest("hex");

// Codage d'un champ de l'empreinte d'entrée B1a (public.champ_registre) : longueur sur 4 octets
// (gros-boutiste) puis les octets UTF-8 ; une valeur absente s'écrit ff ff ff ff.
function champRegistre(t: string | null): Buffer {
  if (t === null) return Buffer.from([0xff, 0xff, 0xff, 0xff]);
  const octets = Buffer.from(t, "utf8");
  const longueur = Buffer.alloc(4);
  longueur.writeInt32BE(octets.length);
  return Buffer.concat([longueur, octets]);
}

// Le calcul accepte des champs nuls (comme la fonction SQL), pour pouvoir être comparé à la base sur
// tous les cas ; le contrôle de forme d'une entrée fournie est fait par entreeBienFormee.
export function empreinteEntree(e: { [K in keyof EntreeRegistre]: EntreeRegistre[K] | null }): string {
  const texte = (n: number | null) => (n === null ? null : String(n));
  return sha256(
    Buffer.concat([
      champRegistre(FORMAT_ENTREE),
      champRegistre(e.entreprise_id),
      champRegistre(texte(e.numero)),
      champRegistre(e.created_at),
      champRegistre(e.created_by),
      champRegistre(e.auteur_email_hmac),
      champRegistre(texte(e.auteur_email_hmac_version)),
      champRegistre(e.auteur_role),
      champRegistre(e.requete),
      champRegistre(e.motif),
      champRegistre(e.auteur),
      champRegistre(e.empreinte_instantane),
      champRegistre(e.empreinte_precedente),
    ]),
  );
}

export function octetsSignes(manifesteTexte: string): Buffer {
  return Buffer.concat([Buffer.from(PREFIXE_SIGNATURE, "ascii"), Buffer.from([0]), Buffer.from(manifesteTexte, "utf8")]);
}

function signatureValide(manifesteTexte: string, signatureHex: string, clePubliqueHex: string) {
  try {
    const cle = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(clePubliqueHex, "hex").toString("base64url") },
      format: "jwk",
    });
    return verify(null, octetsSignes(manifesteTexte), cle, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------
// Vérification
// ---------------------------------------------------------------------------------------------------

export function verifierPreuve(fichier: unknown, liste: unknown, elements: ElementsFournis = {}): Verdict {
  const compteRendu: string[] = [];
  const fin = (resultat: Resultat, motif: string | null): Verdict => {
    compteRendu.push(`Résultat : ${LIBELLES[resultat]}${motif ? ` (${motif})` : ""}`);
    return { resultat, motif, compteRendu };
  };

  // 1. Forme du fichier, de la liste de confiance et du manifeste.
  let f: unknown = fichier;
  if (typeof f === "string") {
    try {
      f = JSON.parse(f);
    } catch {
      return fin("verification_impossible", "fichier_illisible");
    }
  }
  if (!estObjetSimple(f) || !clesExactes(f, ["format", "manifeste", "signature"]) || f.format !== FORMAT_FICHIER)
    return fin("verification_impossible", "fichier_mal_forme");
  if (typeof f.manifeste !== "string") return fin("verification_impossible", "fichier_mal_forme");
  if (typeof f.signature !== "string" || !HEX128.test(f.signature)) return fin("verification_impossible", "signature_mal_formee");
  if (!listeClesValide(liste)) return fin("verification_impossible", "liste_de_cles_invalide");
  const manifesteTexte = f.manifeste;
  let manifeste: unknown;
  try {
    manifeste = JSON.parse(manifesteTexte);
  } catch {
    return fin("verification_impossible", "manifeste_illisible");
  }
  const invalide = champInvalideManifeste(manifeste);
  if (invalide) return fin("verification_impossible", `manifeste_invalide:${invalide}`);
  const m = manifeste as Manifeste;
  if (elements.entree !== undefined && !entreeBienFormee(elements.entree)) return fin("verification_impossible", "entree_mal_formee");
  compteRendu.push(`Version : entreprise ${m.entreprise}, numéro ${m.numero}`);

  // 2. La clé est-elle dans la liste de confiance ?
  const cle = liste.cles.find((c) => c.identifiant === m.cle);
  if (!cle) {
    compteRendu.push(`Clé : ${m.cle}, absente de la liste de confiance fournie`);
    return fin("cle_non_approuvee", "cle_absente");
  }

  // 3. Signature sur le préfixe et les octets exacts du manifeste.
  if (!signatureValide(manifesteTexte, f.signature, cle.cle_publique)) {
    compteRendu.push("Signature : invalide");
    return fin("non_conforme", "signature_invalide");
  }
  compteRendu.push("Signature : valide");

  // 4. Le manifeste est-il canonique ?
  let canonique: string | null;
  try {
    canonique = texteCanoniqueRfc8785(manifeste);
  } catch {
    canonique = null;
  }
  if (canonique !== manifesteTexte) {
    compteRendu.push("Manifeste : non canonique");
    return fin("non_conforme", "manifeste_non_canonique");
  }
  compteRendu.push("Manifeste : canonique");

  // 5. Révocation : sans exception de date, tant qu'il n'y a pas d'horodatage par un tiers.
  if (cle.revocation) {
    compteRendu.push(`Clé : ${cle.identifiant}, révoquée le ${cle.revocation.le} (${cle.revocation.motif})`);
    return fin("cle_non_approuvee", "cle_revoquee");
  }

  // 6. Période d'utilisation de la clé (bornes comprises). Les dates ont toutes le même format :
  // l'ordre alphabétique est l'ordre chronologique.
  if (m.preuve_creee_le < cle.debut || (cle.fin !== null && m.preuve_creee_le > cle.fin)) {
    compteRendu.push(`Clé : ${cle.identifiant}, preuve datée du ${m.preuve_creee_le} hors de sa période (date déclarative)`);
    return fin("cle_non_approuvee", "cle_hors_periode");
  }
  compteRendu.push(`Clé : ${cle.identifiant}, approuvée, non révoquée selon la liste fournie`);

  // 7. Éléments fournis : empreintes recalculées.
  if (elements.instantane === undefined) compteRendu.push("Instantané : non fourni, empreinte non recalculée");
  else if (sha256(elements.instantane) !== m.empreinte_instantane) {
    compteRendu.push("Instantané : empreinte différente de celle du manifeste");
    return fin("non_conforme", "instantane_different");
  } else compteRendu.push("Instantané : empreinte recalculée, identique");

  if (elements.entree === undefined) compteRendu.push("Entrée du registre : non fournie, empreinte non recalculée");
  else {
    const e = elements.entree;
    const memeVersion =
      e.entreprise_id === m.entreprise &&
      e.numero === m.numero &&
      e.created_at === m.version_creee_le &&
      e.empreinte_instantane === m.empreinte_instantane &&
      e.empreinte_precedente === m.empreinte_precedente;
    if (!memeVersion || empreinteEntree(e) !== m.empreinte_entree) {
      compteRendu.push("Entrée du registre : différente de celle du manifeste");
      return fin("non_conforme", "entree_differente");
    }
    compteRendu.push("Entrée du registre : empreinte recalculée, identique");
  }

  if (elements.pdf === undefined) compteRendu.push(m.pdf ? "PDF : non fourni, empreinte non recalculée" : "PDF : aucun PDF dans cette preuve");
  else if (!m.pdf) {
    compteRendu.push("PDF : fourni, mais cette preuve ne couvre aucun PDF");
    return fin("non_conforme", "pdf_non_couvert");
  } else if (elements.pdf.length !== m.pdf.octets || sha256(elements.pdf) !== m.pdf.empreinte) {
    compteRendu.push("PDF : différent de celui du manifeste");
    return fin("non_conforme", "pdf_different");
  } else compteRendu.push("PDF : empreinte recalculée, identique");

  compteRendu.push(`Date : ${m.preuve_creee_le}, déclarative, non horodatée`);
  return fin("conforme", null);
}

const LIBELLES: Record<Resultat, string> = {
  conforme: "conforme (aux contrôles réellement faits et à la liste de confiance fournie)",
  non_conforme: "non conforme",
  cle_non_approuvee: "clé non approuvée",
  verification_impossible: "vérification impossible",
};
