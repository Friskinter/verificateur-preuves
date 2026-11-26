// Registre des versions du document unique : texte canonique d'un instantané selon RFC 8785 (JSON
// Canonicalization Scheme). RFC 8785 reprend l'écriture des nombres et des chaînes d'ECMAScript
// (JSON.stringify) ; il reste le tri des propriétés par unités de code UTF-16 et la récursion.
//
// La canonicalisation se fait uniquement ici, côté serveur : PostgreSQL n'écrit pas toujours les
// nombres comme ECMAScript (prototype B1 : 1e+23 et environ 0,03 % des doubles). La base ne fait que
// vérifier : empreinte SHA-256 des octets reçus, et égalité exacte du texte relu avec l'instantané
// qu'elle reconstruit elle-même.

export class TexteNonCanonisable extends Error {
  constructor(public readonly code: string, chemin: string) {
    super(`${code} (${chemin || "racine"})`);
    this.name = "TexteNonCanonisable";
  }
}

// Demi-codet UTF-16 isolé : interdit par RFC 8785 (§ 3.2.2.2), illisible pour PostgreSQL. U+0000 :
// autorisé par RFC 8785 mais impossible à stocker dans PostgreSQL (jsonb et text) ; refusé ici pour que
// l'erreur soit claire plutôt que levée par la base.
const DEMI_CODET_ISOLE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function chaine(t: string, chemin: string) {
  if (t.includes("\u0000")) throw new TexteNonCanonisable("caractere_nul", chemin);
  if (DEMI_CODET_ISOLE.test(t)) throw new TexteNonCanonisable("demi_codet_isole", chemin);
  return JSON.stringify(t);
}

function ecrire(v: unknown, chemin: string): string {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") return chaine(v, chemin);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new TexteNonCanonisable("nombre_non_fini", chemin);
    return JSON.stringify(v); // -0 donne « 0 », comme le veut RFC 8785
  }
  if (Array.isArray(v)) return `[${v.map((x, i) => ecrire(x, `${chemin}[${i}]`)).join(",")}]`;
  if (typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    // Tri par défaut de Array.prototype.sort : unités de code UTF-16, exactement RFC 8785 § 3.2.3.
    const cles = Object.keys(v).sort();
    return `{${cles
      .map((k) => {
        const valeur = (v as Record<string, unknown>)[k];
        return `${chaine(k, chemin)}:${ecrire(valeur, `${chemin}.${k}`)}`;
      })
      .join(",")}}`;
  }
  // undefined, fonction, Date, Map… : pas une valeur JSON. Rien n'est ignoré en silence.
  throw new TexteNonCanonisable("valeur_non_json", chemin);
}

export function texteCanonique(valeur: unknown): string {
  return ecrire(valeur, "");
}

// Parties du contenu d'un espace figées dans une version (identiques à ce que reconstruit la fonction
// SQL figer_version). Une partie absente du contenu est absente de l'instantané.
export const PARTIES_INSTANTANE = ["entreprise", "fiche", "unites", "duerp", "actions"] as const;

export function instantaneDuContenu(contenu: Record<string, unknown>): Record<string, unknown> {
  const instantane: Record<string, unknown> = {};
  for (const partie of PARTIES_INSTANTANE) {
    if (Object.prototype.hasOwnProperty.call(contenu, partie)) instantane[partie] = contenu[partie];
  }
  return instantane;
}
