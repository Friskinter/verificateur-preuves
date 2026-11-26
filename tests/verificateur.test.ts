import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { texteCanonique } from "./canonique.ts";
import {
  empreinteEntree,
  octetsSignes,
  texteCanoniqueRfc8785,
  verifierPreuve,
  type ClePreuve,
  type EntreeRegistre,
  type Manifeste,
} from "../verificateur.ts";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Uniquement des clés de test créées ici : aucune clé privée réelle de Frisk ne doit jamais apparaître
// dans un test.

const sha256 = (v: string | Uint8Array) => createHash("sha256").update(v).digest("hex");

function paire() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x as string;
  return { privee: privateKey, publique: Buffer.from(x, "base64url").toString("hex") };
}

const k1 = paire();
const k2 = paire();

function cle(identifiant: string, publique: string, autres: Partial<ClePreuve> = {}): ClePreuve {
  return { identifiant, algorithme: "ed25519", cle_publique: publique, debut: "2026-01-01T00:00:00.000000Z", fin: null, revocation: null, ...autres };
}
const liste = (...cles: ClePreuve[]) => ({ format: "frisk-cles-preuve-1", cles });
const listeK1 = liste(cle("frisk-preuve-ed25519-v1", k1.publique));

// Une version 2 cohérente : instantané, entrée et PDF de démonstration.
const instantane = texteCanonique({ entreprise: { nom: "Démo Frisk" }, duerp: { risques: [{ id: "r1", gravite: 3 }] } });
const pdf = new Uint8Array(Buffer.from("%PDF-1.7 document de démonstration"));
const entree: EntreeRegistre = {
  entreprise_id: "20000000-0000-0000-0000-0000000000b2",
  numero: 2,
  created_at: "2026-11-24T10:15:30.123456Z", // microsecondes non nulles
  created_by: "30000000-0000-0000-0000-0000000000b2",
  auteur_email_hmac: "a".repeat(64),
  auteur_email_hmac_version: 1,
  auteur_role: "responsable",
  requete: "40000000-0000-0000-0000-0000000000b2",
  motif: "Mise à jour annuelle",
  auteur: "Responsable prévention",
  empreinte_instantane: sha256(instantane),
  empreinte_precedente: "b".repeat(64),
};

function manifeste(autres: Partial<Manifeste> = {}): Manifeste {
  return {
    format: "frisk-preuve-version-1",
    entreprise: entree.entreprise_id,
    numero: entree.numero,
    version_creee_le: entree.created_at,
    format_entree: "frisk-registre-versions-1",
    algorithme_empreinte: "sha-256",
    empreinte_instantane: entree.empreinte_instantane!,
    empreinte_entree: empreinteEntree(entree),
    empreinte_precedente: entree.empreinte_precedente,
    pdf: { algorithme: "sha-256", empreinte: sha256(pdf), octets: pdf.length },
    cle: "frisk-preuve-ed25519-v1",
    preuve_creee_le: "2026-11-24T10:16:00.000000Z",
    ...autres,
  };
}

// Signataire de test seulement : la vraie signature sera faite par le serveur en B2c.
function preuve(m: unknown, privee: KeyObject = k1.privee, texte = texteCanoniqueRfc8785(m)) {
  return { format: "frisk-preuve-fichier-1", manifeste: texte, signature: sign(null, octetsSignes(texte), privee).toString("hex") };
}

describe("vérificateur de preuves : résultat conforme", () => {
  it("preuve seule : conforme, et le compte rendu dit ce qui n'a pas été vérifié", () => {
    const v = verifierPreuve(preuve(manifeste()), listeK1);
    expect(v.resultat).toBe("conforme");
    expect(v.motif).toBeNull();
    expect(v.compteRendu).toEqual([
      "Version : entreprise 20000000-0000-0000-0000-0000000000b2, numéro 2",
      "Signature : valide",
      "Manifeste : canonique",
      "Clé : frisk-preuve-ed25519-v1, approuvée, non révoquée selon la liste fournie",
      "Instantané : non fourni, empreinte non recalculée",
      "Entrée du registre : non fournie, empreinte non recalculée",
      "PDF : non fourni, empreinte non recalculée",
      "Date : 2026-11-24T10:16:00.000000Z, déclarative, non horodatée",
      "Résultat : conforme (aux contrôles réellement faits et à la liste de confiance fournie)",
    ]);
  });

  it("avec l'instantané, l'entrée et le PDF : tout est recalculé", () => {
    const v = verifierPreuve(JSON.stringify(preuve(manifeste())), listeK1, { instantane, entree, pdf });
    expect(v.resultat).toBe("conforme");
    expect(v.compteRendu).toContain("Instantané : empreinte recalculée, identique");
    expect(v.compteRendu).toContain("Entrée du registre : empreinte recalculée, identique");
    expect(v.compteRendu).toContain("PDF : empreinte recalculée, identique");
  });

  it("première version de l'entreprise : empreinte précédente nulle, sans PDF", () => {
    const e1 = { ...entree, numero: 1, empreinte_precedente: null };
    const m = manifeste({ numero: 1, empreinte_precedente: null, empreinte_entree: empreinteEntree(e1), pdf: null });
    const v = verifierPreuve(preuve(m), listeK1, { entree: e1 });
    expect(v.resultat).toBe("conforme");
    expect(v.compteRendu).toContain("PDF : aucun PDF dans cette preuve");
  });

  it("rotation : une ancienne preuve reste vérifiable avec l'ancienne clé, la nouvelle clé signe", () => {
    const apresRotation = liste(
      cle("frisk-preuve-ed25519-v1", k1.publique, { fin: "2026-12-31T23:59:59.999999Z" }),
      cle("frisk-preuve-ed25519-v2", k2.publique, { debut: "2027-01-01T00:00:00.000000Z" }),
    );
    expect(verifierPreuve(preuve(manifeste()), apresRotation).resultat).toBe("conforme");
    const nouvelle = manifeste({ cle: "frisk-preuve-ed25519-v2", preuve_creee_le: "2027-02-01T08:00:00.000000Z" });
    expect(verifierPreuve(preuve(nouvelle, k2.privee), apresRotation).resultat).toBe("conforme");
  });
});

describe("vérificateur de preuves : non conforme", () => {
  it("signature modifiée d'un seul caractère", () => {
    const p = preuve(manifeste());
    p.signature = (p.signature[0] === "0" ? "1" : "0") + p.signature.slice(1);
    expect(verifierPreuve(p, listeK1)).toMatchObject({ resultat: "non_conforme", motif: "signature_invalide" });
  });

  it("manifeste modifié après signature (une empreinte changée)", () => {
    const p = preuve(manifeste());
    p.manifeste = p.manifeste.replace(manifeste().empreinte_entree, "c".repeat(64));
    expect(verifierPreuve(p, listeK1)).toMatchObject({ resultat: "non_conforme", motif: "signature_invalide" });
  });

  it("signature faite sans le préfixe de domaine", () => {
    const texte = texteCanoniqueRfc8785(manifeste());
    const p = { format: "frisk-preuve-fichier-1", manifeste: texte, signature: sign(null, Buffer.from(texte, "utf8"), k1.privee).toString("hex") };
    expect(verifierPreuve(p, listeK1)).toMatchObject({ resultat: "non_conforme", motif: "signature_invalide" });
  });

  it("signée par une autre clé que celle annoncée", () => {
    expect(verifierPreuve(preuve(manifeste(), k2.privee), listeK1)).toMatchObject({ resultat: "non_conforme", motif: "signature_invalide" });
  });

  it("manifeste signé mais non canonique (espaces, ordre des champs)", () => {
    const m = manifeste();
    const p = preuve(m, k1.privee, JSON.stringify(m, null, 1));
    expect(verifierPreuve(p, listeK1)).toMatchObject({ resultat: "non_conforme", motif: "manifeste_non_canonique" });
  });

  it("instantané, entrée ou PDF différents de ceux du manifeste", () => {
    const p = preuve(manifeste());
    expect(verifierPreuve(p, listeK1, { instantane: instantane + " " }).motif).toBe("instantane_different");
    expect(verifierPreuve(p, listeK1, { entree: { ...entree, motif: "Autre motif" } }).motif).toBe("entree_differente");
    expect(verifierPreuve(p, listeK1, { entree: { ...entree, created_at: "2026-11-24T10:15:30.123000Z" } }).motif).toBe("entree_differente");
    const autrePdf = new Uint8Array(pdf);
    autrePdf[3] ^= 1;
    expect(verifierPreuve(p, listeK1, { pdf: autrePdf }).motif).toBe("pdf_different");
  });

  it("PDF fourni alors que la preuve n'en couvre aucun", () => {
    const v = verifierPreuve(preuve(manifeste({ pdf: null })), listeK1, { pdf });
    expect(v).toMatchObject({ resultat: "non_conforme", motif: "pdf_non_couvert" });
  });
});

describe("vérificateur de preuves : clé non approuvée", () => {
  it("clé absente de la liste", () => {
    expect(verifierPreuve(preuve(manifeste()), liste(cle("frisk-preuve-ed25519-v9", k2.publique)))).toMatchObject({
      resultat: "cle_non_approuvee",
      motif: "cle_absente",
    });
  });

  it("clé révoquée : refusée même si la preuve se dit antérieure à la révocation", () => {
    const revoquee = liste(cle("frisk-preuve-ed25519-v1", k1.publique, { revocation: { le: "2026-12-15T00:00:00.000000Z", motif: "fuite" } }));
    const v = verifierPreuve(preuve(manifeste({ preuve_creee_le: "2026-06-20T00:00:00.000000Z" })), revoquee);
    expect(v).toMatchObject({ resultat: "cle_non_approuvee", motif: "cle_revoquee" });
  });

  it("preuve datée avant le début ou après la fin d'utilisation de la clé", () => {
    const bornee = liste(cle("frisk-preuve-ed25519-v1", k1.publique, { debut: "2026-06-01T00:00:00.000000Z", fin: "2026-06-30T23:59:59.999999Z" }));
    expect(verifierPreuve(preuve(manifeste({ preuve_creee_le: "2026-05-31T23:59:59.999999Z" })), bornee).motif).toBe("cle_hors_periode");
    expect(verifierPreuve(preuve(manifeste({ preuve_creee_le: "2026-07-01T00:00:00.000000Z" })), bornee).motif).toBe("cle_hors_periode");
    expect(verifierPreuve(preuve(manifeste({ preuve_creee_le: "2026-06-30T23:59:59.999999Z" })), bornee).resultat).toBe("conforme");
  });
});

describe("vérificateur de preuves : vérification impossible", () => {
  const impossible = (fichier: unknown, l: unknown = listeK1) => verifierPreuve(fichier, l);

  it("fichier illisible ou mal formé", () => {
    expect(impossible("{pas du json").motif).toBe("fichier_illisible");
    expect(impossible({ ...preuve(manifeste()), format: "autre" }).motif).toBe("fichier_mal_forme");
    expect(impossible({ ...preuve(manifeste()), cle_publique: k1.publique }).motif).toBe("fichier_mal_forme");
    expect(impossible({ ...preuve(manifeste()), signature: "ABC" }).motif).toBe("signature_mal_formee");
    expect(impossible({ ...preuve(manifeste()), manifeste: "{" }).motif).toBe("manifeste_illisible");
  });

  it("manifeste : champ manquant, champ en trop, valeur mal formée", () => {
    const { pdf: _pdf, ...sansPdf } = manifeste();
    void _pdf;
    expect(impossible(preuve(sansPdf)).motif).toBe("manifeste_invalide:liste_des_champs");
    expect(impossible(preuve({ ...manifeste(), auteur: "x" })).motif).toBe("manifeste_invalide:liste_des_champs");
    expect(impossible(preuve(manifeste({ numero: 1 }))).motif).toBe("manifeste_invalide:empreinte_precedente");
    expect(impossible(preuve(manifeste({ numero: 2.5 }))).motif).toBe("manifeste_invalide:numero");
    expect(impossible(preuve(manifeste({ entreprise: entree.entreprise_id.toUpperCase() }))).motif).toBe("manifeste_invalide:entreprise");
    expect(impossible(preuve(manifeste({ version_creee_le: "2026-11-24T10:15:30.123Z" }))).motif).toBe("manifeste_invalide:version_creee_le");
    expect(impossible(preuve(manifeste({ preuve_creee_le: "2026-02-30T00:00:00.000000Z" }))).motif).toBe("manifeste_invalide:preuve_creee_le");
    expect(impossible(preuve(manifeste({ pdf: { algorithme: "md5", empreinte: "0".repeat(64), octets: 1 } }))).motif).toBe("manifeste_invalide:pdf");
  });

  it("entrée du registre fournie mais mal formée", () => {
    const { motif: _motif, ...incomplete } = entree;
    void _motif;
    const v = verifierPreuve(preuve(manifeste()), listeK1, { entree: incomplete as unknown as EntreeRegistre });
    expect(v).toMatchObject({ resultat: "verification_impossible", motif: "entree_mal_formee" });
  });

  it("entrée du registre : contraintes des colonnes de la migration 029", () => {
    const p = preuve(manifeste());
    const malFormee = (autres: Record<string, unknown>) =>
      verifierPreuve(p, listeK1, { entree: { ...entree, ...autres } as EntreeRegistre }).motif;
    expect(malFormee({ auteur_email_hmac: "A".repeat(64) })).toBe("entree_mal_formee");
    expect(malFormee({ auteur_email_hmac: null })).toBe("entree_mal_formee");
    expect(malFormee({ auteur_email_hmac_version: 0 })).toBe("entree_mal_formee");
    expect(malFormee({ created_at: "2026-11-24T10:15:30.123Z" })).toBe("entree_mal_formee");
    expect(malFormee({ created_by: "pas-un-uuid" })).toBe("entree_mal_formee");
    expect(malFormee({ requete: "pas-un-uuid" })).toBe("entree_mal_formee");
    expect(malFormee({ motif: null })).toBe("entree_mal_formee");
    expect(malFormee({ auteur: "a\u0000b" })).toBe("entree_mal_formee");
    expect(malFormee({ numero: 2147483648 })).toBe("entree_mal_formee");
    expect(malFormee({ empreinte_instantane: null })).toBe("entree_mal_formee");
    // Valeurs nulles permises par le schéma : compte supprimé, demande sans identifiant.
    const e = { ...entree, created_by: null, requete: null };
    const m = manifeste({ empreinte_entree: empreinteEntree(e) });
    expect(verifierPreuve(preuve(m), listeK1, { entree: e }).resultat).toBe("conforme");
  });

  it("version 2 sans empreinte précédente (version 1 figée avant le registre) : admise", () => {
    expect(verifierPreuve(preuve(manifeste({ empreinte_precedente: null })), listeK1).resultat).toBe("conforme");
  });

  it("liste de confiance invalide : identifiant en double, clé publique mal formée", () => {
    const p = preuve(manifeste());
    expect(impossible(p, liste(cle("frisk-preuve-ed25519-v1", k1.publique), cle("frisk-preuve-ed25519-v1", k2.publique))).motif).toBe(
      "liste_de_cles_invalide",
    );
    expect(impossible(p, liste(cle("frisk-preuve-ed25519-v1", "zz"))).motif).toBe("liste_de_cles_invalide");
    expect(impossible(p, { format: "frisk-cles-preuve-1" }).motif).toBe("liste_de_cles_invalide");
  });
});

describe("écritures indépendantes", () => {
  it("l'écriture RFC 8785 du vérificateur est celle de B1a (tests/canonique.ts)", () => {
    const exemples: unknown[] = [
      manifeste(),
      { b: 1, a: [true, null, "é", 1e21, 0.1, -0], "€": { z: " ", y: "\"\\" }, "é": 2, e: "😀" },
      { "😀": 1, "ﬁ": 2, A: 3, a: 4 },
    ];
    for (const e of exemples) expect(texteCanoniqueRfc8785(e)).toBe(texteCanonique(e));
  });

  it("mêmes refus que B1a : U+0000 et demi-codet isolé", () => {
    for (const t of ["a\u0000b", "\ud800", "x\udc00"]) {
      expect(() => texteCanonique({ t })).toThrow();
      expect(() => texteCanoniqueRfc8785({ t })).toThrow();
      expect(() => texteCanoniqueRfc8785({ [t]: 1 })).toThrow();
    }
  });

  it("empreinte d'entrée : vecteur fixe, identique à celui de la fonction SQL (test 33)", () => {
    // Même calcul que public.empreinte_entree_version ; le test SQL 33 vérifie la même valeur côté base.
    expect(empreinteEntree(VECTEUR_ENTREE)).toBe(EMPREINTE_VECTEUR);
  });
});

const VECTEUR_ENTREE: Parameters<typeof empreinteEntree>[0] = {
  entreprise_id: "20000000-0000-0000-0000-0000000000b2",
  numero: 2,
  created_at: "2026-11-24T10:15:30.123456Z",
  created_by: "30000000-0000-0000-0000-0000000000b2",
  auteur_email_hmac: "a".repeat(64),
  auteur_email_hmac_version: 1,
  auteur_role: "responsable",
  requete: null,
  motif: "Mise à jour annuelle — été",
  auteur: null,
  empreinte_instantane: "c".repeat(64),
  empreinte_precedente: "b".repeat(64),
};
const EMPREINTE_VECTEUR = "8528160c6124aba13e375513746f91df07d8b9f8ef5a9663878fcb439c0a8639";

describe("outil en ligne de commande (verifier-preuve.mts)", () => {
  it("conforme : code 0 et compte rendu ; PDF modifié : code 1 ; commande incomplète : code 2", () => {
    const dossier = mkdtempSync(join(tmpdir(), "frisk-preuve-"));
    try {
      const ecrire = (nom: string, contenu: string | Uint8Array) => {
        writeFileSync(join(dossier, nom), contenu);
        return join(dossier, nom);
      };
      const fPreuve = ecrire("preuve.json", JSON.stringify(preuve(manifeste())));
      const fCles = ecrire("cles.json", JSON.stringify(listeK1));
      const fEntree = ecrire("entree.json", JSON.stringify(entree));
      const fInstantane = ecrire("instantane.json", instantane);
      const fPdf = ecrire("doc.pdf", pdf);
      const fAutre = ecrire("autre.pdf", Buffer.from("%PDF autre"));
      const lancer = (...a: string[]) =>
        spawnSync(process.execPath, ["--no-warnings", "verifier-preuve.mts", ...a], { encoding: "utf8" });

      const ok = lancer(fPreuve, fCles, "--instantane", fInstantane, "--entree", fEntree, "--pdf", fPdf);
      expect(ok.status).toBe(0);
      expect(ok.stdout).toContain("Résultat : conforme");
      expect(ok.stdout).toContain("Entrée du registre : empreinte recalculée, identique");

      const ko = lancer(fPreuve, fCles, "--pdf", fAutre);
      expect(ko.status).toBe(1);
      expect(ko.stdout).toContain("Résultat : non conforme (pdf_different)");

      expect(lancer(fPreuve).status).toBe(2);
    } finally {
      rmSync(dossier, { recursive: true, force: true });
    }
  });
});
