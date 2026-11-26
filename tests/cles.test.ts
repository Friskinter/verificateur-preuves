import { createPublicKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import liste from "../cles-preuve-frisk.json";
import { listeClesValide } from "../verificateur.ts";

// Liste des clés de confiance de Frisk  : bien formée, et chaque clé
// publique est une vraie clé Ed25519. Une clé n'est jamais retirée de la liste (les anciennes preuves en
// dépendent) : on la révoque ou on lui donne une date de fin.
describe("liste des clés de confiance", () => {
  it("est bien formée", () => {
    expect(listeClesValide(liste)).toBe(true);
  });

  it("chaque clé publique est une clé Ed25519 lisible", () => {
    for (const c of liste.cles) {
      const cle = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(c.cle_publique, "hex").toString("base64url") }, format: "jwk" });
      expect(cle.asymmetricKeyType).toBe("ed25519");
    }
  });

  it("contient la première clé de Frisk, exactement, active", () => {
    // Valeurs exactes : une modification accidentelle de la clé publique ou de sa date ferait échouer ce test.
    expect(liste.cles.find((c) => c.identifiant === "frisk-preuve-ed25519-v1")).toEqual({
      identifiant: "frisk-preuve-ed25519-v1",
      algorithme: "ed25519",
      cle_publique: "807bd51e1b8fc81b5213013d5e2b7257cd85eb96b34788b5d0b3b083836be802",
      debut: "2026-11-24T21:59:39.479000Z",
      fin: null,
      revocation: null,
    });
  });
});
