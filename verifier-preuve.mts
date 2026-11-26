// Vérifie une preuve signée d'une version du document unique, sans accès à la base (phase B2b).
// Utilisation (Node.js 24 ou plus récent, qui exécute ce fichier TypeScript directement) :
//
//   node verifier-preuve.mts <preuve.json> <cles.json> [--instantane <fichier>] [--entree <entree.json>] [--pdf <fichier.pdf>]
//
// <cles.json> est la liste des clés de confiance de Frisk (format frisk-cles-preuve-1), obtenue
// séparément de la preuve. Code de sortie : 0 si conforme, 1 sinon, 2 si la commande est mal écrite.

import { readFileSync } from "node:fs";
import { verifierPreuve, type ElementsFournis } from "./verificateur.ts";

const USAGE =
  "Utilisation : node verifier-preuve.mts <preuve.json> <cles.json> [--instantane <fichier>] [--entree <entree.json>] [--pdf <fichier.pdf>]";

function arreter(message: string): never {
  console.error(message);
  console.error(USAGE);
  process.exit(2);
}

const positionnels: string[] = [];
const options = new Map<string, string>();
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a.startsWith("--")) {
    if (!["--instantane", "--entree", "--pdf"].includes(a)) arreter(`Option inconnue : ${a}`);
    if (options.has(a)) arreter(`Option donnée deux fois : ${a}`);
    const valeur = args[++i];
    if (valeur === undefined) arreter(`Valeur manquante après ${a}`);
    options.set(a, valeur);
  } else positionnels.push(a);
}
if (positionnels.length !== 2) arreter("Il faut le fichier de preuve et la liste des clés.");

function lireJson(chemin: string, quoi: string): unknown {
  try {
    return JSON.parse(readFileSync(chemin, "utf8"));
  } catch {
    return arreter(`Lecture impossible ${quoi} : ${chemin}`);
  }
}
function lireOctets(chemin: string, quoi: string): Uint8Array {
  try {
    return new Uint8Array(readFileSync(chemin));
  } catch {
    return arreter(`Lecture impossible ${quoi} : ${chemin}`);
  }
}

// Le fichier de preuve est passé tel quel (texte) : le vérificateur le relit lui-même.
let preuve: string;
try {
  preuve = readFileSync(positionnels[0], "utf8");
} catch {
  arreter(`Lecture impossible de la preuve : ${positionnels[0]}`);
}
const cles = lireJson(positionnels[1], "de la liste des clés");
const elements: ElementsFournis = {};
const cheminInstantane = options.get("--instantane");
if (cheminInstantane) elements.instantane = lireOctets(cheminInstantane, "de l'instantané");
const cheminEntree = options.get("--entree");
if (cheminEntree) elements.entree = lireJson(cheminEntree, "de l'entrée") as ElementsFournis["entree"];
const cheminPdf = options.get("--pdf");
if (cheminPdf) elements.pdf = lireOctets(cheminPdf, "du PDF");

const verdict = verifierPreuve(preuve, cles, elements);
for (const ligne of verdict.compteRendu) console.log(ligne);
// exitCode plutôt que exit() : tout le compte rendu est écrit avant la fin, même redirigé.
process.exitCode = verdict.resultat === "conforme" ? 0 : 1;
