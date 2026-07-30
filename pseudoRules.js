/**
 * pseudoRules.js — Règles de validation et normalisation des pseudos
 * Utilisé côté serveur ET exporté pour le client
 */

// ── Mots réservés interdits ────────────────────────────────────────────────
const RESERVED = [
    'admin', 'moderator', 'mod', 'system', 'chaltet', 'chatlet',
    'root', 'support', 'staff', 'bot', 'robot', 'official',
    'null', 'undefined', 'anonymous', 'guest', 'deleted'
];

// ── Homoglyphes utilisés uniquement pour comparaison d'unicité ─────────────
const HOMOGLYPH_MAP = {
    // lettres ressemblantes
    'o': '0',
    'O': '0',
    'о': '0',
    'О': '0',

    'l': '1',
    'L': '1',
    'I': '1',
    'i': '1',
    '|': '1',

    // cyrillique
    'а': 'a',
    'А': 'a',
    'е': 'e',
    'Е': 'e',
    'р': 'p',
    'Р': 'p',
    'с': 'c',
    'С': 'c',
    'х': 'x',
    'Х': 'x',
    'у': 'y',
    'У': 'y',

    // grec
    'α': 'a',
    'Α': 'a',
    'ο': '0',
    'Ο': '0',
    'ρ': 'p',
    'Ρ': 'p'
};


// ── Normalisation pour comparaison unique ─────────────────────────────────
function normalizePseudo(pseudo) {
    return pseudo
        .normalize('NFKC')
        .toLowerCase()
        .split('')
        .map(c => HOMOGLYPH_MAP[c] || c)
        .join('')
        .replace(/\s+/g, '');
}


// ── Zalgo / caractères combinants ─────────────────────────────────────────
function hasZalgo(str) {
    return /[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]/u.test(str);
}


// ── Invisibles / caractères dangereux ─────────────────────────────────────
function hasInvisible(str) {
    return /[\u0000-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060\u2066-\u206F\uFEFF]/u.test(str);
}


// ── XSS HTML ──────────────────────────────────────────────────────────────
function hasXSS(str) {
    return /<\s*\/?\s*(script|img|iframe|svg|object|style|link|meta)|on\w+\s*=|javascript\s*:|data\s*:/i.test(str);
}


// ── Répétition excessive ──────────────────────────────────────────────────
function hasExcessiveRepeat(str) {
    return /(.)\1{5,}/u.test(str);
}


// ── Validation pseudo ─────────────────────────────────────────────────────
function validatePseudo(pseudo) {

    if (!pseudo || typeof pseudo !== 'string') {
        return 'Pseudo invalide.';
    }

    pseudo = pseudo.trim();

    if (pseudo.length < 1) {
        return 'Le pseudo doit faire au moins 1 caractère.';
    }

    if (hasInvisible(pseudo)) {
        return 'Le pseudo contient des caractères invisibles.';
    }

    if (hasZalgo(pseudo)) {
        return 'Le pseudo contient une écriture non autorisée.';
    }

    if (hasXSS(pseudo)) {
        return 'Le pseudo contient des caractères interdits.';
    }

    if (pseudo.length > 20) {
        return 'Le pseudo ne doit pas dépasser 20 caractères.';
    }


    if (hasExcessiveRepeat(pseudo)) {
        return 'Le pseudo contient trop de caractères répétés.';
    }


    const norm = normalizePseudo(pseudo);

    if (!norm || norm.length < 1) {
        return 'Pseudo invalide.';
    }


    for (const reserved of RESERVED) {
        if (norm === normalizePseudo(reserved)) {
            return `Le pseudo "${pseudo}" est réservé.`;
        }
    }

    return null;
}


// ── Validation NIP ────────────────────────────────────────────────────────
function validatePin(pin) {

    if (!pin || typeof pin !== 'string') {
        return 'NIP invalide.';
    }

    if (!/^\d+$/.test(pin)) {
        return 'Le NIP ne doit contenir que des chiffres.';
    }

    if (pin.length < 4) {
        return 'Le NIP doit faire au moins 4 chiffres.';
    }

    if (pin.length > 20) {
        return 'Le NIP ne doit pas dépasser 20 chiffres.';
    }

    return null;
}


// ── DisplayName invité ────────────────────────────────────────────────────
function validateDisplayName(name) {

    if (!name || typeof name !== 'string') {
        return 'Nom invalide.';
    }

    name = name.trim();

    if (name.length < 1) {
        return 'Le nom doit faire au moins 1 caractère.';
    }

    if (name.length > 20) {
        return 'Le nom ne doit pas dépasser 20 caractères.';
    }

    if (hasInvisible(name)) {
        return 'Le nom contient des caractères invisibles.';
    }

    if (hasZalgo(name)) {
        return 'Le nom contient une écriture non autorisée.';
    }

    if (hasXSS(name)) {
        return 'Le nom contient des caractères interdits.';
    }

    if (hasExcessiveRepeat(name)) {
        return 'Le nom contient trop de caractères répétés.';
    }

    return null;
}


module.exports = {
    validatePseudo,
    validatePin,
    normalizePseudo,
    validateDisplayName
};