/**
 * auth.js — Système d'authentification Chaltet
 * Stockage : Redis
 * Hash : bcryptjs
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const {
    validatePseudo,
    validatePin,
    normalizePseudo
} = require('./pseudoRules');


// ── Inscription ──────────────────────────────────────────────────────────────
async function register(redisClient, pseudo, pin, avatarIndex = 0) {

    const pseudoErr = validatePseudo(pseudo);
    if (pseudoErr)
        return { success:false, error:pseudoErr };


    const pinErr = validatePin(pin);
    if (pinErr)
        return { success:false, error:pinErr };


    const normalized = normalizePseudo(pseudo);


    // Réserver le pseudo de façon atomique
    const reserved = await redisClient.hSetNX(
        'accounts:index',
        normalized,
        pseudo
    );


    if (!reserved) {
        return {
            success:false,
            error:'Ce pseudo est déjà pris.'
        };
    }


    try {

        const pinHash = await bcrypt.hash(pin, 10);


        const accountKey = `account:${normalized}`;


        await redisClient.hSet(accountKey, {

            pseudo,
            normalized,
            pinHash,

            avatarIndex:String(parseInt(avatarIndex) || 0),

            avatarUrl:'',

            createdAt:String(Date.now()),

            lastSeen:String(Date.now())
        });



        const token = generateToken();


        await redisClient.setEx(
            `session:${token}`,
            30 * 24 * 3600,
            normalized
        );


        return {
            success:true,
            token,
            pseudo,
            avatarIndex:parseInt(avatarIndex) || 0
        };


    } catch(err) {

        // rollback si création compte échoue
        await redisClient.hDel(
            'accounts:index',
            normalized
        );

        throw err;
    }
}



// ── Connexion ────────────────────────────────────────────────────────────────
async function login(redisClient, pseudo, pin) {

    const pseudoErr = validatePseudo(pseudo);

    if (pseudoErr)
        return {success:false,error:pseudoErr};


    const pinErr = validatePin(pin);

    if (pinErr)
        return {success:false,error:pinErr};



    const normalized = normalizePseudo(pseudo);


    const account =
        await redisClient.hGetAll(`account:${normalized}`);



    if (!account || !account.pinHash) {

        return {
            success:false,
            error:'Pseudo ou NIP incorrect.'
        };
    }



    const match =
        await bcrypt.compare(pin, account.pinHash);



    if (!match) {

        return {
            success:false,
            error:'Pseudo ou NIP incorrect.'
        };
    }



    await redisClient.hSet(
        `account:${normalized}`,
        'lastSeen',
        String(Date.now())
    );



    const token = generateToken();



    await redisClient.setEx(
        `session:${token}`,
        30 * 24 * 3600,
        normalized
    );



    return {

        success:true,

        token,

        pseudo:account.pseudo,

        avatarIndex:
            parseInt(account.avatarIndex) || 0,

        avatarUrl:
            account.avatarUrl || null
    };
}



// ── Vérifier session ─────────────────────────────────────────────────────────
async function verifySession(redisClient, token) {

    if (!token)
        return null;



    const normalized =
        await redisClient.get(`session:${token}`);



    if (!normalized)
        return null;



    const account =
        await redisClient.hGetAll(`account:${normalized}`);



    if (!account || !account.pseudo)
        return null;



    await redisClient.expire(
        `session:${token}`,
        30 * 24 * 3600
    );



    return {

        pseudo:account.pseudo,

        avatarIndex:
            parseInt(account.avatarIndex) || 0,

        avatarUrl:
            account.avatarUrl || null
    };
}



// ── Vérifier disponibilité pseudo ────────────────────────────────────────────
async function checkPseudo(redisClient, pseudo) {

    const err = validatePseudo(pseudo);

    if (err)
        return {
            available:false,
            error:err
        };


    const normalized = normalizePseudo(pseudo);


    const exists =
        await redisClient.hExists(
            'accounts:index',
            normalized
        );


    return {
        available:!exists
    };
}



// ── Avatar ───────────────────────────────────────────────────────────────────
async function updateAvatar(redisClient, token, avatarIndex, avatarUrl) {

    const normalized =
        await redisClient.get(`session:${token}`);


    if (!normalized) {

        return {
            success:false,
            error:'Session invalide.'
        };
    }



    await redisClient.hSet(
        `account:${normalized}`,
        {
            avatarIndex:String(avatarIndex || 0),
            avatarUrl:avatarUrl || ''
        }
    );


    return {
        success:true
    };
}



// ── Token sécurisé ───────────────────────────────────────────────────────────
function generateToken() {

    return crypto
        .randomBytes(48)
        .toString('hex');
}



module.exports = {

    register,

    login,

    verifySession,

    checkPseudo,

    updateAvatar,

    validatePseudo,

    validatePin
};