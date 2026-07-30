const { createClient } = require('redis');
const { normalizePseudo } = require('./pseudoRules');

async function migrate() {
    const redis = createClient();

    await redis.connect();

    const oldIndex = await redis.hGetAll('accounts:index');

    console.log('Anciens pseudos:', oldIndex);

    await redis.del('accounts:index');

    for (const [oldKey, pseudo] of Object.entries(oldIndex)) {

        const newKey = normalizePseudo(pseudo);

        console.log(`${oldKey} -> ${newKey} (${pseudo})`);

        await redis.hSet(
            'accounts:index',
            newKey,
            pseudo
        );
    }

    await redis.quit();

    console.log('Migration terminée.');
}

migrate().catch(console.error);
