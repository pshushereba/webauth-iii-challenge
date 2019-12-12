const db = require('../database/db-config.js');

function find() {
    return db('users').select('id', 'username', 'password');
}

function findBy(filter) {
    return db('users').where(filter);
}

async function add(user) {
    const [id] = await db('users').insert(user);
    
    return findById(id);
}

function findById(id) {
    return db('users')
      .where({ id })
      .first();
  }

module.exports = {
    find,
    add,
    findById,
    findBy
}