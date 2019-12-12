const express = require('express');

const authRouter = require('./auth/auth-router.js');

const server = express();
server.use(express.json());

server.use('/api/auth', authRouter);

server.get('/', (req, res) => {
    res.send('<h2>Default Project Route</h2>');
})

module.exports = server;