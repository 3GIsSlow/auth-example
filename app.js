/**
 * Express
 */
const express = require('express');
const app = express();

/**
 * Logging with Winston
 */
const winston = require('winston');
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.json(),
        winston.format.timestamp(),
        winston.format.prettyPrint()
    ), 
    defaultMeta: {
        service: 'express'
    },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'all.log' })
    ]
});

/**
 * Json Web Tokens and Body Parser
 */
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

/**
 * Read the .env file
 */
const dotenv = require('dotenv');
dotenv.config();

/**
 * Middleware
 */
app.use(bodyParser.json());

/**
 * Create some test users
 */
const users = [
    {
        username: "admin",
        password: "password1",
        roles: [
            "admin"
        ]
    },
    {
        username: "user",
        password: "password2",
        roles: [
            "user"
        ]
    }
];

// If not in production, change the format for logging to console.
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.cli()
    }));
}

app.listen(process.env.PORT, () => {
    logger.info(`Server is listening on port: ${process.env.PORT}`);
});

/**
 * Callback function for protected routes
 */
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.TOKEN_SECRET, (error, user) => {
            if (error) {
                return res.sendStatus(403);
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
}

/**
 * Routes
 */
app.post('/auth', (req, res, next) => {
    const { username, password } = req.body;
    const user = users.find(user => { return user.username === username && user.password === password });    

    if (user) {
        logger.info(`Giving JWT to ${user.username}`)

        const accessToken = jwt.sign({
            username: user.username,
            roles: user.roles
        }, process.env.TOKEN_SECRET, { expiresIn: "15m" });

        res.json({ accessToken });
    } else {
        logger.info(`The password for ${username} is either incorrect or this user does not exist.`);

        res.status(401).send('Username or password is incorrect.');
    }
});

app.get('/records', authenticate, (req, res, next) => {
    const { roles } = req.user;

    const records = [
        {
            username: "bubbabarber24",
            isCool: true
        },
        {
            username: "wolfbane",
            isCool: false
        }
    ];

    if (!roles.find(role => role === 'admin')) {
        return res.sendStatus(403);
    }

    res.json(records);
});


