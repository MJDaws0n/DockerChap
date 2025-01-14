require('dotenv').config();

const http = require('http');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const { isStringObject } = require('util/types');

const db = new Database('docker-chap.db');
const PORT = process.env.PORT || 3000;

// Initialize the database
{
    // Create users table
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        fname TEXT NOT NULL,
        lname TEXT NOT NULL,
        password TEXT NOT NULL,
        reset_token TEXT,
        session TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`).run();

    // Create containers table
    db.prepare(`CREATE TABLE IF NOT EXISTS containers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT NOT NULL,
        owner INTEGER NOT NULL,
        container TEXT NOT NULL,
        image TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`).run();
}


/**
 * Serve an HTML file by path.
 * @param {string} filePath - The path to the HTML file.
 * @param {object} res - The HTTP response object.
 */
function serveHtml(filePath, res) {
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('500 Internal Server Error');
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        }
    });
}

/**
 * Serve an JS file by path.
 * @param {string} filePath - The path to the JS file.
 * @param {object} res - The HTTP response object.
 */
function serveScript(filePath, res) {
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('500 Internal Server Error');
        } else {
            res.writeHead(200, { 'Content-Type': 'application/javascript' });
            res.end(data);
        }
    });
}

/**
 * Serve an SVG file by path.
 * @param {string} filePath - The path to the SVG file.
 * @param {object} res - The HTTP response object.
 */
function serveSvg(filePath, res) {
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('500 Internal Server Error');
        } else {
            res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
            res.end(data);
        }
    });
}

/**
 * Generate a secure token.
 * @returns {string} A secure token.
 */
function generateSecureToken() {
    return crypto.randomBytes(64).toString('hex');
}

const server = http.createServer((req, res) => {
    let urlToProcess = req.url;

    // Normalize only for localhost requests
    if (req.headers.host === `localhost:${PORT}`) {
        urlToProcess = req.url.replace(/\/+/g, '/');
    }

    const pathName = new URL(urlToProcess, `http://${req.headers.host}`).pathname;

    switch (pathName) {
        case '/': {
            const filePath = path.join(__dirname, '/routes/home.html');
            serveHtml(filePath, res);
            break;
        }
        case '/login': {
            const filePath = path.join(__dirname, '/routes/login.html');
            serveHtml(filePath, res);
            break;
        }
        case '/signup': {
            const filePath = path.join(__dirname, '/routes/signup.html');
            serveHtml(filePath, res);
            break;
        }
        case '/logout': {
            const filePath = path.join(__dirname, '/routes/logout.html');
            serveHtml(filePath, res);
            break;
        }
        case '/dashboard': {
            const filePath = path.join(__dirname, '/routes/dashboard.html');
            serveHtml(filePath, res);
            break;
        }

        case '/api/signup': {
            let body = '';
            req.on('data', chunk => {
                body += chunk;
            });

            req.on('end', () => {
                let { username, password, fname, lname } = JSON.parse(body);

                if (
                    !username || !password || !fname || !lname ||
                    typeof username !== 'string' || typeof password !== 'string' ||
                    typeof fname !== 'string' || typeof lname !== 'string'
                ) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'All fields (username, password, fname, lname) must be provided.' }));
                    return;
                }

                username = username.toString().trim();
                password = password.toString().trim();
                fname = fname.toString().trim();
                lname = lname.toString().trim();

                // Check if the username already exists
                const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
                if (existingUser) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Username already exists' }));
                    return;
                }

                // Hash the password
                bcrypt.hash(password, 10, (err, hashedPassword) => {
                    if (err) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Error hashing password' }));
                        return;
                    }

                    // Generate reset token (e.g., for password reset functionality)
                    const resetToken = generateSecureToken();

                    // Generate session token
                    const sessionToken = generateSecureToken();

                    // Insert the new user into the database
                    const insert = db.prepare('INSERT INTO users (username, password, fname, lname, reset_token, session) VALUES (?, ?, ?, ?, ?, ?)');
                    insert.run(username, hashedPassword, fname, lname, resetToken, sessionToken);

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'User registered successfully', session: sessionToken, username: username }));
                });
            });
            break;
        }
        case '/api/login': {
            let body = '';
            req.on('data', chunk => {
                body += chunk;
            });

            req.on('end', () => {
                const { username, password } = JSON.parse(body);

                // Fetch the user from the database
                const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
                if (!user) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid username or password' }));
                    return;
                }

                // Compare the entered password with the stored hashed password
                bcrypt.compare(password, user.password, (err, result) => {
                    if (err || !result) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Invalid username or password' }));
                        return;
                    }

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Login successful', sessionToken: user.session, username: username }));
                });
            });
            break;
        }
        case '/api/user': {
            // Parse cookies from the request
            const cookies = {};
            const cookieHeader = req.headers.cookie;
            if (cookieHeader) {
                cookieHeader.split(';').forEach(cookie => {
                    const [name, value] = cookie.trim().split('=');
                    cookies[name] = decodeURIComponent(value);
                });
            }

            // Extract the session cookie
            const session = cookies.session;
            if (!session) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Not logged in' }));
                return;
            }
            
            // Fetch the user from the database
            const user = db.prepare('SELECT * FROM users WHERE session = ?').get(session);
            if (!user) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Not logged in' }));
                return;
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ message: 'User fetched successfully', username: user.username, sessionToken: user.session, fname: user.fname, lname: user.lname  }));
            break;
        }



        case '/assets/user.js': {
            const filePath = path.join(__dirname, '/assets/scripts/accounts.js');
            serveScript(filePath, res);
            break;
        }
        case '/assets/cookies.js': {
            const filePath = path.join(__dirname, '/assets/scripts/cookies.js');
            serveScript(filePath, res);
            break;
        }

        case '/assets/icons/toggle-left.svg': {
            const filePath = path.join(__dirname, '/assets/icons/toggle-left.svg');
            serveSvg(filePath, res);
            break;
        }
        case '/assets/icons/toggle-right.svg': {
            const filePath = path.join(__dirname, '/assets/icons/toggle-right.svg');
            serveSvg(filePath, res);
            break;
        }

        default: {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
            break;
        }
    }
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
