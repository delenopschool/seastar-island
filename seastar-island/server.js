const express = require('express');
const path = require('path');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const morgan = require('morgan');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const si = require('systeminformation');
const app = express();

const adapter = new FileSync('db.json');
const db = low(adapter);

// Stel standaardwaarden in
db.defaults({ users: [], messages: [], logs: [], errorLogs: [] }).write();

// Middleware voor logging
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware om statische bestanden te serveren
app.use(express.static(path.join(__dirname, 'public')));

// JWT geheim (gebruikt voor het tekenen van tokens)
const JWT_SECRET = 'Bgt50123';

// Route om een nieuwe gebruiker te registreren
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.get('users').push({ username, password: hashedPassword }).write();
    res.status(201).send('User registered');
});

// Route om in te loggen
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = db.get('users').find({ username }).value();
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '5h' });
        res.json({ token });
    } else {
        res.status(401).send('Incorrect username or password');
    }
});

// Middleware om de JWT-token te verifiëren
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.status(401).send('Access denied.');

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Invalid token.');
        req.user = user;
        next();
    });
}

// Route om de root te serveren
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Route om de sessie te resetten en door te sturen naar de loginpagina
app.get('/logout', (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

// Beveiligde route (alleen toegankelijk na authenticatie)
app.get('/admin_dashboard.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'));
});

// Route om het access log-bestand te serveren
app.get('/access-log', authenticateToken, (req, res) => {
    fs.readFile(path.join(__dirname, 'access.log'), 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading log file');
        } else {
            res.type('text').send(data);
        }
    });
});

// Route om het CPU-gebruik op te halen
app.get('/cpu-usage', authenticateToken, async (req, res) => {
    try {
        const cpuData = await si.currentLoad();
        const usage = cpuData.currentload.toFixed(2); // CPU usage in percentage
        res.json({ usage });
    } catch (error) {
        console.error('Error fetching CPU usage:', error);
        res.status(500).send('Error fetching CPU usage');
    }
});

// Route om het CPU-gebruik op te halen (test zonder authenticatie)
app.get('/cpu-usage-test', async (req, res) => {
    try {
        const cpuData = await si.currentLoad();
        const usage = cpuData.currentload.toFixed(2); // CPU usage in percentage
        res.json({ usage });
    } catch (error) {
        console.error('Error fetching CPU usage:', error);
        res.status(500).send('Error fetching CPU usage');
    }
});

// Endpoint om berichten op te slaan (zonder authenticatie)
app.post('/submit_form', (req, res) => {
    const { name, email, message } = req.body;
    const timestamp = new Date().toISOString();
    try {
        const newMessage = { id: Date.now(), name, email, message, submitted_at: timestamp };
        db.get('messages').push(newMessage).write();
        db.get('logs').push({ action: 'form submitted', name, email, timestamp }).write();
        res.status(201).json(newMessage);
        res.sendFile(path.join(__dirname, 'index.html'));
    } catch (error) {
        db.get('errorLogs').push({ error: error.message, timestamp }).write();
        res.status(500).send('Failed to send message.');
    }
});

// Endpoint om alle berichten te bekijken
app.get('/messages', authenticateToken, (req, res) => {
    const messages = db.get('messages').value();
    res.json(messages);
});

// Endpoint om alle logs te bekijken
app.get('/logs', authenticateToken, (req, res) => {
    const logs = db.get('logs').value();
    res.json(logs);
});

// Endpoint om alle error logs te bekijken
app.get('/errorLogs', authenticateToken, (req, res) => {
    const errorLogs = db.get('errorLogs').value();
    res.json(errorLogs);
});

// Endpoint om een specifiek bericht te verwijderen
app.delete('/messages/:id', authenticateToken, (req, res) => {
    const messageId = parseInt(req.params.id);
    db.get('messages').remove({ id: messageId }).write();
    res.send('Message deleted successfully');
});

// Endpoint om een specifieke log te verwijderen
app.delete('/logs/:timestamp', authenticateToken, (req, res) => {
    const timestamp = req.params.timestamp;
    db.get('logs').remove({ timestamp: timestamp }).write();
    res.send('Log deleted successfully');
});

// Endpoint om een specifieke error log te verwijderen
app.delete('/errorLogs/:timestamp', authenticateToken, (req, res) => {
    const timestamp = req.params.timestamp;
    db.get('errorLogs').remove({ timestamp: timestamp }).write();
    res.send('Error log deleted successfully');
});

// Endpoint om alle berichten te verwijderen
app.delete('/messages', authenticateToken, (req, res) => {
    db.get('messages').remove().write();
    res.send('All messages deleted successfully');
});

// Endpoint om alle logs te verwijderen
app.delete('/logs', authenticateToken, (req, res) => {
    db.get('logs').remove().write();
    res.send('All logs deleted successfully');
});

// Endpoint om alle error logs te verwijderen
app.delete('/errorLogs', authenticateToken, (req, res) => {
    db.get('errorLogs').remove().write();
    res.send('All error logs deleted successfully');
});

// Route voor 404 fouten (Pagina niet gevonden)
app.use((req, res, next) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Route voor 500 fouten (Interne serverfout)
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).sendFile(path.join(__dirname, 'public', '500.html'));
});

// Route voor 504 fouten
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(504).sendFile(path.join(__dirname, 'public', '504.html'));
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
