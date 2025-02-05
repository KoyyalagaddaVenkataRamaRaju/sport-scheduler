const express = require('express');
const bcrypt = require('bcryptjs');
const pool = require('./db/db');
const router = express.Router();

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        console.log("User is authenticated: ", req.session.user);
        return next();
    }
    console.log("User not authenticated");
    res.redirect('/login');
};

// Middleware to check admin role
const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') {
        console.log("User is admin: ", req.session.user);
        return next();
    }
    console.log("User is not admin");
    res.redirect('/');
};


// Home Page
router.get('/', (req, res) => res.render('home'));

// Register Route
router.get('/register', (req, res) => {
    res.render('register');
});

// Register POST Route
router.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    try {
        if (!name || !email || !password || !role) {
            return res.render('register', { message: 'All fields are required' });
        }
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.render('register', { message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)',
            [name, email, hashedPassword, role]
        );
        res.redirect('/login');
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).send('Server Error');
    }
});

// Login Route
router.get('/login', (req, res) => {
    res.render('login');
});

// Login POST Route (Handling the form submission)
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.render('login', { message: 'Please enter both email and password.' });
        }

        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];

        if (!user) {
            return res.render('login', { message: 'Invalid email or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.render('login', { message: 'Invalid email or password.' });
        }

        req.session.user = {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        };

        if (user.role === 'player') {
            res.redirect('/player-dashboard');
        } else if (user.role === 'admin') {
            res.redirect('/admin-dashboard');
        }

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Server Error');
    }
});

// Admin Dashboard
router.get('/admin-dashboard', isAdmin, async (req, res) => {
    try {
        const sports = await pool.query('SELECT * FROM sports');
        const sessions = await pool.query(
            `SELECT se.id, se.venue, se.date_time, s.name AS sport_name 
            FROM sessions se
            JOIN sports s ON se.sport_id = s.id
            WHERE se.status = $1`,
            ['upcoming']
        );

        res.render('admin-dashboard', {
            sports: sports.rows,
            sessions: sessions.rows
        });
    } catch (error) {
        console.error('Error fetching admin dashboard:', error);
        res.status(500).send('Server Error');
    }
});


// POST Route to Add Sport (Admin only)
router.post('/admin/add-sport', isAdmin, async (req, res) => {
    const { sport_name } = req.body;

    if (!sport_name) {
        return res.render('admin-dashboard', { message: 'Sport name is required.' });
    }

    try {
        await pool.query('INSERT INTO sports (name) VALUES ($1)', [sport_name]);

        res.redirect('/admin-dashboard');
    } catch (error) {
        console.error('Error adding sport:', error);
        res.status(500).send('Server Error');
    }
});

// POST Route to Create a Session (Admin only)
router.post('/sessions', isAdmin, async (req, res) => {
    const { sport_id, venue, date_time } = req.body;

    if (!sport_id || !venue || !date_time) {
        return res.render('admin-dashboard', { message: 'All fields are required to create a session.' });
    }

    try {
        await pool.query(
            'INSERT INTO sessions (sport_id, venue, date_time, status) VALUES ($1, $2, $3, $4)',
            [sport_id, venue, date_time, 'upcoming']
        );

        res.redirect('/admin-dashboard');
    } catch (error) {
        console.error('Error creating session:', error);
        res.status(500).send('Server Error');
    }
});

// Player Dashboard
router.get('/player-dashboard', isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;

    try {
        const sports = await pool.query('SELECT * FROM sports');

        const joinedSessions = await pool.query(
            `SELECT s.name AS sport_name, se.venue, se.date_time, se.id AS session_id
            FROM sessions se
            JOIN sports s ON se.sport_id = s.id
            JOIN session_players sp ON sp.session_id = se.id
            WHERE sp.user_id = $1 AND se.status = $2`,
            [userId, 'upcoming']
        );

        const sessions = await pool.query(
            `SELECT s.name AS sport_name, se.venue, se.date_time, se.id AS session_id
            FROM sessions se
            JOIN sports s ON se.sport_id = s.id
            WHERE se.status = $1`,
            ['upcoming']
        );

        res.render('player-dashboard', {
            joinedSessions: joinedSessions.rows,
            sessions: sessions.rows,
            sports: sports.rows
        });
    } catch (error) {
        console.error('Error fetching player dashboard:', error);
        res.status(500).send('Server Error');
    }
});

// POST Route to Join a Session (Player only)
router.post('/sessions/join/:sessionId', isAuthenticated, async (req, res) => {
    const { sessionId } = req.params;
    const userId = req.session.user.id;

    try {
        const checkUserInSession = await pool.query(
            'SELECT * FROM session_players WHERE user_id = $1 AND session_id = $2',
            [userId, sessionId]
        );

        if (checkUserInSession.rows.length > 0) {
            return res.redirect('/player-dashboard');
        }

        await pool.query(
            'INSERT INTO session_players (user_id, session_id) VALUES ($1, $2)',
            [userId, sessionId]
        );

        res.redirect('/player-dashboard');
    } catch (error) {
        console.error('Error joining session:', error);
        res.status(500).send(`Server Error: ${error.message}`);
    }
});

// Change Password Page Route
router.get('/change-password', isAuthenticated, (req, res) => {
    res.render('change-password');
});

// Change Password POST Route
router.post('/change-password', isAuthenticated, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userId = req.session.user.id;

    try {
        const result = await pool.query('SELECT password, role FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).send('Current password is incorrect');
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).send('Passwords do not match');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);

        const role = user.role;
        if (role === 'player') {
            res.redirect('/player-dashboard');
        } else if (role === 'admin') {
            res.redirect('/admin-dashboard');
        } else {
            res.status(500).send('Unknown user role');
        }

    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).send('Server Error');
    }
});

// Logout Route
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Failed to destroy session');
        }
        res.redirect('/');
    });
});


module.exports = router;