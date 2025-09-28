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

        console.log('Starting cookie refresh process...');

        // Step 1: Get CSRF token
        const csrfToken = await getCSRFToken(oldCookie);
        if (!csrfToken) {
            return res.status(400).json({ 
                error: "Failed to get CSRF token",
                details: "This usually means the cookie is invalid or expired"
            });
        }

        // Step 2: Get authentication ticket
        const authTicket = await getAuthenticationTicket(oldCookie, csrfToken);
        if (!authTicket) {
            return res.status(400).json({ 
                error: "Failed to get authentication ticket", 
                details: "Cookie may be invalid, expired, or account needs fresh login"
            });
        }

        // Step 3: Redeem ticket for new cookie
        const newCookie = await redeemAuthTicket(authTicket, csrfToken);
        if (!newCookie) {
            return res.status(400).json({ 
                error: "Failed to redeem authentication ticket",
                details: "The authentication ticket could not be exchanged for a new cookie"
            });
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
        console.error('API Error:', error.message);
        res.status(500).json({ 
            error: error.message,
            details: "Internal server error during cookie refresh"
        });
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
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Origin': 'https://www.roblox.com',
                    'Referer': 'https://www.roblox.com/login'
                },
                validateStatus: () => true,
                timeout: 10000
            }
        );
        
        const token = response.headers['x-csrf-token'];
        if (!token) {
            console.error('No CSRF token in response. Status:', response.status);
            console.error('Response data:', response.data);
        }
        return token;
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
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Origin': 'https://www.roblox.com',
                    'Referer': 'https://www.roblox.com/home',
                    'RBXAuthenticationNegotiation': '1',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-site'
                },
                validateStatus: () => true,
                timeout: 15000
            }
        );
        
        console.log('Auth ticket response status:', response.status);
        
        if (response.status === 401) {
            console.error('401 Unauthorized - Cookie is likely invalid or expired');
            console.error('Response:', response.data);
            return null;
        }
        
        if (response.status === 403) {
            console.error('403 Forbidden - CSRF token issue or rate limit');
            console.error('Response:', response.data);
            return null;
        }
        
        const ticket = response.headers['rbx-authentication-ticket'];
        if (!ticket) {
            console.error('No authentication ticket in response headers');
            console.error('Available headers:', Object.keys(response.headers));
            console.error('Response body:', response.data);
        }
        return ticket;
    } catch (error) {
        console.error('Auth ticket error:', error.message);
        if (error.response) {
            console.error('Error response status:', error.response.status);
            console.error('Error response data:', error.response.data);
        }
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
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Origin': 'https://www.roblox.com',
                    'Referer': 'https://www.roblox.com/home',
                    'X-CSRF-TOKEN': csrfToken,
                    'RBXAuthenticationNegotiation': '1',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-site'
                },
                validateStatus: () => true,
                timeout: 15000
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
        
        console.error('No new cookie found in redeem response');
        console.error('Response status:', response.status);
        console.error('Response data:', response.data);
        return null;
    } catch (error) {
        console.error('Redeem error:', error.message);
        if (error.response) {
            console.error('Redeem error status:', error.response.status);
            console.error('Redeem error data:', error.response.data);
        }
        return null;
    }
}

async function getUsername(cookie) {
    try {
        const response = await axios.get('https://users.roblox.com/v1/users/authenticated', {
            headers: { 
                'Cookie': `.ROBLOSECURITY=${cookie}`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            timeout: 10000
        });
        return response.data.name;
    } catch (error) {
        console.error('Username fetch error:', error.message);
        return 'Unknown';
    }
}

const PORT = process.env.PORT || 5000;

// Start server if not being imported (for local development)
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
        console.log('Ready to refresh Roblox cookies!');
    });
}

// Export for Vercel
export default app;