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
        console.log('Cookie length:', oldCookie.length);

        // Step 1: Get CSRF token
        console.log('Step 1: Getting CSRF token...');
        const csrfToken = await getCSRFToken(oldCookie);
        console.log('CSRF token result:', csrfToken ? 'SUCCESS' : 'FAILED');
        if (!csrfToken) {
            return res.status(400).json({ 
                error: "Failed to get CSRF token",
                details: "This usually means the cookie is invalid or expired. Check that your cookie starts with '_|WARNING:-DO-NOT-SHARE-THIS.'"
            });
        }

        // Step 2: Get authentication ticket
        const authTicket = await getAuthenticationTicket(oldCookie, csrfToken);
        if (!authTicket) {
            return res.status(400).json({ 
                error: "Roblox Authentication Ticket System Restricted", 
                details: "Roblox has restricted the authentication ticket system due to security updates. Cookie refresh may not work from hosted services like Vercel/Replit due to IP restrictions.",
                suggestions: [
                    "Try using the cookie directly in your applications",
                    "Consider using Roblox Open Cloud API keys for bots",
                    "The cookie might work from your local computer's IP"
                ],
                moreInfo: "This is a Roblox platform limitation, not an issue with this website."
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
        console.log('Making CSRF token request...');
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
        
        console.log('CSRF Response status:', response.status);
        console.log('CSRF Response headers available:', Object.keys(response.headers).join(', '));
        
        const token = response.headers['x-csrf-token'];
        if (!token) {
            console.error('No CSRF token in response. Status:', response.status);
            console.error('Response data:', response.data);
            console.error('All headers:', response.headers);
        } else {
            console.log('CSRF token obtained successfully');
        }
        return token;
    } catch (error) {
        console.error('CSRF token error:', error.message);
        console.error('Error details:', error.code, error.response?.status);
        return null;
    }
}

async function getAuthenticationTicket(cookie, csrfToken) {
    // Try multiple endpoints and methods
    const endpoints = [
        {
            url: 'https://auth.roblox.com/v1/authentication-ticket',
            method: 'POST',
            data: {}
        },
        {
            url: 'https://auth.roblox.com/v1/authentication-ticket',
            method: 'POST', 
            data: { ctype: 'Ticket' }
        },
        {
            url: 'https://auth.roblox.com/v2/authentication-ticket',
            method: 'POST',
            data: {}
        }
    ];

    for (const endpoint of endpoints) {
        try {
            console.log(`Trying ${endpoint.method} ${endpoint.url}...`);
            const response = await axios({
                method: endpoint.method,
                url: endpoint.url,
                data: endpoint.data,
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
            });
            
            console.log(`Response status: ${response.status}`);
            
            if (response.status === 200) {
                const ticket = response.headers['rbx-authentication-ticket'];
                if (ticket) {
                    console.log('✅ Authentication ticket obtained successfully!');
                    return ticket;
                } else {
                    console.log('No ticket in headers, checking response body...');
                    if (response.data && response.data.ticket) {
                        console.log('✅ Found ticket in response body!');
                        return response.data.ticket;
                    }
                }
            }
            
            if (response.status === 401) {
                console.error('401 Unauthorized - Cookie invalid/expired');
                console.error('Response:', response.data);
                continue; // Try next endpoint
            }
            
            if (response.status === 403) {
                console.error('403 Forbidden - CSRF token issue');
                console.error('Response:', response.data);
                continue; // Try next endpoint
            }
            
            console.log('Available headers:', Object.keys(response.headers));
            console.log('Response body:', response.data);
            
        } catch (error) {
            console.error(`Error with ${endpoint.url}:`, error.message);
            if (error.response) {
                console.error('Error status:', error.response.status);
                console.error('Error data:', error.response.data);
            }
            continue; // Try next endpoint
        }
    }
    
    console.error('❌ All authentication ticket endpoints failed');
    return null;
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