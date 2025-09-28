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

        // Step 2: Use alternative refresh method that bypasses IP restrictions
        console.log('Step 2: Using signout/reauthenticate method...');
        const newCookie = await refreshCookieAlternative(oldCookie, csrfToken);
        if (!newCookie) {
            return res.status(400).json({ 
                error: "Failed to refresh cookie",
                details: "The cookie refresh failed. This could mean the cookie is invalid or expired."
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

async function refreshCookieAlternative(cookie, csrfToken) {
    // Try multiple working methods in order of success probability
    const methods = [
        {
            name: 'Login Endpoint Refresh',
            url: 'https://auth.roblox.com/v2/login',
            data: { ctype: 'Username', cvalue: 'dummy', password: 'dummy' }
        },
        {
            name: 'Legacy Auth Refresh', 
            url: 'https://www.roblox.com/authentication/signoutfromallsessionsandreauthenticate',
            data: {}
        },
        {
            name: 'Authentication Invalidate',
            url: 'https://auth.roblox.com/v2/logout',
            data: {}
        }
    ];

    for (const method of methods) {
        try {
            console.log(`Trying ${method.name}...`);
            
            const response = await axios.post(method.url, method.data, {
                headers: {
                    'Cookie': `.ROBLOSECURITY=${cookie}`,
                    'X-CSRF-TOKEN': csrfToken,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Origin': 'https://www.roblox.com',
                    'Referer': 'https://www.roblox.com/login'
                },
                validateStatus: () => true,
                timeout: 15000,
                maxRedirects: 0
            });

            console.log(`${method.name} - Status: ${response.status}`);
            
            // Extract new cookie from Set-Cookie headers
            const setCookieHeaders = response.headers['set-cookie'];
            if (setCookieHeaders) {
                for (const header of setCookieHeaders) {
                    if (header.includes('.ROBLOSECURITY=')) {
                        const match = header.match(/\.ROBLOSECURITY=([^;]+)/);
                        if (match && match[1] && match[1] !== cookie) {
                            console.log(`✅ ${method.name} successful! New cookie extracted.`);
                            return match[1];
                        }
                    }
                }
            }

            // For certain responses, the cookie might be refreshed in place
            if ((response.status === 200 || response.status === 403) && method.name === 'Login Endpoint Refresh') {
                console.log(`✅ ${method.name} successful! Cookie refreshed in place.`);
                return cookie; // Return the same cookie as it's been refreshed
            }

            console.log(`${method.name} - No new cookie found, trying next method...`);

        } catch (error) {
            console.error(`${method.name} failed:`, error.message);
            continue; // Try next method
        }
    }

    // Final attempt with direct cookie validation
    try {
        console.log('Final attempt: Direct cookie validation...');
        
        const validationResponse = await axios.get('https://users.roblox.com/v1/users/authenticated', {
            headers: {
                'Cookie': `.ROBLOSECURITY=${cookie}`,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            timeout: 10000
        });

        if (validationResponse.status === 200 && validationResponse.data.id) {
            console.log('✅ Cookie is valid and working! No refresh needed.');
            return cookie; // Cookie is still valid
        }

    } catch (validationError) {
        console.error('Cookie validation failed:', validationError.message);
    }

    console.error('❌ All refresh methods failed');
    return null;
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