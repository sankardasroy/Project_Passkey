require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql2');
const base64url = require('base64url');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const https = require('https');
const http = require('http');
const path = require('path');
const cookieParser = require('cookie-parser');
const { verifyRegistrationResponse, verifyAuthenticationResponse } = require('@simplewebauthn/server');

// Environment configuration
const port = process.env.PORT || 5200;
const isProduction = process.env.NODE_ENV === 'production';

// Load JWT keys from environment variables
const privateKey = process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n');
const publicKey = process.env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n');

const app = express();

// CORS configuration
app.use(cors({
    origin: 'https://localhost:5200',
    credentials: true
})); // use credentials for cookies
app.use(bodyParser.json());
app.use(cookieParser());

// Database connection
const users = {};
const con = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "Hashtag@123",
    database: process.env.DB_Name || 'webauthn_passkey'
});

con.connect(function(err, result) {
    if (err) {
        console.log('Error connecting to database');
        return;
    }
    console.log('Connected to Database');
});

// JWT token generation functions
const generateAccessToken = (email, userId) => {
  return jwt.sign(
    { email, userId },
    privateKey,
    { algorithm: 'RS256', expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRY || '15m' }
  );
};

const generateRefreshToken = (email, userId) => {
  return jwt.sign(
    { email, userId },
    privateKey,
    { algorithm: 'RS256', expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRY || '1d' }
  );
};

// Middleware to authenticate JWT tokens
const authenticateToken = (req, res, next) => {
    const token = req.cookies.accessToken;

    if (!token) return res.sendStatus(401).json({ error: 'Access token missing' });

    try {
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        req.user = decoded;
        next();
    }
    catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// Expected origin for WebAuthn verification
const expectedOrigin = process.env.EXPECTED_ORIGIN || 'https://localhost:5200';
const expectedRPID = process.env.EXPECTED_RP_ID || 'localhost';

// Endpoint to complete registration
app.post('/webauthn/register', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    // Check if the user already exists
    const checkUserQuery = `SELECT * FROM users WHERE email = ?`;
    con.query(checkUserQuery, [email], (err, results) => {
        if (err) {
            console.error('Error checking user:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length > 0) {
            // If user already exists, return a message
            console.error('Email already exists');
            return res.status(400).json({ error: 'User already exists' });
        }

        // Proceed with registration if the user doesn't exist
        const userId = crypto.randomBytes(32).toString('base64');
       
        // Generate the challenge as a Buffer first
        const challengeBuffer = crypto.randomBytes(32);

        // Encode the challenge using base64url
        const challenge = base64url.encode(challengeBuffer);

        // Store the new user and challenge in the database
        const insertUserQuery = `
            INSERT INTO users (email, user_id, challenge) 
            VALUES (?, ?, ?)
        `;
        con.query(insertUserQuery, [email, userId, challenge], (err) => {
            if (err) {
                console.error('Error storing challenge:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Define WebAuthn options for registration
            const publicKeyCredentialCreationOptions = {
                challenge: challenge,
                rp: {
                    name: 'Passwordless login',
                    id: expectedRPID
                },
                user: {
                    id: userId,
                    name: email,
                    displayName: email,
                },
                pubKeyCredParams: [
                    { type: 'public-key', alg: -7 },
                    { type: 'public-key', alg: -257 }
                ], // ES256 RS256
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    residentKey: 'required',
                    userVerification: 'required',
                },
                attestation: 'direct',
            };

            // Respond with WebAuthn options
            res.json(publicKeyCredentialCreationOptions);
        });
    });
});

// Endpoint to complete registration
app.post('/webauthn/register/complete', (req, res) => {
    const { email, credential } = req.body;
    if (!email || !credential) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    const parsedCredential = credential;
    const getChallengeQuery = `SELECT challenge, user_id FROM users WHERE email = ?`;

    con.query(getChallengeQuery, [email], async function(err, results) {
        if (err) {
            console.error('Error fetching challenge:', err);
            return res.status(400).json({ error: 'Database error' });
        }
       
        if (results.length === 0 || !results[0].challenge) {
            console.error('No challenge found for user');
            return res.status(400).json({ error: 'Invalid authentication request' });
        }
       
        let storedChallenge = results[0].challenge;
        const userId = results[0].user_id;

        try {
            const verification = await verifyRegistrationResponse({
                response: parsedCredential,
                expectedChallenge: storedChallenge,
                expectedOrigin: expectedOrigin,
                expectedRPID: expectedRPID,
            });

            // Extract the verification result and registration information
            const { verified, registrationInfo } = verification;
            
            if (verified && registrationInfo) {
                // Debug the registration info structure
                console.log('Registration info structure:', 
                    JSON.stringify(registrationInfo, (key, value) => 
                        ArrayBuffer.isView(value) || value instanceof ArrayBuffer ? 
                        '[Binary data]' : value
                    )
                );
                
                let credentialPublicKeyBase64 = null;
                let credentialIDBase64url = null;
                const initialCounter = 0;
                
                // CHANGE #1: Store the credential ID directly in base64url format
                if (registrationInfo.credential && registrationInfo.credential.id) {
                    credentialIDBase64url = registrationInfo.credential.id;
                }
                
                // Convert the public key to base64 if it exists
                if (registrationInfo.credential && registrationInfo.credential.publicKey) {
                    try {
                        credentialPublicKeyBase64 = Buffer.from(registrationInfo.credential.publicKey).toString('base64');
                    } catch (error) {
                        console.error('Error converting publicKey to base64:', error);
                    }
                }

                // Define the SQL query
                const insertCredentialQuery = `UPDATE users SET credential = ?, public_key = ?,
                                              credential_id = ?, counter = ? WHERE email = ?`;
                
                // Execute the SQL query to update the user's information
                con.query(insertCredentialQuery, [
                    JSON.stringify(registrationInfo),
                    credentialPublicKeyBase64,
                    credentialIDBase64url, 
                    initialCounter, 
                    email
                ], (dbError) => {
                    // Handle any database errors during credential storage
                    if (dbError) {
                        console.error('Error storing credential:', dbError);
                        return res.status(500).json({ error: 'Database error' });
                    }
                    
                    // Send a success response to the client
                    res.json({ success: true });
                    
                    // Log the successful registration
                    console.log(`Credential and public key saved for ${email}`);
                });
            } else {
                // Handle the case where verification failed
                console.error('Registration verification failed');
                return res.status(400).json({ error: 'Registration verification failed' });
            }
        } catch (verificationError) {
            // Handle any errors that occurred during verification
            console.error('Verification error:', verificationError);
            return res.status(400).json({ error: 'Verification error' });
        }
    });
});

// Begin authentication
app.post('/webauthn/authenticate', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    // Generate a new challenge
    const challengeBuffer = crypto.randomBytes(32);
    const challenge = base64url.encode(challengeBuffer);
    
    console.log("Generated challenge for authentication:", challenge);

    // Store challenge in database
    const updateChallengeQuery = `UPDATE users SET challenge = ? WHERE email = ?`;
    con.query(updateChallengeQuery, [challenge, email], (err) => {
        if (err) {
            console.error('Error updating challenge:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        // Retrieve the credential ID for this user
        const getCredentialQuery = `SELECT credential_id FROM users WHERE email = ?`;
        con.query(getCredentialQuery, [email], (err, results) => {
            if (err || results.length === 0) {
                console.error('Error fetching credential ID:', err);
                return res.status(400).json({ error: 'User not found or not registered' });
            }

            const credentialId = results[0].credential_id;

            // Send authentication request to frontend
            const publicKeyCredentialRequestOptions = {
                challenge: challenge,  // Use the same challenge format consistently
                allowCredentials: [
                    {
                        type: 'public-key',
                        id: credentialId,
                        transports: ['internal'],
                    }
                ],
                userVerification: 'required',
                timeout: 60000,
            };
            
            res.json(publicKeyCredentialRequestOptions);
        });
    });
});

app.post('/webauthn/authenticate/complete', (req, res) => {
    const { email, assertion } = req.body;

    if (!email || !assertion) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    // Get the user data needed for verification
    const getUserDataQuery = `SELECT challenge, public_key, credential_id, counter FROM users WHERE email = ?`;
    
    con.query(getUserDataQuery, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user data:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.error('User not found:', email);
            return res.status(400).json({ error: 'User not found' });
        }
        
        const userData = results[0];
        
        if (!userData.challenge) {
            console.error('No active challenge found for user');
            return res.status(400).json({ error: 'No active authentication request' });
        }

        if (!userData.public_key || !userData.credential_id) {
            console.error('Public key or credential ID not found for user');
            return res.status(400).json({ error: 'User not properly registered' });
        }

        const storedChallenge = userData.challenge;
        const publicKeyBase64 = userData.public_key;
        const credentialId = userData.credential_id;
        const storedCounter = typeof userData.counter === 'number' ? userData.counter : 0;
        
        try {
            // Helper function to ensure base64url format
            const toBase64Url = (str) => {
                // If already base64url, return as-is
                if (!/[+/=]/.test(str)) {
                    return str;
                }
                
                // If standard base64, convert to base64url
                return str.replace(/\+/g, '-')
                          .replace(/\//g, '_')
                          .replace(/=+$/, '');
            };

            // Properly format all parts of the assertion for WebAuthn verification
            const formattedAssertion = {
                id: toBase64Url(assertion.id || assertion.rawId),
                rawId: toBase64Url(assertion.rawId || assertion.id),
                type: assertion.type,
                response: {
                    clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
                    authenticatorData: toBase64Url(assertion.response.authenticatorData),
                    signature: toBase64Url(assertion.response.signature)
                }
            };
            
            // Add userHandle if it exists
            if (assertion.response.userHandle) {
                formattedAssertion.response.userHandle = toBase64Url(assertion.response.userHandle);
            }

            const verification = await verifyAuthenticationResponse({
                response: formattedAssertion,
                expectedChallenge: storedChallenge,
                expectedOrigin: expectedOrigin,
                expectedRPID: expectedRPID,
                credential: {
                    id: credentialId,
                    publicKey: Buffer.from(publicKeyBase64, 'base64'),
                    credentialPublicKey: Buffer.from(publicKeyBase64, 'base64'),
                    counter: storedCounter
                },
                requireUserVerification: true,
            });
            
            console.log('Library verification successful:', JSON.stringify(verification, null, 2));
            
            // Extract the new counter value from verification result
            const newCounter = verification.authenticationInfo.newCounter;
            console.log('Authentication successful for user:', email);
            
            // Update the counter and clear the challenge
            const updateUserQuery = `UPDATE users SET challenge = NULL, counter = ? WHERE email = ?`;
            con.query(updateUserQuery, [newCounter, email], (updateErr) => {
                if (updateErr) {
                    console.error('Error updating user data:', updateErr);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                console.log('User data updated with new counter:', newCounter);
                
                const accessToken = generateAccessToken(email, results[0].user_id);
                const refreshToken = generateRefreshToken(email, results[0].user_id);
                
                res.cookie('accessToken', accessToken, {
                    httpOnly: true,
                    secure: true, // Updated to true for HTTPS
                    sameSite: 'Strict', // Enhanced CSRF protection
                    maxAge: 15 * 60 * 1000 // 15 minutes
                });

                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: true, // Updated to true for HTTPS
                    sameSite: 'Strict', // Enhanced CSRF protection
                    maxAge: 24 * 60 * 60 * 1000 // 1 day
                });

                return res.json({ success: true });
            });
        } catch (error) {
            console.error('Authentication verification error:', error);
            return res.status(400).json({ 
                error: 'Authentication failed',
                details: error.message
            });
        }
    });
});

// Verify token endpoint for session persistence
app.post('/webauthn/verify-token', (req, res) => {
    const token = req.cookies.accessToken;
    
    if (!token) {
        return res.status(400).json({ success: false, error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return res.json({ 
            success: true, 
            email: decoded.email,
            userId: decoded.userId
        });
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
});

app.post('/webauthn/refresh-token', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ success: false, error: 'No refresh token provided' });
    }

    try {
        const decoded = jwt.verify(refreshToken, publicKey, { algorithms: ['RS256'] });

        // Generate a new access token
        const newAccessToken = generateAccessToken(decoded.email, decoded.userId);

        res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: true, // HTTPS enabled
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.json({ success: true});
    } catch (error) {
        console.error('Refresh token verification failed:', error);
        return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
});

// Logout endpoint to clear cookies
app.post('/webauthn/logout', (req, res) => {
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
    });
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
    });
    res.json({ success: true, message: 'Logged out successfully' });
});

//add this for switching to production
//const path = require('path');
// Serve static files from the React app
app.use(express.static(path.join(__dirname, '../Frontend/build')));

// Catch-all handler for React Router
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../Frontend/build', 'index.html'));
});

// Server startup with HTTPS
let server;

try {
    const sslCertPath = process.env.SSL_CERT_PATH || path.join(__dirname, 'certs', 'server.crt');
    const sslKeyPath = process.env.SSL_KEY_PATH || path.join(__dirname, 'certs', 'server.key');
    
    const certificate = fs.readFileSync(sslCertPath);
    const certPrivateKey = fs.readFileSync(sslKeyPath);
    
    const httpsOptions = {
        key: certPrivateKey,
        cert: certificate
    };
    
    server = https.createServer(httpsOptions, app);
    server.listen(port, () => {
        console.log(`🔧 HTTPS server running on https://localhost:${port}`);
        console.log(`📍 Expected origin: ${expectedOrigin}`);
    });
} catch (error) {
    console.error('Error loading SSL certificates:', error.message);
    console.error('Make sure certificate files exist at:');
    console.error(`  Certificate: ${path.join(__dirname, 'certs', 'server.crt')}`);
    console.error(`  Key: ${path.join(__dirname, 'certs', 'server.key')}`);
    process.exit(1);
}

module.exports = server;