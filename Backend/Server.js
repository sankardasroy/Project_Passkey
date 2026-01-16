const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql2');
const base64url = require('base64url');
const jwt = require('jsonwebtoken');
const { verifyRegistrationResponse, verifyAuthenticationResponse } = require('@simplewebauthn/server');



const app = express();
app.use(cors());
app.use(bodyParser.json());

const users = {}; // Store users by email

var con = mysql.createConnection({
    host: 'localhost',
    user: "root",
    password: "Hashtag@123",
    database: 'webauthn_passkey'
});

con.connect(function(err, result) {
    if (err) {
        console.log('Error connecting to database');
        return;
    }
    console.log('Connected to Database');
});

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
                    id: 'localhost'
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
                expectedOrigin: 'http://localhost:5200', //CHANGED TO MATCH BACKEND PORT
                expectedRPID: 'localhost',
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
                    
                    // Only log these values if they exist
                    if (credentialPublicKeyBase64) {
                        console.log('Public Key (Base64):', credentialPublicKeyBase64);
                    }
                    
                    if (credentialIDBase64url) {
                        console.log('Credential ID (Base64URL):', credentialIDBase64url);
                    }
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
                expectedOrigin: 'http://localhost:5200', //CHANGED TO MATCH BACKEND PORT
                expectedRPID: 'localhost',
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
                
                // Generate a JWT token for session persistence
                const token = jwt.sign(
                    { email: email, userId: results[0].user_id },
                    'your-secret-key-change-this',
                    { expiresIn: '7d' }
                );
                
                // Send success response with token
                res.json({ 
                    success: true,
                    message: 'Authentication successful',
                    token: token
                });
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

app.listen(5200, () => {
    console.log('Server running on port 5200...');
});

// Verify token endpoint for session persistence
app.post('/webauthn/verify-token', (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.status(400).json({ success: false, error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, 'your-secret-key-change-this');
        return res.json({ 
            success: true, 
            email: decoded.email,
            userId: decoded.userId
        });
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
});

app.get('/test', (req, res) => {
    res.send('Backend is alive!');
});


//add this for switching to production
const path = require('path');
// Serve static files from the React app
app.use(express.static(path.join(__dirname, 'build')));
// The "catchall" handler: for any request that doesn't
// match one above, send back React's index.html file.
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});