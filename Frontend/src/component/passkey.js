import React, { useState} from 'react';
import { useNavigate } from 'react-router-dom'
import axios from 'axios';

function Passkey( { setIsAuthenticated, setUserEmail } ) { //accepting setIsAuthenticated and setUserEmail as props
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [isLoginView, setIsLoginView] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  // Helper functions remain the same
  const base64UrlToBase64 = (base64url) => {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    return base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      + padding;
  };

  const base64UrlToUint8Array = (base64url) => {
    const base64 = base64UrlToBase64(base64url);
    const binary = atob(base64);
    return new Uint8Array(binary.split('').map(c => c.charCodeAt(0)));
  };

  const handleRegister = async () => {
    if (!email) {
      setError('Please enter your email');
      return;
    }

    setError('');
    setIsLoading(true);
    
    try {
      const { data: publicKeyCredentialCreationOptions } = await axios.post('http://localhost:5200/webauthn/register', { email });

      const publicKeyCredentialCreationOptionsParsed = {
        challenge: base64UrlToUint8Array(publicKeyCredentialCreationOptions.challenge),
        rp: publicKeyCredentialCreationOptions.rp,
        user: {
          id: base64UrlToUint8Array(publicKeyCredentialCreationOptions.user.id),
          name: publicKeyCredentialCreationOptions.user.name,
          displayName: publicKeyCredentialCreationOptions.user.displayName
        },
        pubKeyCredParams: publicKeyCredentialCreationOptions.pubKeyCredParams,
        authenticatorSelection: publicKeyCredentialCreationOptions.authenticatorSelection,
        attestation: publicKeyCredentialCreationOptions.attestation,
      };

      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptionsParsed,
      });

      await axios.post('http://localhost:5200/webauthn/register/complete', {
        email,
        credential,
      });

      window.alert('Registration successful');
      setEmail('');
      setIsLoginView(true); // Switch to login view after successful registration

    } catch (error) {
      console.error('Registration failed:', error);
      setError('Registration failed: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAuthenticate = async () => {
    if (!email) {
      setError('Email is required');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      const { data: publicKeyCredentialRequestOptions } = await axios.post(
        'http://localhost:5200/webauthn/authenticate',
        { email }
      );

      const publicKeyCredentialRequestOptionsParsed = {
        challenge: base64UrlToUint8Array(publicKeyCredentialRequestOptions.challenge),
        allowCredentials: [{
          type: 'public-key',
          id: base64UrlToUint8Array(publicKeyCredentialRequestOptions.allowCredentials[0].id),
          transports: ['internal']
        }],
        userVerification: publicKeyCredentialRequestOptions.userVerification
      };

      const assertion = await navigator.credentials.get({ 
        publicKey: publicKeyCredentialRequestOptionsParsed 
      });

      const assertionResponse = {
        id: assertion.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
        type: assertion.type,
        response: {
          authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
          clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
          signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
          userHandle: assertion.response.userHandle ? 
            btoa(String.fromCharCode(...new Uint8Array(assertion.response.userHandle))) : 
            null
        }
      };

      const response= await axios.post('http://localhost:5200/webauthn/authenticate/complete', {
        email,
        assertion: assertionResponse
      });

      if (response.data.success) {
        // Store the token in localStorage for session persistence
        if (response.data.token) {
          console.log('Storing token in localStorage:', response.data.token);
          localStorage.setItem('authToken', response.data.token);
          localStorage.setItem('userEmail', email);
          console.log('Token and email stored successfully');
        } else {
          console.log('No token received from backend');
        }
        setUserEmail(email);
        setIsAuthenticated(true); //update authentication state
        navigate('/tictactoe', { state: { username: email } }); // Redirect to Tic Tac Toe on success
      } else {
        setError('Authentication failed: ' + response.data.message || 'Unknown error');
      }

      window.alert('Authentication successful');
      setEmail('');

    } catch (error) {
      console.error('Authentication failed:', error);
      setError('Authentication failed: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ 
      textAlign: "center", 
      marginTop: "50px",
      maxWidth: "450px",
      margin: "50px auto",
      padding: "20px",
      borderRadius: "8px",
      boxShadow: "0 2px 10px rgba(0, 0, 0, 0.1)"
    }}>
      <h1>{isLoginView ? "Login" : "Register"}</h1>
      
      <div style={{ marginBottom: "20px" }}>
        <label style={{ display: "block", textAlign: "left", marginBottom: "8px" }}>
          Email or phone number
        </label>
        <input
          type="email"
          placeholder="example@email.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={{ 
            width: "100%", 
            padding: "12px", 
            borderRadius: "4px",
            border: "1px solid #ccc",
            fontSize: "16px",
            boxSizing: "border-box"
          }}
        />
      </div>
      
      {error && <p style={{color:'red', marginBottom: "15px"}}>{error}</p>}
      
      <button 
        onClick={isLoginView ? handleAuthenticate : handleRegister} 
        disabled={isLoading}
        style={{ 
          width: "100%",
          padding: "12px", 
          background: isLoginView ? "#1a1a1a" : "#1a1a1a", 
          color: "white",
          border: "none",
          borderRadius: "4px",
          fontSize: "16px",
          cursor: "pointer",
          marginBottom: "15px"
        }}
      >
        {isLoading ? "Processing..." : "Continue"}
      </button>
      
      <div style={{ marginTop: "20px" }}>
        {isLoginView ? (
          <p>Don't have an account? <span 
            onClick={() => setIsLoginView(false)} 
            style={{color: "#007bff", cursor: "pointer", textDecoration: "underline"}}
          >
            Register here.
          </span></p>
        ) : (
          <p>Already have an account? <span 
            onClick={() => setIsLoginView(true)} 
            style={{color: "#007bff", cursor: "pointer", textDecoration: "underline"}}
          >
            Login here.
          </span></p>
        )}
      </div>
      
      
    </div>
  );
}

export default Passkey;
