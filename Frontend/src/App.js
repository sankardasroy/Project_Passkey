import './App.css';
import { useState, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import Passkey from './component/passkey.js';
import Board from './component/Board';
import ProtectedRoute from './component/ProtectedRoute';
import LandingPage from './component/LandingPage.js';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userEmail, setUserEmail] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  
  // Check for stored token on app load
  useEffect(() => {
    const checkToken = async () => {
      const token = localStorage.getItem('authToken');
      const storedEmail = localStorage.getItem('userEmail');
      console.log('Checking for stored token:', token ? 'Found' : 'Not found');
      
      if (token) {
        try {
          // Verify the token is still valid
          const response = await axios.post('http://localhost:5200/webauthn/verify-token', { token });
          console.log('Token verification response:', response.data);
          if (response.data.success) {
            console.log('Token is valid, setting authenticated to true');
            setIsAuthenticated(true);
            setUserEmail(storedEmail || response.data.email);
          } else {
            // Token is invalid, remove it
            console.log('Token verification failed, removing token');
            localStorage.removeItem('authToken');
            localStorage.removeItem('userEmail');
          }
        } catch (error) {
          console.error('Token verification failed:', error);
          localStorage.removeItem('authToken');
          localStorage.removeItem('userEmail');
        }
      }
      setIsLoading(false);
    };
    
    checkToken();
  }, []);
  
  // Logout function to clear token and authentication state
  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userEmail');
    setIsAuthenticated(false);
    setUserEmail('');
  };
  
  if (isLoading) {
    return <div>Loading...</div>;
  }
  
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route 
        path="/login" 
        element={
          isAuthenticated ? (
            <Navigate to="/tictactoe" />
          ) : (
            <Passkey setIsAuthenticated={setIsAuthenticated} setUserEmail={setUserEmail} />
          )
        } 
      />
      
      <Route
        path="/tictactoe"
        element={
          <ProtectedRoute
            element={<Board username={userEmail} onLogout={handleLogout} />}
            isAuthenticated={isAuthenticated}
          />
        }
      />
    </Routes>
  );
}

export default App;
