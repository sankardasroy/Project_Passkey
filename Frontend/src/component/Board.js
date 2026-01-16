import React, { useState, useEffect } from 'react';
import Square from './Square.js';
import { useNavigate, useLocation } from 'react-router-dom';
import './Board.css';

export default function Board({ username, onLogout }) {
  // Array is created to track square has which value with X or O
  const [square, setSquare] = useState(Array(9).fill(null));
  // This state will keep track whose turn is next
  const [xIsNext, setXIsNext] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  // Use the username prop if provided, otherwise fall back to location state or default
  const displayUsername = username || location.state?.username || "Player";
  
  // State to control welcome message visibility
  const [showWelcome, setShowWelcome] = useState(true);
  
  // Hide welcome message after 3 seconds
  useEffect(() => {
    const timer = setTimeout(() => {
      setShowWelcome(false);
    }, 3000);
    
    return () => clearTimeout(timer);
  }, []);

  function resetBoard() {
    setSquare(Array(9).fill(null));
    setXIsNext(true);
  }

  function handleLogout() {
    localStorage.removeItem('authToken');
    navigate('/'); // Redirect to login page
  }

  function handleClick(i) {
    if (square[i] || calculateWinner(square)) {
      return;
    }
    
    const nextSquare = square.slice();
    nextSquare[i] = xIsNext ? 'X' : 'O';
    
    setSquare(nextSquare);
    setXIsNext(!xIsNext);
  }

  const winner = calculateWinner(square);
  let status;
  if (winner) {
    status = 'Winner: ' + winner;
  } else if (!square.includes(null)) {
    status = 'Draw!';
  } else {
    status = 'Next player: ' + (xIsNext ? 'X' : 'O');
  }

  return (
    <div className="game-container">
      {/* App Header */}
      <div className="app-header">
        <h1>Tic Tac Toe</h1>
      </div>
      
      {/* Welcome Message */}
      {showWelcome && (
        <div className="welcome-message">
          <h2>Welcome, {displayUsername}!</h2>
          <p>Get ready to play!</p>
        </div>
      )}
      
      {/* Navigation Bar */}
      <div className="nav-bar">
        <div className="player-info">
          <span className="username">{displayUsername}</span>
        </div>
        <div className="game-status">{status}</div>
        <div className="nav-controls">
          <button className="nav-btn" onClick={resetBoard}>New Game</button>
          <button className="nav-btn" onClick={handleLogout}>Log out</button>
        </div>
      </div>
      
      {/* Game Board */}
      <div className="board">
        {[...Array(9)].map((_, i) => (
          <Square
            key={i}
            value={square[i]}
            OnSquareClick={() => handleClick(i)}
          />
        ))}
      </div>
    </div>
  );
}

function calculateWinner(square) {
  const lines = [
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    [0, 4, 8],
    [2, 4, 6],
  ];

  for (let i = 0; i < lines.length; i++) {
    const [a, b, c] = lines[i];
    if (square[a] && square[a] === square[b] && square[a] === square[c]) {
      return square[a];
    }
  }
  return null;
}
