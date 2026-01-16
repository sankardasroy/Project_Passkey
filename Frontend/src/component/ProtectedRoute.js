import React from 'react';
import { Navigate } from 'react-router-dom';

function ProtectedRoute({ element, isAuthenticated }) {
  // Clone the element and pass all props through
  if (isAuthenticated) {
    return element;
  }
  return <Navigate to="/" />;
}

export default ProtectedRoute;