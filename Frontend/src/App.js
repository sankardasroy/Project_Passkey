import './App.css';
import Passkey from './component/passkey.js';
import { Routes, Route } from 'react-router-dom';
import Board from './component/Board';

function App() {
  return (
/*    <div className="App">
      <Passkey />
    </div> */
    <Routes>
      <Route path = "/" element = {<Passkey />} />
	  /* this looks like a hacked way of invoking authentication */
      <Route path = "/tictactoe" element = {<Board />} />
    </Routes>
  );
}

export default App;
