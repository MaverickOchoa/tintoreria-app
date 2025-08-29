import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [message, setMessage] = useState('');

  useEffect(() => {
    // Realiza la solicitud al backend
    fetch('http://127.0.0.1:8000')
      .then(response => response.json())
      .then(data => setMessage(data.message))
      .catch(error => console.error('Error al conectar con el backend:', error));
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>Conexión con el Backend</h1>
        <p>Mensaje recibido desde la API de FastAPI:</p>
        <p className="message">{message || 'Cargando...'}</p>
      </header>
    </div>
  );
}

export default App;