import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { Root } from './App';
import './styles/global.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root container #root is missing from index.html.');

createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      <Root />
    </BrowserRouter>
  </StrictMode>,
);
