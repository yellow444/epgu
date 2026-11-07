import React from 'react';
import { createRoot } from 'react-dom/client';
import PublicEntry from './PublicEntry';

// Гайд и ручная подготовка открываются без входа и без backend. Рабочий
// раздел загружается отдельно и по-прежнему требует входа.
const rootElement = document.getElementById('root');
const root = createRoot(rootElement);
root.render(<PublicEntry />);
