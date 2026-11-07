// Публичная входная точка клиента. Гайд по интеграциям и ручная подготовка
// работают без backend и без входа; рабочий раздел (заявления, сертификаты,
// вызовы API) загружается только по явному выбору и остаётся под AuthGate.
// Разделы задаются адресом: #guide или #guide/<маршрут>/<шаг>, #manual,
// #connection, #workspace. Пустой или неизвестный адрес открывает гайд.
import React, { lazy, Suspense, useEffect, useState } from 'react';
import { Button, Space, Spin, Typography } from 'antd';
import IntegrationGuide from './components/IntegrationGuide/IntegrationGuide';
import PublicSetup from './components/PublicSetup/PublicSetup';
import ConnectionCard from './components/ConnectionCard/ConnectionCard';

const ProtectedWorkspace = lazy(() => import('./ProtectedWorkspace'));

const SECTIONS = [
  { key: 'guide', label: 'Гайд по интеграциям' },
  { key: 'manual', label: 'Ручная подготовка' },
  { key: 'connection', label: 'Карточка подключения TEST' },
  { key: 'workspace', label: 'Рабочий раздел' },
];

export function sectionFromHash(hash) {
  if (hash === '#workspace') return 'workspace';
  if (hash === '#manual') return 'manual';
  if (hash === '#connection') return 'connection';
  return 'guide';
}

export default function PublicEntry() {
  const [section, setSection] = useState(() => sectionFromHash(window.location.hash));

  useEffect(() => {
    const onHash = () => setSection(sectionFromHash(window.location.hash));
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const open = (key) => {
    // Шаг гайда в адресе сохраняется, пока пользователь остаётся в гайде.
    if (key !== sectionFromHash(window.location.hash)) {
      window.history.replaceState(null, '', `#${key}`);
    }
    setSection(key);
  };

  return (
    <div className="public-entry">
      <nav aria-label="Разделы" style={{ padding: '12px 16px', borderBottom: '1px solid #e5e9f0', background: '#fff' }}>
        <Space wrap align="center">
          <Typography.Text strong>Подключение к Госуслугам</Typography.Text>
          {SECTIONS.map((item) => (
            <Button
              key={item.key}
              type={section === item.key ? 'primary' : 'default'}
              aria-pressed={section === item.key}
              onClick={() => open(item.key)}
            >
              {item.label}
            </Button>
          ))}
          {section !== 'workspace' && (
            <Typography.Text type="secondary">Без входа и без сервера установки</Typography.Text>
          )}
        </Space>
      </nav>
      {section === 'guide' && (
        <main style={{ maxWidth: 1200, margin: '0 auto', padding: '24px 16px' }}>
          <IntegrationGuide />
        </main>
      )}
      {section === 'manual' && (
        <main style={{ maxWidth: 1200, margin: '0 auto', padding: '24px 16px' }}>
          <PublicSetup />
        </main>
      )}
      {section === 'connection' && (
        <main style={{ maxWidth: 960, margin: '0 auto', padding: '24px 16px' }}>
          <ConnectionCard />
        </main>
      )}
      {section === 'workspace' && (
        <Suspense fallback={<Spin aria-label="Загрузка рабочего раздела" style={{ display: 'block', margin: '64px auto' }} />}>
          <ProtectedWorkspace />
        </Suspense>
      )}
    </div>
  );
}
