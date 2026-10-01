import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Input, Result, Space, Spin, Typography } from 'antd';
import { authRequest } from './authApi';

const { Title, Paragraph, Text } = Typography;

export const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

function LoginForm({ notice, onLoggedIn }) {
  const [login, setLogin] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const session = await authRequest('/auth/login', { method: 'POST', body: { login, password } });
      setPassword('');
      onLoggedIn(session);
    } catch (err) {
      setError(err.detail || 'Вход не выполнен');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <Space direction="vertical" style={{ width: '100%' }}>
        {notice && <Alert type="info" showIcon message={notice} />}
        <Input
          aria-label="Логин"
          placeholder="Логин"
          autoComplete="username"
          value={login}
          onChange={(event) => setLogin(event.target.value)}
        />
        <Input.Password
          aria-label="Пароль"
          placeholder="Пароль"
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        {error && <Alert type="error" showIcon message={error} />}
        <Button type="primary" htmlType="submit" block loading={busy} disabled={!login || !password}>
          Войти
        </Button>
      </Space>
    </form>
  );
}

// Вход в установку. Пока пользователь не вошёл, приложение не рисуется
// вовсе; сервер и сам не отвечает на методы без сессии.
export default function AuthGate({ children }) {
  const [phase, setPhase] = useState('loading');
  const [session, setSession] = useState(null);
  const [mode, setMode] = useState(null);
  const [notice, setNotice] = useState('');

  const load = useCallback(async () => {
    setPhase('loading');
    try {
      const payload = await authRequest('/auth/session');
      setSession(payload);
      setPhase('ready');
      return;
    } catch (err) {
      if (err.status !== 401) {
        setPhase('error');
        return;
      }
    }
    try {
      const described = await authRequest('/auth/mode');
      setMode(described);
      setPhase(described.bootstrap_required ? 'bootstrap' : 'login');
    } catch (err) {
      setPhase('error');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const logout = useCallback(async (message = '') => {
    try {
      await authRequest('/auth/logout', { method: 'POST' });
    } catch (err) {
      // Сессию на сервере могли уже погасить.
    }
    setSession(null);
    setNotice(message);
    setPhase('login');
  }, []);

  const refresh = useCallback(async () => {
    try {
      const payload = await authRequest('/auth/session');
      setSession(payload);
      return payload;
    } catch (err) {
      // Сеть могла моргнуть: на вход отправляет только ответ "нет сессии".
      if (err.status === 401) {
        setSession(null);
        setPhase('login');
      }
      return null;
    }
  }, []);

  // Сессия может закончиться, пока страница открыта: по сроку, после смены
  // пароля или перезапуска установки. Тогда методы отвечают 401, а
  // пользователь видит пустые разделы. Поэтому сессия перепроверяется, когда
  // вкладка снова на экране, и раз в минуту; без неё показывается вход.
  useEffect(() => {
    if (phase !== 'ready') return undefined;
    let current = '';
    const check = async () => {
      try {
        const payload = await authRequest('/auth/session');
        const text = JSON.stringify(payload);
        if (text !== current) {
          current = text;
          setSession(payload);
        }
      } catch (err) {
        if (err.status === 401) {
          setSession(null);
          setNotice('Сессия закончилась. Войдите снова.');
          setPhase('login');
        }
      }
    };
    const onVisible = () => {
      if (document.visibilityState === 'visible') check();
    };
    window.addEventListener('focus', check);
    document.addEventListener('visibilitychange', onVisible);
    const timer = window.setInterval(check, 60000);
    return () => {
      window.removeEventListener('focus', check);
      document.removeEventListener('visibilitychange', onVisible);
      window.clearInterval(timer);
    };
  }, [phase]);

  const value = useMemo(() => ({ session, mode, logout, refresh }), [session, mode, logout, refresh]);

  if (phase === 'loading') return <Spin style={{ display: 'block', margin: '64px auto' }} />;
  if (phase === 'error') {
    return (
      <Result
        status="warning"
        title="Сервер установки недоступен"
        extra={<Button onClick={load}>Повторить</Button>}
      />
    );
  }
  if (phase !== 'ready') {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '48px 16px' }}>
        <Card style={{ width: '100%', maxWidth: 420 }}>
          <Title level={4}>Вход в установку</Title>
          {phase === 'bootstrap' ? (
            <Alert
              type="info"
              showIcon
              message="Установка ещё не настроена"
              description={
                <>
                  <Paragraph>Первого администратора создают на сервере установки командой:</Paragraph>
                  <Text code>python auth_cli.py create-admin --login admin</Text>
                </>
              }
            />
          ) : (
            <LoginForm
              notice={notice}
              onLoggedIn={(payload) => {
                setNotice('');
                setSession(payload);
                setPhase('ready');
              }}
            />
          )}
        </Card>
      </div>
    );
  }
  return (
    <AuthContext.Provider value={value}>
      {typeof children === 'function' ? children(value) : children}
    </AuthContext.Provider>
  );
}
