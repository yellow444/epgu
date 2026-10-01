import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Checkbox,
  Dropdown,
  Input,
  List,
  Modal,
  Space,
  Tag,
  Typography,
} from 'antd';
import { KeyOutlined, LogoutOutlined, TeamOutlined, UserOutlined } from '@ant-design/icons';
import { authRequest } from './authApi';
import { useAuth } from './AuthGate';

const { Text } = Typography;

function PasswordModal({ open, onClose }) {
  const { logout } = useAuth();
  const [form, setForm] = useState({ current: '', next: '', repeat: '' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setForm({ current: '', next: '', repeat: '' });
      setError('');
    }
  }, [open]);

  const submit = async () => {
    if (form.next !== form.repeat) {
      setError('Новый пароль и повтор не совпадают');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await authRequest('/auth/password', { method: 'POST', body: { current: form.current, new: form.next } });
      onClose();
      // Сервер завершил все сессии аккаунта: входим заново с новым паролем.
      logout('Пароль изменён. Войдите с новым паролем.');
    } catch (err) {
      setError(err.detail || 'Пароль не изменён');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Смена пароля"
      okText="Сменить"
      cancelText="Отмена"
      onOk={submit}
      onCancel={onClose}
      confirmLoading={busy}
      destroyOnHidden
    >
      <Space direction="vertical" style={{ width: '100%' }}>
        <Input.Password
          aria-label="Текущий пароль"
          placeholder="Текущий пароль"
          autoComplete="current-password"
          value={form.current}
          onChange={(event) => setForm({ ...form, current: event.target.value })}
        />
        <Input.Password
          aria-label="Новый пароль"
          placeholder="Новый пароль, от 12 знаков"
          autoComplete="new-password"
          value={form.next}
          onChange={(event) => setForm({ ...form, next: event.target.value })}
        />
        <Input.Password
          aria-label="Повтор нового пароля"
          placeholder="Повтор нового пароля"
          autoComplete="new-password"
          value={form.repeat}
          onChange={(event) => setForm({ ...form, repeat: event.target.value })}
        />
        {error && <Alert type="error" showIcon message={error} />}
      </Space>
    </Modal>
  );
}

function UsersModal({ open, onClose }) {
  const { session } = useAuth();
  const [accounts, setAccounts] = useState([]);
  const [form, setForm] = useState({ login: '', display_name: '', password: '', installation_admin: false });
  const [passwords, setPasswords] = useState({});
  const [error, setError] = useState('');
  const [done, setDone] = useState('');

  const load = useCallback(async () => {
    try {
      setAccounts((await authRequest('/auth/accounts')).accounts || []);
    } catch (err) {
      setError(err.detail || 'Список пользователей недоступен');
    }
  }, []);

  useEffect(() => {
    if (open) {
      setError('');
      setDone('');
      load();
    }
  }, [open, load]);

  const run = async (action, message) => {
    setError('');
    setDone('');
    try {
      await action();
      setDone(message);
      load();
    } catch (err) {
      setError(err.detail || 'Действие не выполнено');
    }
  };

  const create = () =>
    run(async () => {
      await authRequest('/auth/accounts', { method: 'POST', body: form });
      setForm({ login: '', display_name: '', password: '', installation_admin: false });
    }, 'Пользователь создан');

  return (
    <Modal open={open} title="Пользователи установки" footer={null} onCancel={onClose} width={640} destroyOnHidden>
      <List
        dataSource={accounts}
        renderItem={(item) => (
          <List.Item
            key={item.account_id}
            data-testid={`account-${item.login}`}
            actions={
              item.account_id === session.account.id
                ? []
                : [
                    <Button
                      key="toggle"
                      size="small"
                      onClick={() =>
                        run(
                          () =>
                            authRequest(`/auth/accounts/${item.account_id}/disabled`, {
                              method: 'POST',
                              body: { disabled: !item.disabled },
                            }),
                          item.disabled ? 'Пользователь включён' : 'Пользователь отключён'
                        )
                      }
                    >
                      {item.disabled ? 'Включить' : 'Отключить'}
                    </Button>,
                  ]
            }
          >
            <Space direction="vertical" size={4} style={{ width: '100%' }}>
              <Space wrap>
                <Text strong>{item.login}</Text>
                <Text type="secondary">{item.display_name}</Text>
                {item.installation_admin && <Tag color="purple">администратор</Tag>}
                {item.disabled && <Tag>отключён</Tag>}
              </Space>
              {item.account_id !== session.account.id && (
                <Space>
                  <Input.Password
                    size="small"
                    aria-label={`Новый пароль для ${item.login}`}
                    placeholder="Новый пароль"
                    autoComplete="new-password"
                    value={passwords[item.account_id] || ''}
                    onChange={(event) => setPasswords({ ...passwords, [item.account_id]: event.target.value })}
                  />
                  <Button
                    size="small"
                    disabled={!passwords[item.account_id]}
                    onClick={() =>
                      run(async () => {
                        await authRequest(`/auth/accounts/${item.account_id}/password`, {
                          method: 'POST',
                          body: { password: passwords[item.account_id] },
                        });
                        setPasswords({ ...passwords, [item.account_id]: '' });
                      }, 'Пароль назначен')
                    }
                  >
                    Назначить пароль
                  </Button>
                </Space>
              )}
            </Space>
          </List.Item>
        )}
      />
      <Space direction="vertical" style={{ width: '100%', marginTop: 16 }}>
        <Text strong>Новый пользователь</Text>
        <Input aria-label="Логин нового пользователя" placeholder="Логин" value={form.login} onChange={(e) => setForm({ ...form, login: e.target.value })} />
        <Input aria-label="Имя нового пользователя" placeholder="Имя" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
        <Input.Password
          aria-label="Пароль нового пользователя"
          placeholder="Пароль, от 12 знаков"
          autoComplete="new-password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />
        <Checkbox checked={form.installation_admin} onChange={(e) => setForm({ ...form, installation_admin: e.target.checked })}>
          Администратор установки
        </Checkbox>
        <Button type="primary" disabled={!form.login || !form.password} onClick={create}>
          Создать пользователя
        </Button>
        {error && <Alert type="error" showIcon message={error} />}
        {done && <Alert type="success" showIcon message={done} />}
      </Space>
    </Modal>
  );
}

// Меню учётной записи в шапке. Дополнения передают свои пункты в extraItems:
// { key, label, icon, Modal } - Modal получает open и onClose.
export default function AccountMenu({ extraItems = [], compact = false }) {
  const { session, logout } = useAuth();
  const [openKey, setOpenKey] = useState(null);
  const account = session.account;
  const items = [
    ...extraItems.map((item) => ({ key: item.key, label: item.label, icon: item.icon })),
    { key: 'password', icon: <KeyOutlined />, label: 'Сменить пароль' },
    ...(account.installation_admin ? [{ key: 'users', icon: <TeamOutlined />, label: 'Пользователи' }] : []),
    { type: 'divider' },
    { key: 'logout', icon: <LogoutOutlined />, label: 'Выйти' },
  ];

  return (
    <>
      <Dropdown
        trigger={['click']}
        menu={{
          items,
          onClick: ({ key }) => {
            if (key === 'logout') logout();
            else setOpenKey(key);
          },
        }}
      >
        <Button icon={<UserOutlined />} aria-label="Учётная запись" data-testid="account-menu">
          {compact ? null : account.display_name || account.login}
        </Button>
      </Dropdown>
      <PasswordModal open={openKey === 'password'} onClose={() => setOpenKey(null)} />
      {account.installation_admin && <UsersModal open={openKey === 'users'} onClose={() => setOpenKey(null)} />}
      {extraItems.map((item) =>
        item.Modal ? <item.Modal key={item.key} open={openKey === item.key} onClose={() => setOpenKey(null)} /> : null
      )}
    </>
  );
}
