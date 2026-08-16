import { certificateDetails, certificateOptionLabel } from './certificateDisplay';

test('renders certificate identity and validity from the backend contract', () => {
  const certificate = {
    id: 'AA BB CC',
    subject: 'Иванов Иван',
    common_name: 'Иван Иванов',
    organization: 'ООО Ромашка',
    valid_from: '2026-01-01',
    valid_to: '2027-01-01',
  };

  expect(certificateDetails(certificate)).toEqual([
    { label: 'Субъект', value: 'Иванов Иван' },
    { label: 'Организация', value: 'ООО Ромашка' },
    { label: 'Идентификатор', value: 'AA BB CC' },
    { label: 'Действителен', value: '2026-01-01 — 2027-01-01' },
  ]);
  expect(certificateOptionLabel(certificate)).toBe(
    'Иван Иванов — ООО Ромашка (до 2027-01-01)'
  );
});
