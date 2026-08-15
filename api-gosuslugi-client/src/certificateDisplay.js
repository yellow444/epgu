const firstText = (...values) =>
  values.find((value) => value !== undefined && value !== null && String(value).trim());

export const certificateDetails = (certificate) => {
  if (!certificate) return [];
  const subject = firstText(certificate.subject, certificate.common_name, 'Не указан');
  const organization = firstText(certificate.organization, 'Не указана');
  const thumbprint = firstText(certificate.id, 'Не указан');
  const validFrom = firstText(certificate.valid_from, 'не указано');
  const validTo = firstText(certificate.valid_to, 'не указано');
  return [
    { label: 'Субъект', value: String(subject) },
    { label: 'Организация', value: String(organization) },
    { label: 'Идентификатор', value: String(thumbprint) },
    { label: 'Действителен', value: `${validFrom} - ${validTo}` },
  ];
};

export const certificateOptionLabel = (certificate) => {
  const identity = firstText(certificate.common_name, certificate.subject, 'Не указан');
  const organization = firstText(certificate.organization, 'Без организации');
  const validTo = firstText(certificate.valid_to, 'срок не указан');
  return `${identity} - ${organization} (до ${validTo})`;
};
