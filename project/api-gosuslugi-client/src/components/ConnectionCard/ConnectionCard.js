import React, { useMemo, useRef, useState } from 'react';
import { Button, Card, Typography } from 'antd';
import definition from './connection_card.v1.json';
import { evaluateConnectionCard } from './evaluateConnectionCard';
import guideDataset from '../IntegrationGuide/knowledge.v1.json';
import { SourceLinks } from '../IntegrationGuide/IntegrationGuide';
import { buildGuideModel } from '../IntegrationGuide/knowledgeModel';
import './ConnectionCard.css';

const { Paragraph, Text, Title } = Typography;
const LABELS = Object.fromEntries(definition.states.map((state) => [state.id, state.label]));
const { SOURCES } = buildGuideModel(guideDataset);
const FACTS = new Map(definition.facts.map((fact) => [fact.id, fact]));

// Только локальные учебные отметки, не новая таблица правил и не состояние ИС.
export const EXAMPLES = [
  { id: 'request', label: 'ИС есть, заявки нет', goal: 'request_power', facts: {
    same_context: 'reported_yes', system_registered: 'reported_yes', cert_bound: 'reported_yes',
    application_submitted: 'reported_no', application_received: 'reported_no',
    power_visible: 'reported_no', power_issued: 'reported_no',
  } },
  { id: 'signature', label: 'Сервер отклонил подпись', goal: 'check_signature', facts: {
    same_context: 'reported_yes', local_signature_valid: 'reported_yes', server_signature_accepted: 'reported_no',
    cert_bound: 'reported_yes', signature_context_checked: 'reported_yes', error_recorded: 'reported_yes',
  } },
  { id: 'pending', label: 'Анкета принята, ждём ответ', goal: 'obtain_api_key', facts: {
    same_context: 'reported_yes', application_submitted: 'reported_yes', application_received: 'reported_yes',
    power_visible: 'unknown', power_issued: 'unknown', key_configured: 'unknown',
  } },
];

export default function ConnectionCard() {
  const [goalId, setGoalId] = useState(definition.goals[0].id);
  const [facts, setFacts] = useState({});
  const [exampleId, setExampleId] = useState(null);
  const resultRef = useRef(null);
  const factsRef = useRef(null);
  const goal = definition.goals.find((item) => item.id === goalId);
  const assessment = useMemo(() => evaluateConnectionCard({ goal: goalId, facts }), [goalId, facts]);
  const rule = assessment.rule;
  const whenEntries = Object.entries(rule.when);

  const reset = () => { setFacts({}); setExampleId(null); };
  const updateGoal = (nextGoal) => { setGoalId(nextGoal); reset(); };
  const openExample = (example) => {
    setGoalId(example.goal);
    setFacts({ ...example.facts });
    setExampleId(example.id);
  };

  return (
    <section aria-labelledby="connection-card-title" className="connection-card">
      <Title id="connection-card-title" level={2}>{definition.title}</Title>
      <Paragraph className="connection-card-lead">{definition.notice}</Paragraph>
      <details className="connection-card-privacy">
        <summary>Какие данные можно вводить</summary>
        <Paragraph>{definition.privacy}</Paragraph>
      </details>
      <div className="connection-card-toolbar">
        <label htmlFor="connection-goal"><Text strong>Что хотите разобрать</Text></label>
        <select id="connection-goal" aria-label="Цель разбора" value={goalId}
          onChange={(event) => updateGoal(event.target.value)}>
          {definition.goals.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}
        </select>
      </div>
      <div className="connection-card-examples" aria-label="Учебные примеры">
        <Text type="secondary">Попробовать на примере:</Text>
        <div className="connection-card-example-buttons">
          {EXAMPLES.map((example) => <Button key={example.id} size="small"
            aria-pressed={exampleId === example.id} onClick={() => openExample(example)}>{example.label}</Button>)}
        </div>
      </div>
      {exampleId && <div className="connection-card-example-notice" role="note">
        <strong>Учебный пример, а не состояние вашей ИС.</strong>{' '}
        Отметки примера остаются учебными и после изменения. <button type="button" onClick={reset}>Начать свой разбор</button>
      </div>}
      <div className="connection-card-layout">
        <section className="connection-card-result" aria-labelledby="connection-result-heading" ref={resultRef} tabIndex={-1}>
          <Card>
            <h3 id="connection-result-heading">Разбор по вашим сведениям</h3>
            <div role="status" aria-live="polite" aria-atomic="true">
              <Paragraph strong className="connection-card-summary">{rule.summary}</Paragraph>
              <Paragraph className="connection-card-next">{rule.next_step}</Paragraph>
            </div>
            <Text type="secondary">Основание — ваши отметки, без проверки системой.</Text>
            <div className="connection-card-links">
              <a href={`#guide/${rule.reference.route}/${rule.reference.node}`} target="_blank" rel="noopener noreferrer"
                title="В новой вкладке — ваши отметки останутся здесь">Открыть узел маршрута</a>
              <a href="#manual" target="_blank" rel="noopener noreferrer"
                title="В новой вкладке — ваши отметки останутся здесь">Открыть ручную подготовку</a>
            </div>
            {assessment.unknown_facts.length > 0 && <details className="connection-card-details">
              <summary>Неизвестных отметок: {assessment.unknown_facts.length}</summary>
              <ul>{assessment.unknown_facts.map((id) => <li key={id}>{FACTS.get(id).title}</li>)}</ul>
            </details>}
            <details className="connection-card-details">
              <summary>Почему такой шаг и на какие источники он опирается</summary>
              <Text strong>Условия сработавшего правила</Text>
              {whenEntries.length ? <ul>{whenEntries.map(([id, expected]) => <li key={id}>
                {FACTS.get(id).title}: {Array.isArray(expected) ? expected.map((item) => LABELS[item]).join(' или ') : LABELS[expected]}
              </li>)}</ul> : <Paragraph>Это общее правило для оставшихся сочетаний отметок.</Paragraph>}
              <Text strong>Источники правила</Text>
              <SourceLinks ids={rule.source_ids} sources={SOURCES} />
              <Paragraph type="secondary">Ссылки дают контекст маршрута. Они не подтверждают ваши отметки и не означают согласование каждой рекомендации оператором.</Paragraph>
            </details>
            <Button className="connection-card-mobile-jump" onClick={() => factsRef.current?.focus()}>Изменить отметки</Button>
          </Card>
        </section>
        <section className="connection-card-facts" aria-labelledby="connection-facts-heading" ref={factsRef} tabIndex={-1}>
          <Card>
            <div className="connection-card-facts-header">
              <h3 id="connection-facts-heading">Ваши отметки</h3>
              <Button size="small" onClick={reset}>Сбросить отметки</Button>
            </div>
            <Paragraph type="secondary">Если не знаете — оставьте «Не проверено / неизвестно».</Paragraph>
            {goal.facts.map((id) => {
              const fact = FACTS.get(id);
              return <div key={id} className="connection-card-fact">
                <label htmlFor={`connection-fact-${id}`}><Text strong>{fact.title}</Text></label>
                <Paragraph id={`connection-hint-${id}`} type="secondary">{fact.hint}</Paragraph>
                <select id={`connection-fact-${id}`} aria-label={fact.title} aria-describedby={`connection-hint-${id}`}
                  value={facts[id] || 'unknown'} onChange={(event) => {
                    const value = event.target.value;
                    setFacts((current) => ({ ...current, [id]: value }));
                  }}>
                  {definition.states.map((state) => <option key={state.id} value={state.id}>{state.label}</option>)}
                </select>
              </div>;
            })}
            <Button className="connection-card-mobile-jump" onClick={() => resultRef.current?.focus()}>К разбору</Button>
          </Card>
        </section>
      </div>
    </section>
  );
}
