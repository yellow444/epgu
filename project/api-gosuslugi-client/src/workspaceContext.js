// Сигнал смены рабочего контекста в этой вкладке: выбранного сертификата, а
// вместе с ним контура, организации и ИС, которые сервер выводит из привязки.
// Кто меняет контекст, вызывает notifyWorkspaceContextChanged; окно одобрения
// планов по новой версии сбрасывает предпросмотр. Смену в другой вкладке, в
// CLI или на сервере этот сигнал не видит: там последнюю проверку делает
// сервер при execute.
import { useSyncExternalStore } from 'react';

let version = 0;
const listeners = new Set();

export function workspaceContextVersion() {
  return version;
}

export function notifyWorkspaceContextChanged() {
  version += 1;
  listeners.forEach((listener) => listener());
}

function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useWorkspaceContextVersion() {
  return useSyncExternalStore(subscribe, workspaceContextVersion);
}
