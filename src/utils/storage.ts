import type { DatasetMeta, IntelRecord, QueryHistoryItem } from '../types/intel';

const DB_NAME = 'sentarika_osint_db';
const DB_VERSION = 1;
const STORE_DATASETS = 'datasets';
const STORE_RECORDS = 'records';
const STORE_HISTORY = 'history';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB bu tarayıcıda desteklenmiyor.'));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_DATASETS)) {
        db.createObjectStore(STORE_DATASETS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_RECORDS)) {
        const recStore = db.createObjectStore(STORE_RECORDS, { keyPath: 'id' });
        recStore.createIndex('datasetId', 'datasetId', { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_HISTORY)) {
        db.createObjectStore(STORE_HISTORY, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Veritabanı açılamadı.'));
  });
}

export async function loadAllDatasets(): Promise<DatasetMeta[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DATASETS, 'readonly');
    const req = tx.objectStore(STORE_DATASETS).getAll();
    req.onsuccess = () => {
      const items = (req.result as DatasetMeta[]) || [];
      items.sort((a, b) => b.importedAt.localeCompare(a.importedAt));
      resolve(items);
    };
    req.onerror = () => reject(req.error);
  });
}

export async function loadAllRecords(): Promise<IntelRecord[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_RECORDS, 'readonly');
    const req = tx.objectStore(STORE_RECORDS).getAll();
    req.onsuccess = () => resolve((req.result as IntelRecord[]) || []);
    req.onerror = () => reject(req.error);
  });
}

export async function saveDatasetAndRecords(meta: DatasetMeta, records: IntelRecord[]): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_DATASETS, STORE_RECORDS], 'readwrite');
    tx.objectStore(STORE_DATASETS).put(meta);
    const recStore = tx.objectStore(STORE_RECORDS);
    for (const rec of records) {
      recStore.put(rec);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function deleteDatasetById(datasetId: string): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_DATASETS, STORE_RECORDS], 'readwrite');
    tx.objectStore(STORE_DATASETS).delete(datasetId);
    const recStore = tx.objectStore(STORE_RECORDS);
    const index = recStore.index('datasetId');
    const cursorReq = index.openKeyCursor(IDBKeyRange.only(datasetId));
    cursorReq.onsuccess = () => {
      const cursor = cursorReq.result;
      if (cursor) {
        recStore.delete(cursor.primaryKey);
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function clearAllData(): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_DATASETS, STORE_RECORDS, STORE_HISTORY], 'readwrite');
    tx.objectStore(STORE_DATASETS).clear();
    tx.objectStore(STORE_RECORDS).clear();
    tx.objectStore(STORE_HISTORY).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadQueryHistory(): Promise<QueryHistoryItem[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_HISTORY, 'readonly');
    const req = tx.objectStore(STORE_HISTORY).getAll();
    req.onsuccess = () => {
      const items = (req.result as QueryHistoryItem[]) || [];
      items.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      resolve(items.slice(0, 100));
    };
    req.onerror = () => reject(req.error);
  });
}

export async function appendQueryHistory(item: QueryHistoryItem): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_HISTORY, 'readwrite');
    tx.objectStore(STORE_HISTORY).put(item);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export function createSyntheticTestDataset(): { meta: DatasetMeta; records: IntelRecord[] } {
  const datasetId = 'synthetic_test_v1';
  const datasetName = 'Sentetik Test Veri Seti (RFC-2606)';
  const rawSamples: Omit<IntelRecord, 'id' | 'datasetId' | 'datasetName'>[] = [
    {
      discordId: '104567890123456789',
      email: 'kuzey.demir@example.test',
      username: 'kuzey_dev',
      source: 'Test_Forum_2023',
      ip: '198.51.100.14',
      phone: '+90 555 010 1001',
      notes: 'Sentetik test kaydı — birincil hesap doğrulama örneği',
      extra: { sunucu_rolu: 'Moderatör', kayit_yili: '2019' },
    },
    {
      discordId: '289104567890123456',
      email: 'kuzey.demir@example.test',
      username: 'kuzey_alt02',
      source: 'Test_OyunPortal_2024',
      ip: '198.51.100.88',
      phone: '',
      notes: 'Aynı e-posta ile çapraz eşleşen alternatif sentetik kayıt',
      extra: { platform: 'Oyun Portalı', durum: 'Pasif' },
    },
    {
      discordId: '452910384756192012',
      email: 'ayse.yilmaz@demo.invalid',
      username: 'aysey_sec',
      source: 'Test_Topluluk_2022',
      ip: '203.0.113.42',
      phone: '+90 555 010 2044',
      notes: 'Sentetik siber güvenlik analist profili',
      extra: { ekip: 'BlueTeam', bolge: 'TR-IST' },
    },
    {
      discordId: '803511102246789120',
      email: 'mert.kaya@example.test',
      username: 'mertk_99',
      source: 'Test_CloudLog_2025',
      ip: '192.0.2.77',
      phone: '',
      notes: 'Sentetik API test kaydı',
      extra: { dogrulama: 'E-posta onaylı' },
    },
    {
      discordId: '112233445566778899',
      email: 'selin.arslan@demo.invalid',
      username: 'selin_art',
      source: 'Test_Forum_2023',
      ip: '198.51.100.205',
      phone: '+90 555 010 9981',
      notes: 'Sentetik test kullanıcısı',
      extra: { rozet: 'Erken Destekçi' },
    },
  ];

  const records: IntelRecord[] = rawSamples.map((item, idx) => ({
    id: `${datasetId}_${idx}`,
    datasetId,
    datasetName,
    ...item,
  }));

  const meta: DatasetMeta = {
    id: datasetId,
    name: datasetName,
    category: 'both',
    format: 'synthetic',
    recordCount: records.length,
    columns: ['discordId', 'email', 'username', 'source', 'ip', 'phone', 'notes'],
    mapping: {
      discordIdField: 'discordId',
      emailField: 'email',
      usernameField: 'username',
      sourceField: 'source',
      ipField: 'ip',
      phoneField: 'phone',
      notesField: 'notes',
    },
    importedAt: new Date().toISOString(),
    sizeBytes: 1420,
  };

  return { meta, records };
}
