import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  FilePlus2,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  X,
} from 'lucide-react';
import type { DatasetMeta, FieldMapping, IntelRecord } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import {
  apiAdminAddDatasetRecord,
  apiAdminDeleteDatasetRecord,
  apiAdminGetDatasetRecords,
  apiAdminUpdateDataset,
  apiAdminUpdateDatasetRecord,
} from '../utils/api';
import { normalizeRows, parseDatasetContent } from '../utils/parser';

interface DatasetEditorModalProps {
  dataset: DatasetMeta | null;
  onClose: () => void;
  onDatasetChanged: (datasetId: string) => Promise<void>;
}

const EMPTY_RECORD_FORM = {
  discordId: '',
  email: '',
  username: '',
  source: '',
  ip: '',
  phone: '',
  notes: '',
};

export function DatasetEditorModal({ dataset, onClose, onDatasetChanged }: DatasetEditorModalProps) {
  const { lang, t } = useI18n();
  const [tab, setTab] = useState<'records' | 'settings'>('records');
  const [meta, setMeta] = useState<DatasetMeta | null>(dataset);
  const [nameInput, setNameInput] = useState(dataset?.name || '');
  const [mapping, setMapping] = useState<FieldMapping | null>(dataset?.mapping || null);

  const [records, setRecords] = useState<IntelRecord[]>([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const [editingRecordId, setEditingRecordId] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState(EMPTY_RECORD_FORM);

  const [addPanelMode, setAddPanelMode] = useState<'none' | 'single' | 'bulk'>('none');
  const [newRecDraft, setNewRecDraft] = useState(EMPTY_RECORD_FORM);
  const [appendRawText, setAppendRawText] = useState('');

  const pageSize = 25;

  const mappingFields: { key: keyof FieldMapping; label: string }[] = [
    { key: 'discordIdField', label: t('Discord ID Sütunu', 'Discord ID Column') },
    { key: 'emailField', label: t('E-posta Sütunu', 'Email Column') },
    { key: 'usernameField', label: t('Kullanıcı Adı Sütunu', 'Username Column') },
    { key: 'sourceField', label: t('Kaynak / Sızıntı Adı', 'Source / Breach Name') },
    { key: 'ipField', label: t('IP Adresi Sütunu', 'IP Address Column') },
    { key: 'phoneField', label: t('Telefon Sütunu', 'Phone Column') },
    { key: 'notesField', label: t('Notlar / Açıklama', 'Notes / Details') },
  ];

  const loadRecords = useCallback(
    async (dsId: string, qText: string, pageNum: number) => {
      setLoading(true);
      try {
        const res = await apiAdminGetDatasetRecords(dsId, qText, pageNum, pageSize);
        setMeta(res.meta);
        setRecords(res.records);
        setTotalRecords(res.total);
      } catch (err) {
        setFeedback({
          type: 'err',
          text: err instanceof Error ? err.message : t('Kayıtlar yüklenemedi.', 'Failed to load records.'),
        });
      } finally {
        setLoading(false);
      }
    },
    [t],
  );

  useEffect(() => {
    if (!dataset) return;
    setTab('records');
    setMeta(dataset);
    setNameInput(dataset.name);
    setMapping(dataset.mapping);
    setSearchQuery('');
    setPage(1);
    setEditingRecordId(null);
    setAddPanelMode('none');
    setFeedback(null);
    void loadRecords(dataset.id, '', 1);
  }, [dataset, loadRecords]);

  const availableColumns = useMemo(() => {
    if (!meta) return [];
    const colSet = new Set<string>(meta.columns || []);
    for (const k of ['discordId', 'email', 'username', 'source', 'ip', 'phone', 'notes']) {
      colSet.add(k);
    }
    if (mapping) {
      for (const v of Object.values(mapping)) {
        if (v) colSet.add(v);
      }
    }
    return Array.from(colSet);
  }, [meta, mapping]);

  if (!dataset || !meta) return null;

  const totalPages = Math.max(1, Math.ceil(totalRecords / pageSize));

  const handleSearchSubmit = (e: FormEvent) => {
    e.preventDefault();
    setPage(1);
    void loadRecords(meta.id, searchQuery.trim(), 1);
  };

  const handleSaveMetaAndRenormalize = async () => {
    if (!mapping) return;
    setSaving(true);
    setFeedback(null);
    try {
      const res = await apiAdminUpdateDataset(meta.id, {
        name: nameInput.trim() || meta.name,
        mapping,
        reNormalize: true,
      });
      setMeta(res.dataset);
      setNameInput(res.dataset.name);
      await loadRecords(meta.id, searchQuery.trim(), page);
      await onDatasetChanged(meta.id);
      setFeedback({
        type: 'ok',
        text: t(
          'Depo adı, sütun eşleştirmeleri ve tüm kayıt filtrelemeleri güncellendi.',
          'Dataset name, column mappings, and all record extractions were updated.',
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Güncelleme başarısız.', 'Update failed.'),
      });
    } finally {
      setSaving(false);
    }
  };

  const handleStartEditRow = (rec: IntelRecord) => {
    setEditingRecordId(rec.id);
    setEditDraft({
      discordId: rec.discordId || '',
      email: rec.email || '',
      username: rec.username || '',
      source: rec.source || '',
      ip: rec.ip || '',
      phone: rec.phone || '',
      notes: rec.notes || '',
    });
  };

  const handleSaveEditRow = async (recordId: string) => {
    setSaving(true);
    setFeedback(null);
    try {
      const res = await apiAdminUpdateDatasetRecord(meta.id, recordId, editDraft);
      setMeta(res.dataset);
      setEditingRecordId(null);
      await loadRecords(meta.id, searchQuery.trim(), page);
      await onDatasetChanged(meta.id);
      setFeedback({ type: 'ok', text: t('Kayıt güncellendi.', 'Record updated.') });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Kayıt güncellenemedi.', 'Failed to update record.'),
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteRow = async (recordId: string) => {
    setSaving(true);
    setFeedback(null);
    try {
      const res = await apiAdminDeleteDatasetRecord(meta.id, recordId);
      setMeta(res.dataset);
      const nextPage = records.length <= 1 && page > 1 ? page - 1 : page;
      setPage(nextPage);
      await loadRecords(meta.id, searchQuery.trim(), nextPage);
      await onDatasetChanged(meta.id);
      setFeedback({ type: 'ok', text: t('Kayıt silindi.', 'Record deleted.') });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Kayıt silinemedi.', 'Failed to delete record.'),
      });
    } finally {
      setSaving(false);
    }
  };

  const handleAddSingleRecord = async (e: FormEvent) => {
    e.preventDefault();
    const hasAny = Object.values(newRecDraft).some((v) => v.trim().length > 0);
    if (!hasAny) {
      setFeedback({ type: 'err', text: t('En az bir alan doldurmalısınız.', 'Fill at least one field.') });
      return;
    }
    setSaving(true);
    setFeedback(null);
    try {
      const res = await apiAdminAddDatasetRecord(meta.id, newRecDraft);
      setMeta(res.dataset);
      setNewRecDraft(EMPTY_RECORD_FORM);
      setAddPanelMode('none');
      await loadRecords(meta.id, searchQuery.trim(), 1);
      setPage(1);
      await onDatasetChanged(meta.id);
      setFeedback({ type: 'ok', text: t('Yeni kayıt depoya eklendi.', 'New record added to dataset.') });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Kayıt eklenemedi.', 'Failed to add record.'),
      });
    } finally {
      setSaving(false);
    }
  };

  const handleAppendBulkLines = async () => {
    const raw = appendRawText.trim();
    if (!raw) {
      setFeedback({ type: 'err', text: t('Eklenecek veri satırı girin.', 'Enter data lines to append.') });
      return;
    }
    setSaving(true);
    setFeedback(null);
    try {
      const parsed = parseDatasetContent(raw);
      const normalized = normalizeRows(parsed.rows, parsed.suggestedMapping, meta.id, meta.name);
      if (normalized.length === 0) {
        setFeedback({ type: 'err', text: t('Ayrıştırılacak geçerli satır bulunamadı.', 'No valid rows parsed.') });
        setSaving(false);
        return;
      }
      const res = await apiAdminUpdateDataset(meta.id, { appendRecords: normalized });
      setMeta(res.dataset);
      setAppendRawText('');
      setAddPanelMode('none');
      await loadRecords(meta.id, searchQuery.trim(), 1);
      setPage(1);
      await onDatasetChanged(meta.id);
      setFeedback({
        type: 'ok',
        text: t(`${normalized.length} yeni kayıt mevcut depoya eklendi.`, `${normalized.length} new records appended.`),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Veri eklenemedi.', 'Failed to append data.'),
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="dataset-editor-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-xs"
    >
      <div className="flex max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-6 py-4 dark:border-slate-800">
          <div>
            <h2 id="dataset-editor-title" className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              {t('Veri Deposunu Düzenle:', 'Edit Dataset:')} {meta.name}
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              {meta.recordCount.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')} {t('kayıt', 'records')} ·{' '}
              <span className="font-mono uppercase">{meta.format}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="inline-flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80">
              <button
                type="button"
                onClick={() => setTab('records')}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                  tab === 'records'
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
                }`}
              >
                {t('Kayıtları Düzenle & Ekle', 'Edit & Add Records')}
              </button>
              <button
                type="button"
                onClick={() => setTab('settings')}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                  tab === 'settings'
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
                }`}
              >
                {t('Ad & Yeniden Filtrele', 'Rename & Re-Filter')}
              </button>
            </div>

            <button
              type="button"
              onClick={onClose}
              aria-label={t('Düzenleme penceresini kapat', 'Close editor modal')}
              className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {feedback && (
            <div
              role="status"
              className={`flex items-center gap-2 rounded-lg border p-3 text-xs ${
                feedback.type === 'ok'
                  ? 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300'
                  : 'border-red-200 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300'
              }`}
            >
              {feedback.type === 'ok' ? (
                <CheckCircle2 className="h-4 w-4 shrink-0" />
              ) : (
                <AlertCircle className="h-4 w-4 shrink-0" />
              )}
              <span>{feedback.text}</span>
            </div>
          )}

          {tab === 'settings' && mapping && (
            <div className="space-y-5">
              <div>
                <label htmlFor="edit-dataset-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  {t('Depo Adı (Yalnızca Admin Görür)', 'Dataset Name (Admin Only)')}
                </label>
                <input
                  id="edit-dataset-name"
                  type="text"
                  value={nameInput}
                  onChange={(e) => setNameInput(e.target.value)}
                  className="mt-1.5 w-full max-w-md rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 text-xs text-slate-900 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <h3 className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  {t('Sütun Eşleştirme ve Yeniden Filtreleme', 'Column Mapping & Re-Normalization')}
                </h3>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  {t(
                    'Sütun eşleştirmelerini değiştirdiğinizde sistem tüm satırlardaki Discord ID, e-posta, IP ve telefon numaralarını yeniden çıkarır.',
                    'Updating column mappings re-extracts Discord IDs, emails, IPs, and phones across all rows in this dataset.',
                  )}
                </p>

                <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {mappingFields.map((field) => (
                    <div key={field.key}>
                      <label htmlFor={`edit-map-${field.key}`} className="block text-xs text-slate-500 dark:text-slate-400">
                        {field.label}
                      </label>
                      <select
                        id={`edit-map-${field.key}`}
                        value={mapping[field.key] || ''}
                        onChange={(e) =>
                          setMapping({
                            ...mapping,
                            [field.key]: e.target.value || null,
                          })
                        }
                        className="mt-1 w-full rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1.5 text-xs text-slate-900 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                      >
                        <option value="">{t('Eşleştirme yok', 'None')}</option>
                        {availableColumns.map((col) => (
                          <option key={col} value={col}>
                            {col}
                          </option>
                        ))}
                      </select>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  disabled={saving}
                  onClick={handleSaveMetaAndRenormalize}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${saving ? 'animate-spin' : ''}`} />
                  <span>{t('Değişiklikleri Kaydet ve Yeniden Filtrele', 'Save & Re-Filter Dataset')}</span>
                </button>
              </div>
            </div>
          )}

          {tab === 'records' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <form onSubmit={handleSearchSubmit} className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder={t('Depo içinde ID, e-posta, IP, tel ara...', 'Search ID, email, IP, phone...')}
                    className="w-72 max-w-full rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  />
                  <button
                    type="submit"
                    disabled={loading}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                  >
                    <Search className="h-3.5 w-3.5" />
                    <span>{t('Filtrele', 'Filter')}</span>
                  </button>
                </form>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setAddPanelMode((m) => (m === 'single' ? 'none' : 'single'))}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>{t('Tek Kayıt Ekle', 'Add Record')}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setAddPanelMode((m) => (m === 'bulk' ? 'none' : 'bulk'))}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-blue-300 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-100 dark:border-blue-800 dark:bg-blue-950/40 dark:text-blue-300"
                  >
                    <FilePlus2 className="h-3.5 w-3.5" />
                    <span>{t('Toplu Satır Ekle', 'Append Lines')}</span>
                  </button>
                </div>
              </div>

              {addPanelMode === 'single' && (
                <form
                  onSubmit={handleAddSingleRecord}
                  className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-3 dark:border-slate-700 dark:bg-slate-900/60"
                >
                  <div className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                    {t('Mevcut Depoya Yeni Kayıt Ekle', 'Add New Record to Dataset')}
                  </div>
                  <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3 lg:grid-cols-4">
                    <input
                      type="text"
                      value={newRecDraft.discordId}
                      onChange={(e) => setNewRecDraft({ ...newRecDraft, discordId: e.target.value })}
                      placeholder="Discord ID"
                      className="rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                    />
                    <input
                      type="text"
                      value={newRecDraft.email}
                      onChange={(e) => setNewRecDraft({ ...newRecDraft, email: e.target.value })}
                      placeholder={t('E-posta', 'Email')}
                      className="rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                    />
                    <input
                      type="text"
                      value={newRecDraft.username}
                      onChange={(e) => setNewRecDraft({ ...newRecDraft, username: e.target.value })}
                      placeholder={t('Kullanıcı Adı', 'Username')}
                      className="rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs dark:border-slate-700 dark:bg-slate-900"
                    />
                    <input
                      type="text"
                      value={newRecDraft.source}
                      onChange={(e) => setNewRecDraft({ ...newRecDraft, source: e.target.value })}
                      placeholder={t('Kaynak', 'Source')}
                      className="rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs dark:border-slate-700 dark:bg-slate-900"
                    />
                    <input
                      type="text"
                      value={newRecDraft.ip}
                      onChange={(e) => setNewRecDraft({ ...newRecDraft, ip: e.target.value })}
                      placeholder="IP"
                      className="rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                    />
                    <input
                      type="text"
                      value={newRecDraft.phone}
                      onChange={(e) => setNewRecDraft({ ...newRecDraft, phone: e.target.value })}
                      placeholder={t('Telefon', 'Phone')}
                      className="rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                    />
                    <input
                      type="text"
                      value={newRecDraft.notes}
                      onChange={(e) => setNewRecDraft({ ...newRecDraft, notes: e.target.value })}
                      placeholder={t('Notlar', 'Notes')}
                      className="sm:col-span-2 rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs dark:border-slate-700 dark:bg-slate-900"
                    />
                  </div>
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setAddPanelMode('none')}
                      className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 dark:border-slate-700 dark:text-slate-300"
                    >
                      {t('İptal', 'Cancel')}
                    </button>
                    <button
                      type="submit"
                      disabled={saving}
                      className="rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      {t('Kaydı Ekle', 'Add Record')}
                    </button>
                  </div>
                </form>
              )}

              {addPanelMode === 'bulk' && (
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-2.5 dark:border-slate-700 dark:bg-slate-900/60">
                  <div className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                    {t('Mevcut Depoya Toplu Satır / JSON / CSV / SQL Ekle', 'Append Raw Lines / JSON / CSV / SQL to Dataset')}
                  </div>
                  <textarea
                    rows={4}
                    value={appendRawText}
                    onChange={(e) => setAppendRawText(e.target.value)}
                    placeholder={'104567890123456789:yeni@ornek.com:kullanici_yeni:KaynakX'}
                    className="w-full rounded-lg border border-slate-300 bg-white p-2.5 font-mono text-xs text-slate-900 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  />
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setAddPanelMode('none')}
                      className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 dark:border-slate-700 dark:text-slate-300"
                    >
                      {t('İptal', 'Cancel')}
                    </button>
                    <button
                      type="button"
                      disabled={saving}
                      onClick={handleAppendBulkLines}
                      className="rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      {t('Çözümle ve Depoya Ekle', 'Parse & Append')}
                    </button>
                  </div>
                </div>
              )}

              <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                {loading ? (
                  <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                    {t('Kayıtlar yükleniyor...', 'Loading records...')}
                  </div>
                ) : records.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                    {t('Bu depoda eşleşen kayıt bulunamadı.', 'No matching records in this dataset.')}
                  </div>
                ) : (
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                      <tr>
                        <th className="px-2.5 py-2 font-semibold">Discord ID</th>
                        <th className="px-2.5 py-2 font-semibold">{t('E-posta', 'Email')}</th>
                        <th className="px-2.5 py-2 font-semibold">{t('Kullanıcı', 'Username')}</th>
                        <th className="px-2.5 py-2 font-semibold">{t('Kaynak', 'Source')}</th>
                        <th className="px-2.5 py-2 font-semibold">IP / {t('Tel', 'Phone')}</th>
                        <th className="px-2.5 py-2 font-semibold">{t('Not', 'Notes')}</th>
                        <th className="px-2.5 py-2 text-right font-semibold">{t('İşlem', 'Action')}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                      {records.map((rec) => {
                        const isEditing = editingRecordId === rec.id;
                        if (isEditing) {
                          return (
                            <tr key={rec.id} className="bg-blue-50/40 dark:bg-blue-950/20">
                              <td className="px-2 py-2">
                                <input
                                  aria-label="Discord ID"
                                  type="text"
                                  value={editDraft.discordId}
                                  onChange={(e) => setEditDraft({ ...editDraft, discordId: e.target.value })}
                                  className="w-36 rounded border border-slate-300 bg-white px-2 py-1 font-mono text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                />
                              </td>
                              <td className="px-2 py-2">
                                <input
                                  aria-label={t('E-posta', 'Email')}
                                  type="text"
                                  value={editDraft.email}
                                  onChange={(e) => setEditDraft({ ...editDraft, email: e.target.value })}
                                  className="w-40 rounded border border-slate-300 bg-white px-2 py-1 font-mono text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                />
                              </td>
                              <td className="px-2 py-2">
                                <input
                                  aria-label={t('Kullanıcı Adı', 'Username')}
                                  type="text"
                                  value={editDraft.username}
                                  onChange={(e) => setEditDraft({ ...editDraft, username: e.target.value })}
                                  className="w-28 rounded border border-slate-300 bg-white px-2 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                />
                              </td>
                              <td className="px-2 py-2">
                                <input
                                  aria-label={t('Kaynak', 'Source')}
                                  type="text"
                                  value={editDraft.source}
                                  onChange={(e) => setEditDraft({ ...editDraft, source: e.target.value })}
                                  className="w-24 rounded border border-slate-300 bg-white px-2 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                />
                              </td>
                              <td className="px-2 py-2 space-y-1">
                                <input
                                  aria-label="IP"
                                  type="text"
                                  value={editDraft.ip}
                                  onChange={(e) => setEditDraft({ ...editDraft, ip: e.target.value })}
                                  placeholder="IP"
                                  className="w-28 rounded border border-slate-300 bg-white px-2 py-1 font-mono text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                />
                                <input
                                  aria-label={t('Telefon', 'Phone')}
                                  type="text"
                                  value={editDraft.phone}
                                  onChange={(e) => setEditDraft({ ...editDraft, phone: e.target.value })}
                                  placeholder={t('Telefon', 'Phone')}
                                  className="w-28 rounded border border-slate-300 bg-white px-2 py-1 font-mono text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                />
                              </td>
                              <td className="px-2 py-2">
                                <input
                                  aria-label={t('Notlar', 'Notes')}
                                  type="text"
                                  value={editDraft.notes}
                                  onChange={(e) => setEditDraft({ ...editDraft, notes: e.target.value })}
                                  className="w-32 rounded border border-slate-300 bg-white px-2 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                />
                              </td>
                              <td className="px-2 py-2 text-right whitespace-nowrap">
                                <div className="inline-flex items-center gap-1">
                                  <button
                                    type="button"
                                    disabled={saving}
                                    onClick={() => handleSaveEditRow(rec.id)}
                                    aria-label={t('Değişiklikleri kaydet', 'Save record')}
                                    className="inline-flex items-center gap-1 rounded bg-emerald-600 px-2 py-1 text-[11px] font-semibold text-white hover:bg-emerald-700"
                                  >
                                    <Check className="h-3 w-3" />
                                    <span>{t('Kaydet', 'Save')}</span>
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => setEditingRecordId(null)}
                                    aria-label={t('Düzenlemeyi iptal et', 'Cancel edit')}
                                    className="rounded border border-slate-300 px-2 py-1 text-[11px] dark:border-slate-700"
                                  >
                                    {t('İptal', 'Cancel')}
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        }

                        return (
                          <tr key={rec.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-2.5 py-2 font-mono whitespace-nowrap text-blue-600 dark:text-blue-400">
                              {rec.discordId || '—'}
                            </td>
                            <td className="max-w-[165px] truncate px-2.5 py-2 font-mono text-slate-800 dark:text-slate-200" title={rec.email}>
                              {rec.email || '—'}
                            </td>
                            <td className="max-w-[110px] truncate px-2.5 py-2 text-slate-700 dark:text-slate-300" title={rec.username}>
                              {rec.username || '—'}
                            </td>
                            <td className="max-w-[120px] truncate px-2.5 py-2 text-slate-600 dark:text-slate-400" title={rec.source}>
                              {rec.source || '—'}
                            </td>
                            <td className="max-w-[140px] truncate px-2.5 py-2 font-mono text-[11px] text-slate-600 dark:text-slate-400" title={[rec.ip, rec.phone].filter(Boolean).join(' · ')}>
                              {[rec.ip, rec.phone].filter(Boolean).join(' · ') || '—'}
                            </td>
                            <td className="max-w-[130px] truncate px-2.5 py-2 text-slate-500 dark:text-slate-400" title={rec.notes}>
                              {rec.notes || '—'}
                            </td>
                            <td className="px-2.5 py-2 text-right whitespace-nowrap">
                              <div className="inline-flex items-center gap-1">
                                <button
                                  type="button"
                                  onClick={() => handleStartEditRow(rec)}
                                  aria-label={`${t('Kaydı düzenle', 'Edit record')}: ${rec.discordId || rec.email || rec.id}`}
                                  className="inline-flex items-center gap-1 rounded border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                                >
                                  <Pencil className="h-3 w-3" />
                                  <span>{t('Düzenle', 'Edit')}</span>
                                </button>
                                <button
                                  type="button"
                                  disabled={saving}
                                  onClick={() => handleDeleteRow(rec.id)}
                                  aria-label={`${t('Kaydı sil', 'Delete record')}: ${rec.discordId || rec.email || rec.id}`}
                                  className="inline-flex items-center gap-1 rounded border border-slate-200 px-2 py-1 text-[11px] font-medium text-red-600 hover:bg-red-50 dark:border-slate-700 dark:text-red-400 dark:hover:bg-red-950/40"
                                >
                                  <Trash2 className="h-3 w-3" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>

              {totalPages > 1 && (
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                  <span>
                    {t('Sayfa', 'Page')} {page} / {totalPages} ({totalRecords}{' '}
                    {t('kayıt', 'records')})
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={page <= 1 || loading}
                      onClick={() => {
                        const prev = page - 1;
                        setPage(prev);
                        void loadRecords(meta.id, searchQuery.trim(), prev);
                      }}
                      className="rounded border border-slate-300 px-2.5 py-1 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:hover:bg-slate-800"
                    >
                      {t('Önceki', 'Previous')}
                    </button>
                    <button
                      type="button"
                      disabled={page >= totalPages || loading}
                      onClick={() => {
                        const next = page + 1;
                        setPage(next);
                        void loadRecords(meta.id, searchQuery.trim(), next);
                      }}
                      className="rounded border border-slate-300 px-2.5 py-1 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:hover:bg-slate-800"
                    >
                      {t('Sonraki', 'Next')}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
