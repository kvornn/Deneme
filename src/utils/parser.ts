import type { FieldMapping, IntelRecord } from '../types/intel';
import { isValidSnowflake } from './snowflake.ts';

export interface ParsedTableResult {
  format: 'json' | 'csv' | 'ndjson' | 'text';
  columns: string[];
  rows: Record<string, string>[];
  suggestedMapping: FieldMapping;
}

const DISCORD_ID_KEYS = [
  'discord_id',
  'discordid',
  'discrod_id',
  'dc_id',
  'dc',
  'userid',
  'user_id',
  'uid',
  'id',
  'snowflake',
  'account_id',
  'member_id',
  'author_id',
];
const EMAIL_KEYS = [
  'email',
  'e-mail',
  'eposta',
  'e_posta',
  'eposta_adresi',
  'mail',
  'mail_address',
  'email_address',
  'leaked_email',
  'contact_email',
];
const USERNAME_KEYS = [
  'username',
  'user',
  'name',
  'nick',
  'nickname',
  'handle',
  'tag',
  'discord_tag',
  'global_name',
  'kullanici',
  'kullanici_adi',
  'display_name',
];
const SOURCE_KEYS = ['source', 'breach', 'leak', 'origin', 'kaynak', 'database', 'db', 'platform', 'incident', 'site'];
const IP_KEYS = ['ip', 'ip_address', 'ipaddress', 'ip_adr', 'last_ip', 'ipv4', 'ipv6', 'reg_ip', 'login_ip'];
const PHONE_KEYS = ['phone', 'tel', 'telefon', 'telefon_no', 'phone_number', 'gsm', 'gsm_no', 'mobile', 'phonenumber', 'numara'];
const NOTES_KEYS = ['notes', 'note', 'info', 'details', 'not', 'aciklama', 'metadata', 'extra', 'comment'];

const SNOWFLAKE_INLINE_RE = /(?<!\d)(\d{17,20})(?!\d)/;
const SNOWFLAKE_GLOBAL_RE = /(?<!\d)(\d{17,20})(?!\d)/g;
const EMAIL_INLINE_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const EMAIL_GLOBAL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const IPV4_INLINE_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;
const IPV4_GLOBAL_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const PHONE_CANDIDATE_RE = /(?:\+?\d[\d\s\-()]{7,19}\d)/g;

function cleanInvisibleChars(str: string): string {
  return str.replace(/[\u200B-\u200D\uFEFF]/g, '').trim();
}

function stringifyCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return cleanInvisibleChars(value);
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value).trim();
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function flattenObject(obj: Record<string, unknown>, prefix = ''): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const nested = flattenObject(value as Record<string, unknown>, fullKey);
      Object.assign(out, nested);
    } else {
      out[fullKey] = stringifyCell(value);
    }
  }
  return out;
}

function parseCsvLine(line: string, delimiter: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === delimiter && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current.trim());
  return result;
}

function detectDelimiter(lines: string[]): string {
  const candidates = [',', ';', '\t', '|', ':'];
  const sample = lines.slice(0, 15);
  let bestDelim = ',';
  let bestScore = -1;

  for (const delim of candidates) {
    const counts = sample.map((l) => parseCsvLine(l, delim).length);
    const minCount = Math.min(...counts);
    const maxCount = Math.max(...counts);
    if (minCount >= 2) {
      const consistency = minCount === maxCount ? 100 : 10;
      const priority = delim === ',' ? 5 : delim === ';' ? 4 : delim === '\t' ? 3 : delim === '|' ? 2 : 1;
      const score = consistency + minCount * 2 + priority;
      if (score > bestScore) {
        bestScore = score;
        bestDelim = delim;
      }
    }
  }

  return bestDelim;
}

function isLikelyHeaderRow(cells: string[]): boolean {
  if (
    cells.some((c) => {
      const t = c.trim();
      if (!t) return false;
      if (t.startsWith('{') || t.startsWith('[')) return true;
      if (/^[a-zA-ZçğıöşüÇĞİÖŞÜ0-9_.-]{2,24}\s*[:=]\s*\S+/.test(t)) return true;
      const sfMatch = t.match(SNOWFLAKE_INLINE_RE);
      if (sfMatch && isValidSnowflake(sfMatch[1])) return true;
      if (EMAIL_INLINE_RE.test(t) || IPV4_INLINE_RE.test(t)) return true;
      const phones = t.match(PHONE_CANDIDATE_RE) || [];
      if (phones.some((p) => isValidPhoneCandidate(p))) return true;
      return false;
    })
  ) {
    return false;
  }

  const knownHeaders = new Set([
    ...DISCORD_ID_KEYS,
    ...EMAIL_KEYS,
    ...USERNAME_KEYS,
    ...SOURCE_KEYS,
    ...IP_KEYS,
    ...PHONE_KEYS,
    ...NOTES_KEYS,
    'password',
    'hash',
    'created_at',
    'date',
  ]);
  const lowered = cells.map((c) => c.toLowerCase().replace(/\s+/g, '_'));
  return lowered.some((c) => knownHeaders.has(c));
}

export function isValidPhoneCandidate(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) return false;
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length < 9 || digits.length > 15) return false;
  if (IPV4_INLINE_RE.test(trimmed)) return false;
  if (isValidSnowflake(digits)) return false;
  // Reject dotted/dashed date strings like 2024-05-12
  if (/^\d{4}[-/.]\d{2}[-/.]\d{2}$/.test(trimmed)) return false;
  return true;
}

function splitSqlTuples(valuesClause: string): string[][] {
  const tuples: string[][] = [];
  let i = 0;
  const len = valuesClause.length;

  while (i < len) {
    if (valuesClause[i] !== '(') {
      i++;
      continue;
    }
    i++; // skip '('
    const row: string[] = [];
    let current = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let depth = 0;

    while (i < len) {
      const ch = valuesClause[i];
      if (inSingleQuote) {
        if (ch === '\\' && i + 1 < len) {
          current += valuesClause[i + 1];
          i += 2;
          continue;
        }
        if (ch === "'" && valuesClause[i + 1] === "'") {
          current += "'";
          i += 2;
          continue;
        }
        if (ch === "'") {
          inSingleQuote = false;
        } else {
          current += ch;
        }
        i++;
        continue;
      }
      if (inDoubleQuote) {
        if (ch === '\\' && i + 1 < len) {
          current += valuesClause[i + 1];
          i += 2;
          continue;
        }
        if (ch === '"') {
          inDoubleQuote = false;
        } else {
          current += ch;
        }
        i++;
        continue;
      }

      if (ch === "'") {
        inSingleQuote = true;
      } else if (ch === '"') {
        inDoubleQuote = true;
      } else if (ch === '(') {
        depth++;
        current += ch;
      } else if (ch === ')') {
        if (depth === 0) {
          const val = current.trim();
          row.push(/^null$/i.test(val) ? '' : val);
          i++;
          break;
        }
        depth--;
        current += ch;
      } else if (ch === ',' && depth === 0) {
        const val = current.trim();
        row.push(/^null$/i.test(val) ? '' : val);
        current = '';
      } else {
        current += ch;
      }
      i++;
    }
    if (row.length > 0) {
      tuples.push(row);
    }
  }
  return tuples;
}

function tryParseSqlInserts(text: string): ParsedTableResult | null {
  const headerRe = /INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?[\w.-]+[`"\]]?(?:\s*\(([^)]+)\))?\s+VALUES\s*/gi;
  const rows: Record<string, string>[] = [];
  const colSet = new Set<string>();

  let match: RegExpExecArray | null;
  while ((match = headerRe.exec(text)) !== null) {
    const rawCols = match[1]
      ? match[1]
          .split(',')
          .map((c) => c.replace(/[`"\[\]\s]/g, ''))
          .filter(Boolean)
      : null;

    const valuesStart = match.index + match[0].length;
    const nextInsertIdx = text.slice(valuesStart).search(/;\s*INSERT\s+/i);
    const semiIdx = text.indexOf(';', valuesStart);
    const valuesEnd =
      semiIdx !== -1
        ? semiIdx
        : nextInsertIdx !== -1
          ? valuesStart + nextInsertIdx
          : text.length;

    const valuesSlice = text.slice(valuesStart, valuesEnd);
    const tuples = splitSqlTuples(valuesSlice);
    for (const tuple of tuples) {
      const cols = rawCols && rawCols.length >= tuple.length
        ? rawCols
        : tuple.map((_, idx) => (rawCols && rawCols[idx]) || `sutun_${idx + 1}`);
      const obj: Record<string, string> = {};
      for (let idx = 0; idx < tuple.length; idx++) {
        const colName = cols[idx] || `sutun_${idx + 1}`;
        colSet.add(colName);
        obj[colName] = cleanInvisibleChars(tuple[idx] || '');
      }
      rows.push(obj);
    }
    headerRe.lastIndex = Math.max(headerRe.lastIndex, valuesEnd);
  }

  if (rows.length === 0) return null;
  const columns = Array.from(colSet);
  return {
    format: 'text',
    columns,
    rows,
    suggestedMapping: detectFieldMapping(columns, rows),
  };
}

function isHeterogeneousText(lines: string[], delimiter: string, parsedLines: string[][]): boolean {
  if (lines.length === 0) return false;
  const sample = lines.slice(0, 50);

  // Mixed JSON object lines alongside plain/delimited lines
  const hasJsonLine = sample.some((l) => l.startsWith('{') && l.endsWith('}'));
  if (hasJsonLine) return true;

  const sampleParsed = parsedLines.slice(0, 50);
  const colCounts = sampleParsed.map((c) => c.length);
  const minCols = Math.min(...colCounts);
  const maxCols = Math.max(...colCounts);

  // Unstructured or multi-delimiter lines
  if (minCols < 2 && maxCols <= 1) {
    return sample.some(
      (l) =>
        SNOWFLAKE_INLINE_RE.test(l) ||
        EMAIL_INLINE_RE.test(l) ||
        IPV4_INLINE_RE.test(l) ||
        /[;|,\t:]/.test(l),
    );
  }

  // Varying column counts across lines
  const modeCount = [...colCounts]
    .sort((a, b) => colCounts.filter((v) => v === b).length - colCounts.filter((v) => v === a).length)[0];
  const consistentRatio = sampleParsed.filter((c) => c.length === modeCount).length / sampleParsed.length;
  if (consistentRatio < 0.75 || maxCols - minCols > 1) {
    return true;
  }

  // Even when column count matches, if ANY column mixes Snowflakes and Emails across rows, treat as heterogeneous
  for (let colIdx = 0; colIdx < maxCols; colIdx++) {
    let sawSnowflake = false;
    let sawEmail = false;
    for (const cells of sampleParsed) {
      const cell = (cells[colIdx] || '').trim();
      if (!cell) continue;
      if (isValidSnowflake(cell)) sawSnowflake = true;
      if (EMAIL_INLINE_RE.test(cell)) sawEmail = true;
    }
    if (sawSnowflake && sawEmail) {
      return true;
    }
  }

  const otherDelims = [',', ';', '\t', '|', ':'].filter((d) => d !== delimiter);
  for (const cells of sampleParsed) {
    if (cells.length === 1 && otherDelims.some((d) => cells[0].includes(d))) {
      return true;
    }
  }

  return false;
}

function detectBestLineDelimiter(line: string): string | null {
  const candidates = ['\t', '|', ';', ',', ':'];
  let best: string | null = null;
  let bestCount = 1;
  for (const d of candidates) {
    const count = parseCsvLine(line, d).length;
    if (count > bestCount) {
      bestCount = count;
      best = d;
    }
  }
  return best;
}

function extractByKeys(
  flat: Record<string, string>,
  keys: string[],
  exclude: Set<string> = new Set(),
): { value: string; matchedKey: string | null } {
  for (const [k, v] of Object.entries(flat)) {
    if (exclude.has(k) || !v.trim()) continue;
    const norm = k.toLowerCase().replace(/[\s.-]+/g, '_');
    const lastSeg = k.split('.').pop()?.toLowerCase().replace(/[\s-]+/g, '_') || norm;
    if (keys.includes(norm) || keys.includes(lastSeg)) {
      return { value: v.trim(), matchedKey: k };
    }
  }
  for (const [k, v] of Object.entries(flat)) {
    if (exclude.has(k) || !v.trim()) continue;
    const lastSeg = (k.split('.').pop() || k).toLowerCase().replace(/[\s-]+/g, '_');
    if (keys.some((cand) => cand.length >= 4 && lastSeg.includes(cand))) {
      return { value: v.trim(), matchedKey: k };
    }
  }
  return { value: '', matchedKey: null };
}

function parseMixedSingleLine(line: string): Record<string, string> {
  // Case A: Single JSON object line inside a mixed file
  if (line.startsWith('{') && line.endsWith('}')) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const flat = flattenObject(parsed as Record<string, unknown>);
        const usedKeys = new Set<string>();

        const idPick = extractByKeys(flat, DISCORD_ID_KEYS, usedKeys);
        const idInline = idPick.value.match(SNOWFLAKE_INLINE_RE)?.[1] || '';
        let resolvedId = isValidSnowflake(idInline) ? idInline : '';
        if (resolvedId && idPick.matchedKey) {
          usedKeys.add(idPick.matchedKey);
        } else if (!resolvedId) {
          for (const [fk, fv] of Object.entries(flat)) {
            const m = fv.match(SNOWFLAKE_INLINE_RE);
            if (m && isValidSnowflake(m[1])) {
              resolvedId = m[1];
              if (fv.trim() === m[1]) usedKeys.add(fk);
              break;
            }
          }
        }

        const emailPick = extractByKeys(flat, EMAIL_KEYS, usedKeys);
        let resolvedEmail = EMAIL_INLINE_RE.test(emailPick.value) ? (emailPick.value.match(EMAIL_INLINE_RE)?.[0] || '') : '';
        if (resolvedEmail && emailPick.matchedKey) {
          usedKeys.add(emailPick.matchedKey);
        } else if (!resolvedEmail) {
          for (const [fk, fv] of Object.entries(flat)) {
            if (usedKeys.has(fk)) continue;
            const m = fv.match(EMAIL_INLINE_RE);
            if (m) {
              resolvedEmail = m[0];
              if (fv.trim().toLowerCase() === m[0].toLowerCase()) usedKeys.add(fk);
              break;
            }
          }
        }

        const ipPick = extractByKeys(flat, IP_KEYS, usedKeys);
        let resolvedIp = IPV4_INLINE_RE.test(ipPick.value) ? (ipPick.value.match(IPV4_INLINE_RE)?.[0] || '') : '';
        if (resolvedIp && ipPick.matchedKey) {
          usedKeys.add(ipPick.matchedKey);
        } else if (!resolvedIp) {
          for (const [fk, fv] of Object.entries(flat)) {
            if (usedKeys.has(fk)) continue;
            const m = fv.match(IPV4_INLINE_RE);
            if (m) {
              resolvedIp = m[0];
              if (fv.trim() === m[0]) usedKeys.add(fk);
              break;
            }
          }
        }

        const phonePick = extractByKeys(flat, PHONE_KEYS, usedKeys);
        let resolvedPhone = isValidPhoneCandidate(phonePick.value) ? phonePick.value : '';
        if (resolvedPhone && phonePick.matchedKey) {
          usedKeys.add(phonePick.matchedKey);
        } else if (!resolvedPhone) {
          for (const [fk, fv] of Object.entries(flat)) {
            if (usedKeys.has(fk)) continue;
            const matches = fv.match(PHONE_CANDIDATE_RE) || [];
            const hit = matches.find((cand) => isValidPhoneCandidate(cand));
            if (hit) {
              resolvedPhone = hit.trim();
              if (fv.trim() === resolvedPhone) usedKeys.add(fk);
              break;
            }
          }
        }

        const userPick = extractByKeys(flat, USERNAME_KEYS, usedKeys);
        if (userPick.matchedKey) usedKeys.add(userPick.matchedKey);

        const sourcePick = extractByKeys(flat, SOURCE_KEYS, usedKeys);
        if (sourcePick.matchedKey) usedKeys.add(sourcePick.matchedKey);

        const notePick = extractByKeys(flat, NOTES_KEYS, usedKeys);
        if (notePick.matchedKey) usedKeys.add(notePick.matchedKey);

        const extraPairs: string[] = [];
        const extraMap: Record<string, string> = {};
        if (notePick.value) extraPairs.push(notePick.value);
        for (const [k, v] of Object.entries(flat)) {
          if (!usedKeys.has(k) && v.trim()) {
            const cleanedVal = v.trim();
            extraPairs.push(`${k}: ${cleanedVal}`);
            extraMap[k] = cleanedVal;
          }
        }

        const outRow: Record<string, string> = {
          discord_id: resolvedId,
          email: resolvedEmail,
          username: userPick.value,
          source: sourcePick.value,
          ip: resolvedIp,
          phone: resolvedPhone,
          notes: extraPairs.join(' | '),
        };
        if (Object.keys(extraMap).length > 0) {
          outRow.__extra_json = JSON.stringify(extraMap);
        }
        return outRow;
      }
    } catch {
      // Fall through to general mixed line parsing
    }
  }

  // Case B: Delimited or free-text line
  const lineDelim = detectBestLineDelimiter(line);
  const rawTokens = lineDelim ? parseCsvLine(line, lineDelim) : line.split(/\s+/);
  const tokens = rawTokens.map((t) => cleanInvisibleChars(t)).filter(Boolean);

  const snowflakes = (line.match(SNOWFLAKE_GLOBAL_RE) || []).filter((s) => isValidSnowflake(s));
  const emails = line.match(EMAIL_GLOBAL_RE) || [];
  const ips = line.match(IPV4_GLOBAL_RE) || [];
  const phones = (line.match(PHONE_CANDIDATE_RE) || []).map((p) => p.trim()).filter(isValidPhoneCandidate);

  const discordId = snowflakes[0] || '';
  const email = emails[0] || '';
  const ip = ips[0] || '';
  const phone = phones[0] || '';

  let username = '';
  let source = '';
  const leftoverNotes: string[] = [];
  const extractedKv: Record<string, string> = {};

  for (const tok of tokens) {
    const kvMatch = tok.match(/^([a-zA-ZçğıöşüÇĞİÖŞÜ0-9_.-]{2,24})\s*[:=]\s*(.+)$/);
    if (kvMatch) {
      const k = kvMatch[1].toLowerCase();
      const v = kvMatch[2].trim();
      if (DISCORD_ID_KEYS.includes(k) && isValidSnowflake(v.match(SNOWFLAKE_INLINE_RE)?.[1] || '')) continue;
      if (EMAIL_KEYS.includes(k) && EMAIL_INLINE_RE.test(v)) continue;
      if (IP_KEYS.includes(k) && IPV4_INLINE_RE.test(v)) continue;
      if (PHONE_KEYS.includes(k) && isValidPhoneCandidate(v)) continue;
      if (!username && USERNAME_KEYS.includes(k)) {
        username = v;
        continue;
      }
      if (!source && SOURCE_KEYS.includes(k)) {
        source = v;
        continue;
      }
      if (v && !/^https?$/i.test(k)) {
        extractedKv[k] = v;
      }
    }

    if (discordId && (tok === discordId || tok === `<@${discordId}>` || tok === `<@!${discordId}>`)) continue;
    if (email && tok.toLowerCase() === email.toLowerCase()) continue;
    if (ip && tok === ip) continue;
    if (phone && tok === phone) continue;

    if (
      (SNOWFLAKE_INLINE_RE.test(tok) && isValidSnowflake(tok.match(SNOWFLAKE_INLINE_RE)?.[1] || '')) ||
      EMAIL_INLINE_RE.test(tok) ||
      IPV4_INLINE_RE.test(tok)
    ) {
      leftoverNotes.push(tok);
      continue;
    }

    const cleanTok = tok.replace(/^[@#]/, '');
    const isSourceLike =
      /(leak|breach|dump|forum|db|database|shop|combo|list|logs|20\d{2})/i.test(tok) &&
      tok.length <= 48 &&
      !/\s/.test(tok);

    if (isSourceLike && !source) {
      source = tok;
      continue;
    }

    if (
      lineDelim &&
      !username &&
      /^[a-zA-Z0-9_.-]{3,32}(?:#\d{4})?$/.test(cleanTok) &&
      !/^\d+$/.test(cleanTok) &&
      !/^(and|or|with|mail|email|ip|tel|phone|id|user|from|hash|null|none)$/i.test(cleanTok)
    ) {
      username = tok;
      continue;
    }

    leftoverNotes.push(tok);
  }

  for (const extraId of snowflakes.slice(1)) {
    if (!leftoverNotes.some((n) => n.includes(extraId))) leftoverNotes.push(extraId);
  }
  for (const extraMail of emails.slice(1)) {
    if (!leftoverNotes.some((n) => n.toLowerCase().includes(extraMail.toLowerCase()))) leftoverNotes.push(extraMail);
  }
  for (const extraIp of ips.slice(1)) {
    if (!leftoverNotes.some((n) => n.includes(extraIp))) leftoverNotes.push(extraIp);
  }

  const outRow: Record<string, string> = {
    discord_id: discordId,
    email,
    username,
    source,
    ip,
    phone,
    notes: leftoverNotes.join(' | '),
  };
  if (Object.keys(extractedKv).length > 0) {
    outRow.__extra_json = JSON.stringify(extractedKv);
  }
  return outRow;
}

export function detectFieldMapping(columns: string[], rows: Record<string, string>[]): FieldMapping {
  const findByName = (candidates: string[], exclude: Set<string>): string | null => {
    const normalizedMap = new Map<string, string>();
    const leafMap = new Map<string, string>();
    for (const col of columns) {
      normalizedMap.set(col.toLowerCase().replace(/[\s.-]+/g, '_'), col);
      const leaf = col.split('.').pop()?.toLowerCase().replace(/[\s-]+/g, '_');
      if (leaf && !leafMap.has(leaf)) leafMap.set(leaf, col);
    }
    for (const candidate of candidates) {
      const match = normalizedMap.get(candidate) || leafMap.get(candidate);
      if (match && !exclude.has(match)) return match;
    }
    for (const col of columns) {
      if (exclude.has(col)) continue;
      const leaf = (col.split('.').pop() || col).toLowerCase().replace(/[\s-]+/g, '_');
      if (candidates.some((cand) => cand.length >= 4 && leaf.includes(cand))) {
        return col;
      }
    }
    return null;
  };

  const used = new Set<string>();
  let discordIdField = findByName(DISCORD_ID_KEYS, used);
  if (discordIdField) used.add(discordIdField);

  let emailField = findByName(EMAIL_KEYS, used);
  if (emailField) used.add(emailField);

  let usernameField = findByName(USERNAME_KEYS, used);
  if (usernameField) used.add(usernameField);

  const sourceField = findByName(SOURCE_KEYS, used);
  if (sourceField) used.add(sourceField);

  let ipField = findByName(IP_KEYS, used);
  if (ipField) used.add(ipField);

  let phoneField = findByName(PHONE_KEYS, used);
  if (phoneField) used.add(phoneField);

  const notesField = findByName(NOTES_KEYS, used);
  if (notesField) used.add(notesField);

  const sampleRows = rows.slice(0, 25);
  if (!discordIdField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => isValidSnowflake((r[col] || '').match(SNOWFLAKE_INLINE_RE)?.[1] || '')).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        discordIdField = col;
        used.add(col);
        break;
      }
    }
  }

  if (!emailField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => EMAIL_INLINE_RE.test((r[col] || '').trim())).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        emailField = col;
        used.add(col);
        break;
      }
    }
  }

  if (!ipField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => IPV4_INLINE_RE.test((r[col] || '').trim())).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        ipField = col;
        used.add(col);
        break;
      }
    }
  }

  if (!phoneField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => isValidPhoneCandidate(r[col] || '')).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        phoneField = col;
        used.add(col);
        break;
      }
    }
  }

  const NON_USERNAME_FALLBACK_COLS = new Set([
    'password', 'pass', 'pw', 'hash', 'salt', 'token', 'secret', 'key', 'cookie',
    'session', 'address', 'city', 'country', 'created_at', 'updated_at', 'date',
    'timestamp', 'bio', 'auth_token', 'access_token', 'discord_id', 'userid',
    'user_id', 'uid', 'email', 'mail', 'ip', 'ip_address', 'phone', 'tel', 'url', 'avatar',
  ]);
  if (!usernameField && columns.length > 0) {
    for (const col of columns) {
      const normCol = col.toLowerCase().replace(/[\s.-]+/g, '_');
      if (!used.has(col) && !NON_USERNAME_FALLBACK_COLS.has(normCol)) {
        usernameField = col;
        used.add(col);
        break;
      }
    }
  }

  return {
    discordIdField,
    emailField,
    usernameField,
    sourceField,
    ipField,
    phoneField,
    notesField,
  };
}

export function parseDatasetContent(rawText: string, fileName?: string): ParsedTableResult {
  const text = rawText.replace(/^\uFEFF/, '').trim();
  if (!text) {
    throw new Error('İçe aktarılacak veri içeriği boş.');
  }

  // 0. SQL INSERT dumps (.sql or raw INSERT INTO statements)
  if (
    fileName?.toLowerCase().endsWith('.sql') ||
    /INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?[\w.-]+[`"\]]?[\s\S]+VALUES\s*\(/i.test(text.slice(0, 4000))
  ) {
    const sqlResult = tryParseSqlInserts(text);
    if (sqlResult) return sqlResult;
  }

  // 1. Try JSON or pure NDJSON
  if (
    text.startsWith('{') ||
    text.startsWith('[') ||
    fileName?.toLowerCase().endsWith('.json') ||
    fileName?.toLowerCase().endsWith('.jsonl') ||
    fileName?.toLowerCase().endsWith('.ndjson')
  ) {
    try {
      const parsed = JSON.parse(text);
      let arrayData: unknown[] | null = null;
      if (Array.isArray(parsed)) {
        arrayData = parsed;
      } else if (parsed && typeof parsed === 'object') {
        const obj = parsed as Record<string, unknown>;
        for (const key of ['data', 'records', 'users', 'items', 'rows', 'results', 'entries']) {
          if (Array.isArray(obj[key])) {
            arrayData = obj[key] as unknown[];
            break;
          }
        }
        if (!arrayData) {
          arrayData = [obj];
        }
      }

      if (arrayData && arrayData.length > 0) {
        const rows = arrayData
          .filter((item): item is Record<string, unknown> => item !== null && typeof item === 'object' && !Array.isArray(item))
          .map((item) => flattenObject(item));
        if (rows.length > 0) {
          const colSet = new Set<string>();
          for (const r of rows) {
            for (const k of Object.keys(r)) colSet.add(k);
          }
          const columns = Array.from(colSet);
          return {
            format: 'json',
            columns,
            rows,
            suggestedMapping: detectFieldMapping(columns, rows),
          };
        }
      }
    } catch {
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const jsonObjects: Record<string, string>[] = [];
      let allJson = lines.length > 0;
      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
            jsonObjects.push(flattenObject(obj as Record<string, unknown>));
          } else {
            allJson = false;
            break;
          }
        } catch {
          allJson = false;
          break;
        }
      }
      if (allJson && jsonObjects.length > 0) {
        const colSet = new Set<string>();
        for (const r of jsonObjects) {
          for (const k of Object.keys(r)) colSet.add(k);
        }
        const columns = Array.from(colSet);
        return {
          format: 'ndjson',
          columns,
          rows: jsonObjects,
          suggestedMapping: detectFieldMapping(columns, jsonObjects),
        };
      }
    }
  }

  // 2. CSV / Delimited / Mixed Text
  const lines = text.split(/\r?\n/).map((l) => cleanInvisibleChars(l)).filter(Boolean);
  if (lines.length === 0) {
    throw new Error('Geçerli bir veri satırı bulunamadı.');
  }

  const delimiter = detectDelimiter(lines);
  const parsedLines = lines.map((line) => parseCsvLine(line, delimiter));

  if (isHeterogeneousText(lines, delimiter, parsedLines)) {
    const startIdx = parsedLines.length > 1 && isLikelyHeaderRow(parsedLines[0]) ? 1 : 0;
    const rows = lines.slice(startIdx).map((line) => parseMixedSingleLine(line));
    const columns = ['discord_id', 'email', 'username', 'source', 'ip', 'phone', 'notes'];
    return {
      format: 'text',
      columns,
      rows,
      suggestedMapping: {
        discordIdField: 'discord_id',
        emailField: 'email',
        usernameField: 'username',
        sourceField: 'source',
        ipField: 'ip',
        phoneField: 'phone',
        notesField: 'notes',
      },
    };
  }

  const maxCols = Math.max(...parsedLines.map((cells) => cells.length));
  let columns: string[];
  let dataStartIdx = 0;

  if (parsedLines.length > 1 && isLikelyHeaderRow(parsedLines[0])) {
    columns = parsedLines[0].map((col, idx) => col || `sutun_${idx + 1}`);
    dataStartIdx = 1;
  } else {
    columns = Array.from({ length: maxCols }, (_, idx) => `sutun_${idx + 1}`);
    dataStartIdx = 0;
  }

  const seenCols = new Map<string, number>();
  columns = columns.map((col) => {
    const count = seenCols.get(col) || 0;
    seenCols.set(col, count + 1);
    return count === 0 ? col : `${col}_${count + 1}`;
  });

  const rows: Record<string, string>[] = [];
  for (let i = dataStartIdx; i < parsedLines.length; i++) {
    const cells = parsedLines[i];
    if (cells.every((c) => !c)) continue;
    const rowObj: Record<string, string> = {};
    for (let c = 0; c < columns.length; c++) {
      rowObj[columns[c]] = cells[c] ?? '';
    }
    rows.push(rowObj);
  }

  if (rows.length === 0) {
    throw new Error('Veri satırları ayrıştırılamadı.');
  }

  const format = fileName?.toLowerCase().endsWith('.csv') || delimiter === ',' ? 'csv' : 'text';
  return {
    format,
    columns,
    rows,
    suggestedMapping: detectFieldMapping(columns, rows),
  };
}

export function normalizeRows(
  rows: Record<string, string>[],
  mapping: FieldMapping,
  datasetId: string,
  datasetName: string,
): IntelRecord[] {
  const mappedFields = new Set(
    [
      mapping.discordIdField,
      mapping.emailField,
      mapping.usernameField,
      mapping.sourceField,
      mapping.ipField,
      mapping.phoneField,
      mapping.notesField,
    ].filter((f): f is string => Boolean(f)),
  );

  return rows.map((row, idx) => {
    const extra: Record<string, string> = {};
    if (row.__extra_json) {
      try {
        const parsedExtra = JSON.parse(row.__extra_json) as Record<string, unknown>;
        if (parsedExtra && typeof parsedExtra === 'object' && !Array.isArray(parsedExtra)) {
          for (const [ek, ev] of Object.entries(parsedExtra)) {
            if (ek === '__proto__' || ek === 'constructor' || ek === 'prototype') continue;
            const cleanEv = cleanInvisibleChars(String(ev ?? ''));
            if (cleanEv) extra[ek] = cleanEv;
          }
        }
      } catch {
        // Ignore malformed internal extra payload
      }
    }
    for (const [key, val] of Object.entries(row)) {
      if (key === '__extra_json') continue;
      const cleaned = cleanInvisibleChars(val || '');
      if (!mappedFields.has(key) && cleaned !== '') {
        extra[key] = cleaned;
      }
    }

    const rawMappedDiscordId = mapping.discordIdField ? cleanInvisibleChars(row[mapping.discordIdField] || '') : '';
    let discordId = '';
    if (rawMappedDiscordId) {
      if (isValidSnowflake(rawMappedDiscordId)) {
        discordId = rawMappedDiscordId;
      } else {
        const inlineMatch = rawMappedDiscordId.match(SNOWFLAKE_INLINE_RE);
        if (inlineMatch && isValidSnowflake(inlineMatch[1])) {
          discordId = inlineMatch[1];
        } else {
          extra[mapping.discordIdField || 'raw_id'] = rawMappedDiscordId;
        }
      }
    }
    if (!discordId) {
      for (const val of Object.values(row)) {
        const match = (val || '').match(SNOWFLAKE_INLINE_RE);
        if (match && isValidSnowflake(match[1])) {
          discordId = match[1];
          break;
        }
      }
    }

    const rawMappedEmail = mapping.emailField ? cleanInvisibleChars(row[mapping.emailField] || '') : '';
    let email = '';
    if (rawMappedEmail) {
      const inlineMatch = rawMappedEmail.match(EMAIL_INLINE_RE);
      if (inlineMatch) {
        email = inlineMatch[0];
      } else {
        extra[mapping.emailField || 'raw_email'] = rawMappedEmail;
      }
    }
    if (!email) {
      for (const val of Object.values(row)) {
        const match = (val || '').match(EMAIL_INLINE_RE);
        if (match) {
          email = match[0];
          break;
        }
      }
    }

    const rawMappedIp = mapping.ipField ? cleanInvisibleChars(row[mapping.ipField] || '') : '';
    let ip = '';
    if (rawMappedIp) {
      const ipv4 = rawMappedIp.match(IPV4_INLINE_RE);
      if (ipv4) {
        ip = ipv4[0];
      } else if (rawMappedIp.includes(':') && /^[0-9a-fA-F:]+$/.test(rawMappedIp)) {
        ip = rawMappedIp;
      } else {
        extra[mapping.ipField || 'raw_ip'] = rawMappedIp;
      }
    }
    if (!ip) {
      for (const val of Object.values(row)) {
        const trimmed = (val || '').trim();
        const match = trimmed.match(IPV4_INLINE_RE);
        if (match) {
          ip = match[0];
          break;
        }
      }
    }

    const rawMappedPhone = mapping.phoneField ? cleanInvisibleChars(row[mapping.phoneField] || '') : '';
    let phone = '';
    if (rawMappedPhone) {
      if (isValidPhoneCandidate(rawMappedPhone)) {
        phone = rawMappedPhone;
      } else {
        const candidates = rawMappedPhone.match(PHONE_CANDIDATE_RE) || [];
        const hit = candidates.find((c) => isValidPhoneCandidate(c));
        if (hit) {
          phone = hit.trim();
        } else {
          extra[mapping.phoneField || 'raw_phone'] = rawMappedPhone;
        }
      }
    }
    if (!phone) {
      for (const [k, val] of Object.entries(row)) {
        if (k === mapping.discordIdField || k === mapping.ipField) continue;
        const candidates = (val || '').match(PHONE_CANDIDATE_RE) || [];
        const hit = candidates.find((c) => isValidPhoneCandidate(c));
        if (hit) {
          phone = hit.trim();
          break;
        }
      }
    }

    return {
      id: `${datasetId}_${idx}`,
      datasetId,
      datasetName,
      discordId,
      email,
      username: mapping.usernameField ? cleanInvisibleChars(row[mapping.usernameField] || '') : '',
      source: mapping.sourceField ? cleanInvisibleChars(row[mapping.sourceField] || '') : '',
      ip,
      phone,
      notes: mapping.notesField ? cleanInvisibleChars(row[mapping.notesField] || '') : '',
      extra,
    };
  });
}

export function reNormalizeDatasetRecords(
  records: IntelRecord[],
  oldMapping: FieldMapping | undefined,
  newMapping: FieldMapping,
  datasetId: string,
  datasetName: string,
): { records: IntelRecord[]; columns: string[] } {
  const colSet = new Set<string>();
  const idKey = oldMapping?.discordIdField || 'discordId';
  const emailKey = oldMapping?.emailField || 'email';
  const userKey = oldMapping?.usernameField || 'username';
  const sourceKey = oldMapping?.sourceField || 'source';
  const ipKey = oldMapping?.ipField || 'ip';
  const phoneKey = oldMapping?.phoneField || 'phone';
  const notesKey = oldMapping?.notesField || 'notes';

  const reconstructedRows: Record<string, string>[] = records.map((rec) => {
    const row: Record<string, string> = {};
    for (const [k, v] of Object.entries(rec.extra || {})) {
      if (v) {
        row[k] = v;
        colSet.add(k);
      }
    }
    if (rec.discordId) {
      row[idKey] = rec.discordId;
      colSet.add(idKey);
    }
    if (rec.email) {
      row[emailKey] = rec.email;
      colSet.add(emailKey);
    }
    if (rec.username) {
      row[userKey] = rec.username;
      colSet.add(userKey);
    }
    if (rec.source) {
      row[sourceKey] = rec.source;
      colSet.add(sourceKey);
    }
    if (rec.ip) {
      row[ipKey] = rec.ip;
      colSet.add(ipKey);
    }
    if (rec.phone) {
      row[phoneKey] = rec.phone;
      colSet.add(phoneKey);
    }
    if (rec.notes) {
      row[notesKey] = rec.notes;
      colSet.add(notesKey);
    }
    return row;
  });

  const normalized = normalizeRows(reconstructedRows, newMapping, datasetId, datasetName).map((normRec, idx) => ({
    ...normRec,
    id: records[idx]?.id || normRec.id,
  }));

  return {
    records: normalized,
    columns: Array.from(colSet),
  };
}
