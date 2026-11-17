import test from 'node:test';
import assert from 'node:assert/strict';
import type { IntelRecord } from '../types/intel';
import { decodeSnowflake, isValidSnowflake } from './snowflake';
import { parseDatasetContent, normalizeRows, reNormalizeDatasetRecords } from './parser';
import {
  searchRecords,
  runBulkLookup,
  buildSearchIndex,
  maskEmail,
  maskIp,
  classifyRecordDatabaseType,
  formatByteVolume,
} from './search';

test('Snowflake validation and decoding matches Discord spec', () => {
  // Official Discord sample Snowflake: 175928847299117063 -> 2016-04-30T11:18:25.796Z
  assert.equal(isValidSnowflake('175928847299117063'), true);
  assert.equal(isValidSnowflake('12345'), false);
  assert.equal(isValidSnowflake('not_an_id'), false);

  const info = decodeSnowflake('175928847299117063', Date.UTC(2026, 3, 30, 11, 18, 25));
  assert.ok(info);
  assert.equal(info.createdAtIso, '2016-04-30T11:18:25.796Z');
  assert.equal(info.workerId, 1);
  assert.equal(info.processId, 0);
  assert.equal(info.increment, 7);
  assert.equal(info.binary64.length, 64);
});

test('Parser auto-detects JSON, NDJSON, CSV, SQL INSERT dumps, and headerless colon-delimited lines', () => {
  const jsonText = JSON.stringify([
    { discord_id: '104567890123456789', email: 'ali@example.test', username: 'ali_x', source: 'LeakA' },
  ]);
  const parsedJson = parseDatasetContent(jsonText, 'sample.json');
  assert.equal(parsedJson.format, 'json');
  assert.equal(parsedJson.rows.length, 1);
  assert.equal(parsedJson.suggestedMapping.discordIdField, 'discord_id');
  assert.equal(parsedJson.suggestedMapping.emailField, 'email');

  const colonText = [
    '104567890123456789:test1@example.test:user_one:Forum2023',
    '452910384756192012:test2@demo.invalid:user_two:App2024',
  ].join('\n');
  const parsedColon = parseDatasetContent(colonText);
  assert.equal(parsedColon.rows.length, 2);
  assert.equal(parsedColon.suggestedMapping.discordIdField, 'sutun_1');
  assert.equal(parsedColon.suggestedMapping.emailField, 'sutun_2');

  const sqlDump = `
    INSERT INTO \`members\` (\`discord_id\`, \`email\`, \`username\`, \`ip\`) VALUES
    ('104567890123456789', 'sql.user@example.test', 'sql_nick', '198.51.100.42'),
    ('452910384756192012', 'other.sql@example.test', 'sql_other', '203.0.113.88');
  `;
  const parsedSql = parseDatasetContent(sqlDump, 'dump.sql');
  assert.equal(parsedSql.rows.length, 2);
  assert.equal(parsedSql.suggestedMapping.discordIdField, 'discord_id');
  assert.equal(parsedSql.suggestedMapping.emailField, 'email');
  const sqlRecs = normalizeRows(parsedSql.rows, parsedSql.suggestedMapping, 'ds_sql', 'SqlDump');
  assert.equal(sqlRecs[0].discordId, '104567890123456789');
  assert.equal(sqlRecs[0].email, 'sql.user@example.test');
  assert.equal(sqlRecs[0].ip, '198.51.100.42');
});

test('Search correlates primary Discord ID matches and cross-referenced records', () => {
  const raw = parseDatasetContent(
    [
      'discord_id,email,username,source,extra_note',
      '104567890123456789,shared@example.test,main_acc,SourceA,verified',
      '289104567890123456,shared@example.test,alt_acc,SourceB,linked',
      '803511102246789120,other@demo.invalid,other_acc,SourceC,unrelated',
    ].join('\n'),
    'test.csv',
  );
  const records = normalizeRows(raw.rows, raw.suggestedMapping, 'ds_1', 'TestCSV');

  const res = searchRecords(records, '104567890123456789', 'auto', false);
  assert.equal(res.detectedType, 'discord_id');
  assert.ok(res.snowflake);
  assert.equal(res.primaryMatches.length, 1);
  assert.equal(res.primaryMatches[0].email, 'shared@example.test');
  assert.equal(res.relatedMatches.length, 1);
  assert.equal(res.relatedMatches[0].discordId, '289104567890123456');

  // Transitive 2-hop correlation via external pool (e.g. email_osint pool)
  const pool = [
    ...records,
    {
      id: 'hop_2',
      datasetId: 'ds_2',
      datasetName: 'EmailPool',
      discordId: '',
      email: 'alt_only@example.test',
      username: 'alt_acc',
      source: 'ShopLeak',
      ip: '',
      phone: '',
      notes: '',
      extra: {},
    },
  ];
  const transitiveRes = searchRecords(records, '104567890123456789', 'discord_id', true, pool);
  assert.equal(transitiveRes.relatedMatches.length, 2);

  const bulk = runBulkLookup(records, '104567890123456789\n999999999999999999\ninvalid');
  assert.equal(bulk.length, 3);
  assert.equal(bulk[0].matches.length, 2);
  assert.equal(bulk[0].matches[0].discordId, '104567890123456789');
  assert.equal(bulk[1].validSnowflake, true);
  assert.equal(bulk[1].matches.length, 0);
  assert.equal(bulk[2].validSnowflake, false);
});

test('Multi-file SearchIndex correlates mentions, normalized phone variants, and ignores junk placeholders', () => {
  const multiFilePool: IntelRecord[] = [
    {
      id: 'f1_1',
      datasetId: 'ds_file1',
      datasetName: 'LogFile1',
      discordId: '',
      email: '',
      username: 'unknown',
      source: 'ChatLog',
      ip: '127.0.0.1',
      phone: '+90 555 111 22 33',
      notes: 'flagged mention <@!104567890123456789> in channel',
      extra: {},
    },
    {
      id: 'f2_1',
      datasetId: 'ds_file2',
      datasetName: 'ShopFile2',
      discordId: '',
      email: 'linked.buyer@example.test',
      username: 'real_buyer_x',
      source: 'ShopDB',
      ip: '198.51.100.77',
      phone: '05551112233',
      notes: '',
      extra: {},
    },
    {
      id: 'f3_1',
      datasetId: 'ds_file3',
      datasetName: 'ForumFile3',
      discordId: '',
      email: 'linked.buyer@example.test',
      username: 'forum_nick',
      source: 'ForumDB',
      ip: '',
      phone: '',
      notes: '',
      extra: { city: 'Izmir' },
    },
    {
      id: 'f4_junk',
      datasetId: 'ds_file4',
      datasetName: 'UnrelatedFile4',
      discordId: '999888777666555444',
      email: 'unrelated@example.test',
      username: 'unknown',
      source: 'OtherDB',
      ip: '127.0.0.1',
      phone: '',
      notes: '',
      extra: {},
    },
  ];

  const idx = buildSearchIndex(multiFilePool);
  const res = searchRecords(multiFilePool, '104567890123456789', 'discord_id', true, multiFilePool, idx);
  // Mention <@!104567890123456789> caught directly in f1_1
  assert.equal(res.primaryMatches.length, 1);
  assert.equal(res.primaryMatches[0].id, 'f1_1');
  // Phone +90 555 111 22 33 <-> 05551112233 links f2_1, email links f3_1, and junk unknown/127.0.0.1 does NOT link f4_junk
  const relatedIds = res.relatedMatches.map((r) => r.id).sort();
  assert.deepEqual(relatedIds, ['f2_1', 'f3_1']);
});

test('reNormalizeDatasetRecords updates mappings and extracts structured entities cleanly', () => {
  const initial: IntelRecord[] = [
    {
      id: 'renorm_1',
      datasetId: 'ds_r',
      datasetName: 'OldName',
      discordId: '',
      email: '',
      username: '',
      source: '',
      ip: '',
      phone: '',
      notes: '',
      extra: {
        uid: '104567890123456789',
        mail_col: 'remapped@example.test',
        raw_phone: '+905321112233',
      },
    },
  ];
  const oldMap = {
    discordIdField: null,
    emailField: null,
    usernameField: null,
    sourceField: null,
    ipField: null,
    phoneField: null,
    notesField: null,
  };
  const newMap = {
    discordIdField: 'uid',
    emailField: 'mail_col',
    usernameField: null,
    sourceField: null,
    ipField: null,
    phoneField: 'raw_phone',
    notesField: null,
  };
  const out = reNormalizeDatasetRecords(initial, oldMap, newMap, 'ds_r', 'NewName');
  assert.equal(out.records.length, 1);
  assert.equal(out.records[0].datasetName, 'NewName');
  assert.equal(out.records[0].discordId, '104567890123456789');
  assert.equal(out.records[0].email, 'remapped@example.test');
  assert.equal(out.records[0].phone, '+905321112233');
});

test('Email search correlates embedded extra fields and linked Discord IDs across databases', () => {
  const pool: IntelRecord[] = [
    {
      id: 'db1_0',
      datasetId: 'ds_a',
      datasetName: 'SecretDumpA',
      discordId: '104567890123456789',
      email: '',
      username: 'alpha_user',
      source: '',
      ip: '',
      phone: '',
      notes: 'backup mail: target.user@example.test',
      extra: {},
    },
    {
      id: 'db2_0',
      datasetId: 'ds_b',
      datasetName: 'SecretDumpB',
      discordId: '104567890123456789',
      email: '',
      username: 'alpha_user',
      source: '',
      ip: '198.51.100.77',
      phone: '+905551112233',
      notes: '',
      extra: { city: 'Ankara' },
    },
  ];
  const emailRes = searchRecords(pool, 'target.user@example.test', 'email', true, pool);
  assert.equal(emailRes.primaryMatches.length, 1);
  assert.equal(emailRes.relatedMatches.length, 1);
  assert.equal(emailRes.relatedMatches[0].ip, '198.51.100.77');
  assert.equal(emailRes.relatedMatches[0].phone, '+905551112233');
});

test('Heterogeneous mixed dump file auto-extracts IDs & Emails and filters accurately by query type', () => {
  const mixedDump = [
    '104567890123456789:ahmet.y@gmail.com:ahmet_dc:198.51.100.12:DiscordLeak2024',
    'caner.kaya@yahoo.com;caner_k;+905321112233;198.51.100.55;MailBreach2023',
    '{"discord_id":"104567890123456789","email":"ahmet.alt@proton.me","note":"ForumX"}',
    'random log line with 452910384756192012 and mail discord.alt@outlook.com ip 203.0.113.9',
    'unrelated@gmail.com|nobody_user|99.99.99.99|OtherLeak2022',
  ].join('\n');

  const parsed = parseDatasetContent(mixedDump, 'mixed_dump.txt');
  assert.equal(parsed.rows.length, 5);
  const records = normalizeRows(parsed.rows, parsed.suggestedMapping, 'ds_mix', 'MixedDump');

  // Row 2 is email-only; must NOT have an email string inside discordId
  assert.equal(records[1].discordId, '');
  assert.equal(records[1].email, 'caner.kaya@yahoo.com');
  assert.equal(records[1].phone, '+905321112233');
  assert.equal(records[1].ip, '198.51.100.55');

  // Row 3 (JSON line) & Row 4 (free-text line) cleanly extracted
  assert.equal(records[2].discordId, '104567890123456789');
  assert.equal(records[2].email, 'ahmet.alt@proton.me');
  assert.equal(records[3].discordId, '452910384756192012');
  assert.equal(records[3].email, 'discord.alt@outlook.com');
  assert.equal(records[3].ip, '203.0.113.9');

  // ID Lookup for 104567890123456789 returns ONLY the 2 rows matching that ID, excluding unrelated emails/IDs
  const idRes = searchRecords(records, '104567890123456789', 'discord_id', true, records);
  assert.equal(idRes.primaryMatches.length, 2);
  assert.equal(idRes.relatedMatches.length, 0);

  // Email search for caner.kaya@yahoo.com returns ONLY caner's row
  const emailRes = searchRecords(records, 'caner.kaya@yahoo.com', 'email', true, records);
  assert.equal(emailRes.primaryMatches.length, 1);
  assert.equal(emailRes.primaryMatches[0].phone, '+905321112233');
  assert.equal(emailRes.relatedMatches.length, 0);

  // Email search for ahmet.alt@proton.me finds JSON row + correlates to Discord ID row 1 via shared Discord ID
  const linkedEmailRes = searchRecords(records, 'ahmet.alt@proton.me', 'email', true, records);
  assert.equal(linkedEmailRes.primaryMatches.length, 1);
  assert.equal(linkedEmailRes.relatedMatches.length, 1);
  assert.equal(linkedEmailRes.relatedMatches[0].email, 'ahmet.y@gmail.com');
});

test('Credential/token columns stay in extra and are never mis-mapped as usernameField', () => {
  const csv = [
    'user_id,email,ip,token',
    '104567890123456789,member@example.test,198.51.100.14,secret_tok_991122',
  ].join('\n');
  const parsed = parseDatasetContent(csv, 'data_part_sample.csv');
  assert.equal(parsed.suggestedMapping.discordIdField, 'user_id');
  assert.equal(parsed.suggestedMapping.emailField, 'email');
  assert.equal(parsed.suggestedMapping.ipField, 'ip');
  assert.equal(parsed.suggestedMapping.usernameField, null);

  const normalized = normalizeRows(parsed.rows, parsed.suggestedMapping, 'ds_tok', 'PartSample');
  assert.equal(normalized.length, 1);
  assert.equal(normalized[0].username, '');
  assert.equal(normalized[0].extra.token, 'secret_tok_991122');
});

test('Masking helpers format addresses reliably', () => {
  assert.equal(maskEmail('kuzey.demir@example.test'), 'ku*****@ex****.test');
  assert.equal(maskIp('198.51.100.14'), '198.51.***.***');
});

test('Multi-file extra high-signal identifiers & handles correlate while junk values never false-link', () => {
  const pool: IntelRecord[] = [
    {
      id: 'ex_1',
      datasetId: 'ds_1',
      datasetName: 'FileOne',
      discordId: '104567890123456789',
      email: '',
      username: 'primary_user',
      source: 'PanelA',
      ip: '',
      phone: '',
      notes: '',
      extra: {
        hwid: 'HWID-XYZ-998877',
        tg: '@kuzey_tg_handle',
        ad_soyad: 'Ali',
        status: 'active',
      },
    },
    {
      id: 'ex_2',
      datasetId: 'ds_2',
      datasetName: 'FileTwo',
      discordId: '',
      email: 'hwid.linked@example.test',
      username: '',
      source: 'GameAntiCheat',
      ip: '198.51.100.44',
      phone: '',
      notes: '',
      extra: {
        hw_id: 'HWID-XYZ-998877',
        adres: 'Ataturk Mah. No:12 Ankara',
      },
    },
    {
      id: 'ex_3',
      datasetId: 'ds_3',
      datasetName: 'FileThree',
      discordId: '',
      email: '',
      username: '',
      source: 'ShippingDB',
      ip: '',
      phone: '+905559998877',
      notes: 'teslimat tamamlandi',
      extra: {
        ev_adresi: 'Ataturk Mah. No:12 Ankara',
        tckn: '10020030040',
      },
    },
    {
      id: 'ex_4',
      datasetId: 'ds_4',
      datasetName: 'FileFour',
      discordId: '',
      email: '',
      username: 'kuzey_tg_handle',
      source: 'TelegramDump',
      ip: '',
      phone: '',
      notes: '',
      extra: {
        steam_id: '76561198000000001',
      },
    },
    {
      id: 'ex_junk',
      datasetId: 'ds_5',
      datasetName: 'UnrelatedFile',
      discordId: '999888777666555444',
      email: 'unrelated.junk@example.test',
      username: 'unrelated_person',
      source: 'OtherDB',
      ip: '',
      phone: '',
      notes: '',
      extra: {
        ad_soyad: 'Ali',
        status: 'active',
        verified: 'true',
      },
    },
  ];

  const idx = buildSearchIndex(pool);
  const res = searchRecords(pool, '104567890123456789', 'discord_id', true, pool, idx);
  assert.equal(res.primaryMatches.length, 1);
  assert.equal(res.primaryMatches[0].id, 'ex_1');

  const relatedIds = res.relatedMatches.map((r) => r.id).sort();
  assert.deepEqual(relatedIds, ['ex_2', 'ex_3', 'ex_4']);
  assert.equal(relatedIds.includes('ex_junk'), false);

  // runBulkLookup also pulls cross-file linked records for a target Discord ID
  const bulk = runBulkLookup(pool, '104567890123456789', idx);
  assert.equal(bulk.length, 1);
  assert.equal(bulk[0].matches.length, 4);
});

test('Mixed dump key=value pairs, Turkish formatted phone, and nested JSON correlate across files', () => {
  const messyDump = [
    'id=104567890123456789 | hwid=HWID-TURBO-77 | tel=+90 (532) 111 22 33 | tg=@kuzey_dev',
    '{"user":{"id":"","mail":"hidden.link@example.test"},"hw_id":"HWID-TURBO-77","city":"Ankara"}',
    '05321112233;backup_user;198.51.100.88;OldForumDump',
  ].join('\n');

  const parsed = parseDatasetContent(messyDump, 'messy_tr.txt');
  const records = normalizeRows(parsed.rows, parsed.suggestedMapping, 'ds_messy_tr', 'MessyTR');
  const idx = buildSearchIndex(records);

  const res = searchRecords(records, '104567890123456789', 'discord_id', true, records, idx);
  assert.equal(res.primaryMatches.length, 1);
  assert.equal(res.primaryMatches[0].phone, '+90 (532) 111 22 33');
  assert.equal(res.relatedMatches.length, 2);
});

test('classifyRecordDatabaseType categorizes leak, sizinti, public_info, and respects server-assigned dbType', () => {
  const base = {
    id: 't',
    datasetId: 'ds',
    datasetName: '',
    discordId: '104567890123456789',
    email: '',
    username: 'user_a',
    source: '',
    ip: '',
    phone: '',
    notes: '',
    extra: {},
  };

  // Leak: stealer / combo / credential fields
  assert.equal(
    classifyRecordDatabaseType({ ...base, source: 'Redline Stealer Logs', extra: { password: 'p123' } }),
    'leak',
  );
  assert.equal(
    classifyRecordDatabaseType({ ...base, source: 'DiscordCombo', extra: { token: 'mfa.xxx' } }),
    'leak',
  );

  // Sizinti: forum/sql breach or private leaked PII (email, ip, phone, tckn/hwid)
  assert.equal(
    classifyRecordDatabaseType({ ...base, source: 'ForumSQLVeritabani', email: 'leak@example.test' }),
    'sizinti',
  );
  assert.equal(
    classifyRecordDatabaseType({ ...base, source: 'UnlabeledFile', ip: '198.51.100.12' }),
    'sizinti',
  );

  // Public Info: OSINT / GitHub / public profile or username-only without private PII
  assert.equal(
    classifyRecordDatabaseType({ ...base, source: 'GitHub OSINT', notes: 'Public bio link' }),
    'public_info',
  );
  assert.equal(
    classifyRecordDatabaseType({ ...base, source: 'ServerDirectory' }),
    'public_info',
  );

  // Pre-computed dbType is preserved even when datasetName is stripped for non-admin users
  assert.equal(
    classifyRecordDatabaseType({ ...base, dbType: 'leak', datasetName: '', source: '' }),
    'leak',
  );
  assert.equal(
    classifyRecordDatabaseType({ ...base, dbType: 'sizinti', datasetName: '', source: '' }),
    'sizinti',
  );
});

test('formatByteVolume formats bytes across B/KB/MB/GB and searchRecords populates scanMetrics', () => {
  assert.equal(formatByteVolume(0), '0 B');
  assert.equal(formatByteVolume(512), '512 B');
  assert.equal(formatByteVolume(2048), '2.0 KB');
  assert.equal(formatByteVolume(5 * 1024 * 1024), '5.0 MB');
  assert.equal(formatByteVolume(3 * 1024 * 1024 * 1024), '3.00 GB');

  const pool: IntelRecord[] = [
    {
      id: 'sm_1',
      datasetId: 'ds_sm',
      datasetName: 'ScanMetricFile',
      discordId: '104567890123456789',
      email: 'metric@example.test',
      username: 'metric_u',
      source: 'PublicOSINT',
      ip: '',
      phone: '',
      notes: '',
      extra: {},
    },
    {
      id: 'sm_2',
      datasetId: 'ds_sm',
      datasetName: 'ScanMetricFile',
      discordId: '289104567890123456',
      email: 'other@example.test',
      username: 'other_u',
      source: 'PublicOSINT',
      ip: '',
      phone: '',
      notes: '',
      extra: {},
    },
  ];
  const res = searchRecords(pool, '104567890123456789', 'discord_id', true, pool);
  assert.ok(res.durationMs > 0);
  assert.equal(res.scanMetrics?.scannedRecords, 2);
});


