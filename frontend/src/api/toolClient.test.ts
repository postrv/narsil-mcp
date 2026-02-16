import { describe, it, expect, vi, beforeEach } from 'vitest';

// We need to test the parsing functions. They're not exported directly,
// so we'll test them through the public API with mocked fetch calls.

// First, let's test the parsers by importing and calling the public functions
// with a mocked codeIntelClient.

// Since the parsing functions are not exported, we test the exported async
// functions which use them. We mock the client's callTool.
vi.mock('./client', () => {
  const mockCallTool = vi.fn();
  return {
    codeIntelClient: {
      callTool: mockCallTool,
    },
  };
});

import { codeIntelClient } from './client';
import { getProjectStructure, getFile, findSymbols, getIndexStatus, stripMarkdownWrapper } from './toolClient';

const mockCallTool = vi.mocked(codeIntelClient.callTool);

beforeEach(() => {
  mockCallTool.mockReset();
});

describe('getProjectStructure', () => {
  it('parses a flat directory structure', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: `## Project Structure
src/
  main.rs
  lib.rs
Cargo.toml`,
    });

    const result = await getProjectStructure('test-repo');
    expect(result.length).toBeGreaterThan(0);
    // Should have src/ dir and Cargo.toml at root
    const rootNames = result.map(n => n.name);
    expect(rootNames).toContain('src');
    expect(rootNames).toContain('Cargo.toml');
  });

  it('parses tree-drawing characters correctly', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: `├── src/
│   ├── main.rs
│   └── lib.rs
└── Cargo.toml`,
    });

    const result = await getProjectStructure('test-repo');
    expect(result.length).toBeGreaterThan(0);
  });

  it('throws on failure', async () => {
    mockCallTool.mockResolvedValue({
      success: false,
      error: 'Repo not found',
    });

    await expect(getProjectStructure('bad-repo')).rejects.toThrow('Repo not found');
  });

  it('handles empty output gracefully', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: '',
    });

    const result = await getProjectStructure('empty-repo');
    expect(result).toEqual([]);
  });

  it('strips emoji prefixes, size suffixes, and unwraps repo root', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: `# Project Structure: test-repo

\`\`\`
\u{1F4C1} test-repo/
  \u{1F4C1} src/
    \u{1F980} main.rs (1.2KB)
    \u{1F980} lib.rs (500B)
  \u{1F4C1} benches/
    \u{1F980} indexing.rs (3.5KB)
  \u{1F4CB} Cargo.toml (2.1KB)
  \u{1F4DD} README.md (13.6KB)
\`\`\``,
    });

    const result = await getProjectStructure('test-repo');
    // Root repo dir should be unwrapped — children are top-level entries
    const topNames = result.map(c => c.name);
    expect(topNames).toContain('src');
    expect(topNames).toContain('benches');
    expect(topNames).toContain('Cargo.toml');
    expect(topNames).toContain('README.md');

    // Paths should be relative to repo root (no "test-repo/" prefix)
    const src = result.find(c => c.name === 'src')!;
    expect(src.path).toBe('src');
    expect(src.isDir).toBe(true);

    const mainRs = src.children!.find(c => c.name === 'main.rs')!;
    expect(mainRs.path).toBe('src/main.rs');
    expect(mainRs.isDir).toBe(false);
    expect(mainRs.name).not.toMatch(/[\u{1F000}-\u{1FFFF}]/u);
    expect(mainRs.name).not.toContain('(');
  });

  it('builds correct paths for sibling directories (no concatenation)', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: `# Project Structure: myrepo

\`\`\`
\u{1F4C1} myrepo/
  \u{1F4C1} benches/
    \u{1F980} bench.rs (1KB)
  \u{1F4C1} config/
    \u{1F4CB} default.toml (500B)
  \u{1F4C1} src/
    \u{1F4C1} api/
      \u{1F980} client.rs (2KB)
    \u{1F980} main.rs (800B)
\`\`\``,
    });

    const result = await getProjectStructure('myrepo');

    // Sibling dirs should NOT be concatenated into paths
    const src = result.find(c => c.name === 'src')!;
    expect(src.path).toBe('src');

    const api = src.children!.find(c => c.name === 'api')!;
    expect(api.path).toBe('src/api');

    const clientRs = api.children!.find(c => c.name === 'client.rs')!;
    expect(clientRs.path).toBe('src/api/client.rs');

    // benches/ should NOT appear in src's path
    const benches = result.find(c => c.name === 'benches')!;
    expect(benches.path).toBe('benches');

    const config = result.find(c => c.name === 'config')!;
    expect(config.path).toBe('config');
  });
});

describe('stripMarkdownWrapper', () => {
  it('strips markdown header, fences, and line numbers', () => {
    const input = [
      '# src/main.rs',
      '',
      'Lines 1-3 of 3',
      '',
      '```rust',
      '   1 │ fn main() {',
      '   2 │     println!("hello");',
      '   3 │ }',
      '```',
    ].join('\n');

    const result = stripMarkdownWrapper(input);
    expect(result).toBe('fn main() {\n    println!("hello");\n}');
  });

  it('handles wider line numbers (4+ digits)', () => {
    const input = [
      '# big.rs',
      '',
      'Lines 998-1000 of 1000',
      '',
      '```rust',
      ' 998 │ let a = 1;',
      ' 999 │ let b = 2;',
      '1000 │ let c = 3;',
      '```',
    ].join('\n');

    const result = stripMarkdownWrapper(input);
    expect(result).toBe('let a = 1;\nlet b = 2;\nlet c = 3;');
  });

  it('preserves empty lines inside code', () => {
    const input = [
      '# test.rs',
      '',
      '```rust',
      '   1 │ fn a() {}',
      '   2 │ ',
      '   3 │ fn b() {}',
      '```',
    ].join('\n');

    const result = stripMarkdownWrapper(input);
    expect(result).toBe('fn a() {}\n\nfn b() {}');
  });

  it('returns raw content when no code block found', () => {
    const input = 'just plain text content';
    const result = stripMarkdownWrapper(input);
    expect(result).toBe('just plain text content');
  });

  it('handles content with no line numbers', () => {
    const input = [
      '```',
      'plain content line 1',
      'plain content line 2',
      '```',
    ].join('\n');

    const result = stripMarkdownWrapper(input);
    expect(result).toBe('plain content line 1\nplain content line 2');
  });

  it('strips ASCII pipe separator (used by get_excerpt)', () => {
    const input = [
      '```rust',
      '   1 | fn main() {',
      '   2 |     println!("hello");',
      '   3 | }',
      '```',
    ].join('\n');

    const result = stripMarkdownWrapper(input);
    expect(result).toBe('fn main() {\n    println!("hello");\n}');
  });

  it('strips U+2502 separator via explicit unicode', () => {
    const input = [
      '```rust',
      '   1 \u2502 fn main() {',
      '   2 \u2502     return 42;',
      '   3 \u2502 }',
      '```',
    ].join('\n');

    const result = stripMarkdownWrapper(input);
    expect(result).toBe('fn main() {\n    return 42;\n}');
  });

  it('strips mojibake separator (â"‚) when UTF-8 is misinterpreted', () => {
    // When U+2502 bytes (E2 94 82) are misinterpreted as Windows-1252,
    // they become â (U+00E2) + " (U+201D) + ‚ (U+201A)
    const mojibake = '\u00e2\u201d\u201a';
    const input = [
      '```rust',
      `   1 ${mojibake} fn main() {`,
      `   2 ${mojibake}     return 42;`,
      `   3 ${mojibake} }`,
      '```',
    ].join('\n');

    const result = stripMarkdownWrapper(input);
    expect(result).toBe('fn main() {\n    return 42;\n}');
  });
});

describe('getFile', () => {
  it('strips markdown wrapper and returns clean code', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: [
        '# src/main.rs',
        '',
        'Lines 1-3 of 3',
        '',
        '```rust',
        '   1 │ fn main() {',
        '   2 │     println!("hello");',
        '   3 │ }',
        '```',
      ].join('\n'),
    });

    const result = await getFile('test-repo', 'src/main.rs');
    expect(result.path).toBe('src/main.rs');
    expect(result.language).toBe('rust');
    expect(result.content).toBe('fn main() {\n    println!("hello");\n}');
    expect(result.lines).toBe(3);
  });

  it('maps extensions to languages correctly', async () => {
    const extensionTests: [string, string][] = [
      ['main.py', 'python'],
      ['index.ts', 'typescript'],
      ['App.tsx', 'tsx'],
      ['main.go', 'go'],
      ['test.js', 'javascript'],
      ['style.css', 'css'],
      ['config.yaml', 'yaml'],
      ['data.json', 'json'],
      ['README.md', 'markdown'],
      ['query.sql', 'sql'],
      ['build.gradle', 'groovy'],
      ['unknown.xyz', 'text'],
    ];

    for (const [filename, expectedLang] of extensionTests) {
      mockCallTool.mockResolvedValue({ success: true, result: 'content' });
      const result = await getFile('repo', filename);
      expect(result.language).toBe(expectedLang);
    }
  });

  it('throws on failure', async () => {
    mockCallTool.mockResolvedValue({
      success: false,
      error: 'File not found',
    });

    await expect(getFile('repo', 'missing.rs')).rejects.toThrow('File not found');
  });
});

describe('findSymbols', () => {
  it('parses symbol output with standard format', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: `## Symbols in test-repo
- **main** (function) - src/main.rs:42
- **Config** (struct) - src/config.rs:10
- **parse** (function) - src/parser.rs:100`,
    });

    const result = await findSymbols('test-repo');
    expect(result).toHaveLength(3);
    expect(result[0]).toEqual({ name: 'main', kind: 'function', file: 'src/main.rs', line: 42 });
    expect(result[1]).toEqual({ name: 'Config', kind: 'struct', file: 'src/config.rs', line: 10 });
    expect(result[2]).toEqual({ name: 'parse', kind: 'function', file: 'src/parser.rs', line: 100 });
  });

  it('returns empty array for no matches', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: 'No symbols found.',
    });

    const result = await findSymbols('test-repo');
    expect(result).toEqual([]);
  });

  it('passes optional path and kind filters', async () => {
    mockCallTool.mockResolvedValue({ success: true, result: '' });

    await findSymbols('test-repo', { path: 'src/main.rs', kind: 'function' });

    expect(mockCallTool).toHaveBeenCalledWith({
      tool: 'find_symbols',
      args: { repo: 'test-repo', path: 'src/main.rs', kind: 'function' },
    });
  });
});

describe('getIndexStatus', () => {
  it('parses index status output', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: `## Index Status
- Repositories: 3
- Files: 1500
- Symbols: 25000`,
    });

    const result = await getIndexStatus();
    expect(result.repos).toBe(3);
    expect(result.files).toBe(1500);
    expect(result.symbols).toBe(25000);
  });

  it('returns zeros for unrecognized format', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: 'Something unexpected',
    });

    const result = await getIndexStatus();
    expect(result.repos).toBe(0);
    expect(result.files).toBe(0);
    expect(result.symbols).toBe(0);
  });

  it('handles partial output', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: 'Files: 42',
    });

    const result = await getIndexStatus();
    expect(result.repos).toBe(0);
    expect(result.files).toBe(42);
    expect(result.symbols).toBe(0);
  });
});
