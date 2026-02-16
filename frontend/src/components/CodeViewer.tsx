import { useEffect, useRef, useMemo } from 'react';
import Prism from 'prismjs';
import 'prismjs/components/prism-rust';
import 'prismjs/components/prism-typescript';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-python';
import 'prismjs/components/prism-go';
import 'prismjs/components/prism-c';
import 'prismjs/components/prism-cpp';
import 'prismjs/components/prism-java';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-yaml';
import 'prismjs/components/prism-toml';
import 'prismjs/components/prism-markdown';
import 'prismjs/components/prism-css';
import 'prismjs/components/prism-sql';
import 'prismjs/components/prism-jsx';
import 'prismjs/components/prism-tsx';
import 'prismjs/components/prism-ruby';
import 'prismjs/components/prism-kotlin';
import 'prismjs/components/prism-swift';
import 'prismjs/components/prism-scala';
import 'prismjs/components/prism-haskell';
import 'prismjs/components/prism-lua';
import 'prismjs/components/prism-elixir';
import 'prismjs/components/prism-nix';

interface CodeViewerProps {
  code: string;
  language: string;
  highlightLine?: number;
  className?: string;
}

export function CodeViewer({ code, language, highlightLine, className = '' }: CodeViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const codeRef = useRef<HTMLElement>(null);

  // Map our language names to Prism grammar names
  const prismLanguage = useMemo(() => {
    const map: Record<string, string> = {
      rust: 'rust',
      python: 'python',
      javascript: 'javascript',
      jsx: 'jsx',
      typescript: 'typescript',
      tsx: 'tsx',
      go: 'go',
      c: 'c',
      cpp: 'cpp',
      java: 'java',
      csharp: 'csharp',
      ruby: 'ruby',
      bash: 'bash',
      kotlin: 'kotlin',
      swift: 'swift',
      scala: 'scala',
      haskell: 'haskell',
      lua: 'lua',
      elixir: 'elixir',
      nix: 'nix',
      json: 'json',
      yaml: 'yaml',
      toml: 'toml',
      markdown: 'markdown',
      html: 'html',
      css: 'css',
      sql: 'sql',
      xml: 'xml',
    };
    return map[language] ?? 'text';
  }, [language]);

  useEffect(() => {
    if (codeRef.current) {
      Prism.highlightElement(codeRef.current);
    }
  }, [code, prismLanguage]);

  // Scroll highlighted line into view
  useEffect(() => {
    if (highlightLine && containerRef.current) {
      const lineEl = containerRef.current.querySelector(
        `[data-line="${highlightLine}"]`
      );
      lineEl?.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  }, [highlightLine, code]);

  const lines = code.split('\n');

  return (
    <div ref={containerRef} className={`relative font-mono text-[13px] leading-relaxed ${className}`}>
      <div className="flex">
        {/* Line numbers */}
        <div className="select-none text-right pr-4 pl-4 py-4 text-slate-400 dark:text-slate-600 bg-slate-50 dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex-shrink-0">
          {lines.map((_, i) => (
            <div
              key={i}
              data-line={i + 1}
              className={`${highlightLine === i + 1 ? 'text-blue-500 font-bold bg-blue-50 dark:bg-blue-950 -mx-4 px-4' : ''}`}
            >
              {i + 1}
            </div>
          ))}
        </div>
        {/* Code content */}
        <div className="flex-1 overflow-x-auto py-4 pl-4 pr-4 bg-white dark:bg-slate-950">
          <pre className="!m-0 !p-0 !bg-transparent">
            <code ref={codeRef} className={`language-${prismLanguage}`}>
              {code}
            </code>
          </pre>
        </div>
      </div>
    </div>
  );
}
