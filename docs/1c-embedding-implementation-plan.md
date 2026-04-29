# 1C Code Embedding Implementation Plan

## Overview
This document describes a phased implementation plan for adding support for indexing, chunking, and embedding 1C codebases in `narsil-mcp`.

The current architecture is already close to what is needed:
- `src/index.rs` performs repository indexing and owns the main search/index lifecycle.
- `src/parser.rs` provides language-specific parsing and symbol extraction with `tree-sitter`.
- `src/chunking.rs` creates AST-aware chunks and can fall back to line-based chunks.
- `src/embeddings.rs` provides TF-IDF similarity search.
- `src/hybrid_search.rs` combines BM25 and TF-IDF over chunks.
- `src/neural.rs` provides optional neural embeddings.

However, 1C codebases are usually not represented as plain source trees. In practice, a 1C repository often contains:
- `*.bsl` source modules
- XML metadata files describing configuration objects, forms, commands, templates, and relationships
- format-specific directory layouts from 1C configuration dumps

Because of this, 1C support must be implemented as both:
1. `BSL language support` for source modules
2. `1C XML-aware ingestion` for extracting meaningful code/search documents from configuration dumps

The goal is not merely to "index XML", but to make 1C repositories searchable and navigable as code.

## Problem Statement
Today, unsupported files are dropped too early during indexing.

In `src/index.rs`, repository indexing currently reads a file and then immediately requires successful parsing:
- if `parser.parse_file(...)` succeeds, the file is cached and indexed
- if parsing fails, the file is skipped entirely

This prevents 1C XML dumps from participating in:
- file cache
- plain text search
- chunk search
- hybrid search
- embeddings

This behavior is stricter than the effective search model implied by project documentation, which presents search tools as operating over repository content, not only over parseable languages.

## Goals
- Add support for `*.bsl` files as a first-class parsed language
- Allow unsupported but textual files to participate in indexing when appropriate
- Add 1C-specific ingestion for XML-based configuration dumps
- Generate useful chunks for 1C modules and metadata-derived artifacts
- Support TF-IDF and hybrid search over 1C code and extracted metadata
- Prepare the system for optional future neural embeddings over 1C chunks
- Preserve current architecture and keep the implementation incremental

## Non-Goals
- Full semantic understanding of all 1C metadata semantics in phase 1
- Full 1C type inference, data flow, or taint analysis
- Full form/layout/template rendering
- Exact parity with specialized 1C tooling ecosystems
- Immediate support for every 1C dump variant before establishing a normalized ingestion model

## Target User Experience
After implementation, a user should be able to point `narsil-mcp` at a 1C repository or configuration dump and:
- search for code in `*.bsl` modules
- run `hybrid_search` against 1C procedures/functions/modules
- retrieve chunks for 1C modules and metadata-backed documents
- find similar code in 1C modules using TF-IDF
- search across configuration object names and attached modules
- inspect normalized repository structure for 1C objects

## Architecture
The recommended architecture introduces a new normalization layer for 1C repositories.

### High-Level Model
1. Repository walker discovers files
2. Files are classified as:
   - parseable source
   - text-only source
   - 1C metadata file
   - binary/ignored
3. 1C-specific files are normalized into internal documents
4. Normalized documents are fed into existing indexing/chunking/search paths
5. `*.bsl` modules receive AST-aware parsing and chunking
6. XML-derived metadata documents receive structured text chunks

### Recommended New Abstractions
- `FileClassification`: identifies how a file should be handled
- `NormalizedDocument`: internal representation for searchable content
- `IngestionProvider`: trait for file-to-document extraction
- `OneCRepositoryDetector`: detects whether a repository is a 1C dump
- `OneCIngestor`: parses XML metadata and emits normalized documents

### Why Normalized Documents
Without normalization, raw XML search will be noisy:
- tags dominate token statistics
- metadata structure hides the actual code intent
- object names and module relationships are split across files

Normalized documents allow the system to expose content that better matches user intent, for example:
- object summary documents
- module source documents
- form module documents
- manager/object/common module descriptors

## Proposed Data Flow

### Current Data Flow
1. Walk repository
2. Read file
3. Parse file with `LanguageParser`
4. If parse succeeds:
   - add symbols
   - cache content
   - index search text
5. If parse fails:
   - skip file entirely

### Proposed Data Flow
1. Walk repository
2. Read file
3. Classify file
4. If plain text and not binary:
   - cache content
   - index plain text baseline
5. If file belongs to a 1C repository:
   - pass through `OneCIngestor`
   - emit normalized documents/chunks
6. If file is `*.bsl`:
   - parse with `LanguageParser`
   - extract symbols
   - produce AST-aware chunks
7. Feed normalized chunks/documents into:
   - `search_index`
   - `hybrid_search`
   - `embedding_engine`
   - optional `neural_engine`

## Key Components

### Existing Files to Modify
- `src/index.rs`
  - Relax early parser gate
  - Introduce file classification / ingestion dispatch
  - Add normalized document indexing path
  - Ensure 1C files enter `file_cache` and search indices

- `src/parser.rs`
  - Add `bsl` language configuration
  - Add tree-sitter query for procedures/functions/modules and possibly variables

- `src/chunking.rs`
  - Add `bsl` and possibly `xml` language detection
  - Add 1C-aware chunk construction rules where useful
  - Support chunking of normalized metadata-derived documents

- `src/hybrid_search.rs`
  - Ensure normalized 1C chunks map to meaningful `DocType`
  - Consider special handling for metadata summary chunks

- `src/embeddings.rs`
  - No architectural rewrite needed
  - Possibly extend indexing metadata or token weighting in later phases

- `src/search.rs`
  - Review tokenizer behavior for Cyrillic identifiers and 1C naming conventions
  - Confirm tokenization quality for BSL keywords and mixed-language identifiers

- `frontend/src/api/toolClient.ts`
  - Add `.bsl` mapping for syntax highlighting in any UI-facing contexts

### New Files to Add
- `src/ingest/mod.rs`
  - Ingestion entry points and shared abstractions

- `src/ingest/types.rs`
  - `NormalizedDocument`, `FileClassification`, `DocumentOrigin`, `DocumentKind`

- `src/ingest/classifier.rs`
  - File classification logic

- `src/ingest/onec.rs`
  - 1C repository detection
  - XML parsing
  - metadata extraction
  - normalized document generation

- `tests/onec_ingest_tests.rs`
  - Unit/integration coverage for XML extraction and normalization

- `test-fixtures/onec/...`
  - Small representative 1C repository fixtures

## 1C Domain Model
At minimum, the system should understand these 1C concepts:
- Configuration
- Common Module
- Catalog
- Document
- Enumeration
- Information Register
- Accumulation Register
- Form
- Command
- Manager Module
- Object Module
- Record Set Module
- Form Module
- Common Module source

### Minimum Useful Normalized Document Types
- `OneCModule`
  - Source from `*.bsl`
  - Includes object name, module type, relative path

- `OneCMetadataSummary`
  - Flattened text summary from XML metadata
  - Includes object type, object name, key properties

- `OneCFormModule`
  - Form metadata + module source joined into one searchable document

- `OneCObjectBundle`
  - Optional aggregate document joining object metadata and linked module names

## Phased Implementation Plan

### Phase 0: Discovery and Fixture Preparation
Goal: establish representative 1C input formats before code changes.

Tasks:
- Collect 3 to 5 small real or synthetic 1C fixtures:
  - config dump with XML metadata and `*.bsl`
  - common modules only
  - objects with forms
  - object + manager + form module combinations
- Document supported dump assumptions
- Identify minimal XML namespaces and file layout patterns to support first

Deliverables:
- `test-fixtures/onec/`
- documented assumptions in this plan or a companion doc

Exit criteria:
- tests can run against realistic 1C fixture structure

### Phase 1: Baseline Text Indexing for Unsupported Files
Goal: stop dropping textual files before they can be searched.

Status: completed on `feat/1c-phase1-text-indexing`.

Tasks:
- Refactor `src/index.rs` so file caching and baseline text indexing do not depend on successful parser support
- Introduce text/binary detection or a conservative whitelist for textual files
- Ensure unsupported text files can be:
  - stored in `file_cache`
  - indexed in BM25/plain search
  - chunked later via line-based fallback

Notes:
- This phase alone will make raw XML at least searchable
- This is necessary even if 1C-specific ingestion is added later

Deliverables:
- refactored repository indexing path
- regression tests for unsupported text files

Completed:
- `src/index.rs` now indexes textual files even when `LanguageParser::parse_file()` fails
- unsupported textual files are cached in `file_cache` and indexed into plain/BM25 search
- `process_file_changes()` was updated so incremental reindexing keeps the same behavior
- binary-looking files are still skipped via conservative `NUL`/UTF-8 text checks
- regression test added for `.xml` coverage in `search_code` and `search_chunks`

Exit criteria:
- a plain text `.xml` file appears in search results
- chunk-based tools can operate on unsupported textual content

### Phase 2: BSL Language Support in Parser
Goal: support `*.bsl` as a first-class language.

Status: completed on `feat/1c-phase2-bsl-parser`.

Tasks:
- Add `tree-sitter-bsl` dependency to `Cargo.toml`
- Add BSL language config in `src/parser.rs`
- Add extension mapping for `.bsl`
- Implement initial tree-sitter query capturing:
  - procedures
  - functions
  - module-level declarations where feasible
- Add parser tests for:
  - `Процедура`
  - `Функция`
  - export variants
  - nested/common real-world patterns if grammar supports them

Suggested initial symbol mapping:
- `Процедура` -> `SymbolKind::Function` or `Method`
- `Функция` -> `SymbolKind::Function`
- module/unit container -> `SymbolKind::Module` if grammar permits

Deliverables:
- parseable `*.bsl`
- extracted symbols
- parser tests

Completed:
- `tree-sitter-bsl` dependency added to `Cargo.toml`
- `src/parser.rs` now recognizes `.bsl` files as the `bsl` language
- initial tree-sitter query extracts BSL procedures and functions as symbols
- parser tests cover Russian and English keyword variants, including `Экспорт` / `Export`

Exit criteria:
- `LanguageParser::parse_file()` succeeds for representative BSL modules
- `find_symbols` can return BSL procedures/functions

### Phase 3: BSL Chunking Support
Goal: produce useful chunks from BSL modules.

Tasks:
- Add `bsl` detection in `src/chunking.rs`
- Verify AST boundaries from `tree-sitter-bsl`
- Implement boundary extraction for:
  - procedures
  - functions
  - module-level top blocks
- Keep line-based fallback for malformed files
- Add tests for:
  - multiple procedures in one module
  - comments/doc blocks
  - large procedures that require split chunks

Deliverables:
- BSL AST-aware chunks
- chunk stats coverage

Exit criteria:
- `get_chunks` produces meaningful chunks for BSL files
- `hybrid_search` can retrieve BSL procedures by content

### Phase 4: 1C Repository Detection
Goal: identify when a repository or subtree should be treated as a 1C dump.

Tasks:
- Add `OneCRepositoryDetector`
- Detect common markers such as:
  - `Configuration.xml`
  - `ConfigDumpInfo.xml`
  - known metadata directory layouts
  - `Ext/` + object metadata patterns
- Support both:
  - whole-repo 1C dumps
  - mixed repositories where a subdirectory contains 1C dump content

Deliverables:
- repository/subtree detector
- tests for positive and negative detection

Exit criteria:
- the engine can reliably detect a 1C dump root in fixtures

### Phase 5: XML Metadata Parsing and Normalization
Goal: transform raw 1C XML metadata into useful internal documents.

Tasks:
- Add `src/ingest/onec.rs`
- Parse XML safely with a Rust XML library suitable for namespace-aware reads
- Extract minimal metadata:
  - object type
  - object name
  - object path
  - form name
  - command name
  - links to modules where discoverable
- Emit `NormalizedDocument`s with flattened text optimized for search

Recommended flattened document shape:
- title line
- object type/name
- module relationships
- selected key properties
- source path references

Example output:
```text
1C Object: Catalog Номенклатура
Path: Catalogs/Номенклатура/Номенклатура.xml
Manager Module: Catalogs/Номенклатура/Ext/ManagerModule.bsl
Object Module: Catalogs/Номенклатура/Ext/ObjectModule.bsl
Forms: ФормаЭлемента, ФормаСписка
Attributes: Код, Наименование, Артикул
Commands: Заполнить, СоздатьСвязанныйДокумент
```

Deliverables:
- namespace-aware XML extraction
- normalized metadata documents
- fixture-based tests

Exit criteria:
- metadata summaries can be searched and returned independently of raw XML

### Phase 6: Linking Metadata and Modules
Goal: connect XML metadata and BSL modules into coherent search documents.

Tasks:
- Resolve relationships between:
  - object XML
  - `Ext/ObjectModule.bsl`
  - `Ext/ManagerModule.bsl`
  - form XML
  - form module BSL
- Optionally emit aggregate documents combining:
  - object summary
  - module references
  - key form/module names
- Preserve original file provenance for every normalized document

Key design rule:
- do not destroy original file-level traceability
- every normalized chunk must point back to a concrete source path or synthetic path with references

Suggested synthetic IDs:
- `onec://Catalogs/Номенклатура#summary`
- `onec://Catalogs/Номенклатура#object-module`
- `onec://Catalogs/Номенклатура/Forms/ФормаЭлемента#form-module`

Deliverables:
- metadata/module linker
- aggregate document support

Exit criteria:
- searching by object name can surface both metadata and module code

### Phase 7: Index Integration
Goal: feed normalized 1C artifacts into existing search and embedding systems.

Tasks:
- Add indexing path for normalized documents/chunks in `src/index.rs`
- Ensure both native file content and normalized synthetic documents can be indexed
- Decide how to store normalized documents:
  - in main search index only
  - in file cache equivalent
  - in a dedicated normalized document store

Recommendation:
- keep original file content in `file_cache`
- maintain a separate in-memory store for normalized/synthetic documents
- index both original and normalized documents in search systems

Reason:
- avoids polluting file-based operations with synthetic content
- preserves current file semantics for tools like `get_file`

Deliverables:
- normalized document indexing
- search result formatting with original provenance

Exit criteria:
- `hybrid_search`, `search_chunks`, and `find_similar_code` can retrieve 1C-derived content

### Phase 8: Tokenization Improvements for 1C
Goal: improve relevance for Cyrillic identifiers and 1C naming conventions.

Tasks:
- Review `src/search.rs::tokenize_code`
- Verify behavior for:
  - Cyrillic identifiers
  - mixed Cyrillic/Latin names
  - underscore-separated BSL identifiers
  - CamelCase-like patterns in transliterated names
- Add tests for common 1C naming patterns
- Revisit stop words if current filtering harms 1C tokens

Potential future enhancements:
- configurable stop-word lists by language
- BSL keyword normalization
- transliteration-aware search expansion, if needed

Deliverables:
- tokenizer tests
- optional tokenizer tuning

Exit criteria:
- typical 1C identifiers are tokenized and retrievable as expected

### Phase 9: Tooling and UX Exposure
Goal: expose 1C support consistently across CLI, MCP tools, and frontend.

Tasks:
- Update README supported languages list to include BSL
- Add `.bsl` language mapping in UI-facing code
- Add notes to search documentation
- Ensure tool output labels show `bsl` and useful chunk/doc types
- Consider surfacing normalized 1C document kinds in result formatting

Deliverables:
- documentation updates
- frontend syntax mapping

Exit criteria:
- user-visible tooling presents 1C artifacts coherently

### Phase 10: Optional Neural Embeddings for 1C
Goal: make 1C chunks usable by `neural_search` when neural mode is enabled.

Tasks:
- Reuse normalized/chunked 1C documents as neural inputs
- Verify payload construction in `src/neural.rs`
- Add tests ensuring 1C chunks can be submitted without assumptions tied to existing languages
- Consider lightweight metadata prefixes in chunk text to improve retrieval quality

Suggested neural text format:
```text
[1C BSL Module]
Object: Catalog Номенклатура
Module Type: ObjectModule
Path: Catalogs/Номенклатура/Ext/ObjectModule.bsl

Процедура ПередЗаписью(...)
...
```

Deliverables:
- neural indexing compatibility for 1C chunks

Exit criteria:
- `neural_search` can operate on indexed 1C content when enabled

## Search and Embedding Strategy

### BM25 / Plain Search
Use for:
- exact names of objects
- module names
- metadata terms
- paths and object types

### TF-IDF / `find_similar_code`
Use for:
- similar procedures/functions in BSL
- repeated business logic patterns
- similar validation or posting logic

### Hybrid Search
Use as default search mode for 1C:
- BM25 catches object names and exact business terms
- TF-IDF catches structural code similarity

### Neural Search
Use later for:
- semantically similar business logic
- similar posting/validation/calculation workflows across modules

## Storage Model

### Original Content
Keep original source files unchanged in:
- `file_cache`

### Synthetic / Normalized Content
Store separately in a new structure such as:
- `normalized_docs: DashMap<String, Vec<NormalizedDocument>>`
or a dedicated index-owned store

This separation avoids breaking file-oriented tools.

## Search Result Provenance
Every 1C-derived result should include:
- source file path
- optional synthetic document id
- object type
- object name
- module type if applicable

Result formatting should clearly distinguish:
- raw file results
- normalized metadata summary results
- module code results

## Recommended Dependencies

### Likely Needed
- `tree-sitter-bsl`
- XML parsing crate, for example:
  - `quick-xml`
  - or equivalent namespace-capable reader

### Selection Criteria
- safe parsing
- streaming support for large XML files
- good namespace handling
- low overhead

## Testing Strategy

### Unit Tests
- BSL parser support
- chunk extraction for BSL modules
- XML metadata extraction
- repository detection
- file classification
- tokenization of Cyrillic identifiers

### Integration Tests
- full indexing of a small 1C fixture repo
- `search_code` over 1C content
- `hybrid_search` over BSL modules
- `search_chunks` returning 1C chunks
- `find_similar_code` over repeated BSL procedures

### Regression Tests
- unsupported text files are not silently dropped
- non-1C repositories continue to behave the same
- malformed XML does not crash indexing
- malformed BSL falls back safely where possible

### Performance Tests
- indexing time for medium 1C dump fixture
- memory cost of normalized documents
- chunk count growth after enabling 1C support

## Risks and Mitigations

### Risk: Raw XML Search Pollution
Mitigation:
- prefer normalized metadata documents over raw XML-only indexing for ranking-sensitive paths

### Risk: Too Many Synthetic Documents
Mitigation:
- define a bounded set of normalized document kinds
- avoid indexing every XML node

### Risk: Ambiguous 1C Dump Variants
Mitigation:
- start with one supported layout family
- document unsupported variants explicitly

### Risk: Tokenization Quality for Cyrillic
Mitigation:
- add targeted tokenizer tests early
- adjust stop-word behavior only when backed by tests

### Risk: Tool Output Becomes Confusing
Mitigation:
- add explicit labels for result origin and document kind

## Security Considerations
- XML parsing must be safe against malicious or malformed input
- avoid entity expansion vulnerabilities if parser supports external entities
- validate and sanitize synthetic ids/paths used in result formatting
- do not allow normalized documents to bypass existing repo boundary guarantees

## Rollout Plan

### Milestone 1
- Phase 1 completed
- unsupported text files searchable

### Milestone 2
- Phases 2 and 3 completed
- `*.bsl` parsed and chunked

### Milestone 3
- Phases 4, 5, and 6 completed
- XML metadata normalized and linked to modules

### Milestone 4
- Phases 7 and 8 completed
- hybrid/TF-IDF search behaves well on 1C repositories

### Milestone 5
- Phases 9 and 10 completed
- user-facing docs and optional neural support are in place

## Suggested Task Breakdown
The work can be implemented in this order:

1. Refactor indexer to stop dropping unsupported text files
2. Add BSL parser support
3. Add BSL chunking tests
4. Add 1C repository detection
5. Add XML normalization for a single supported dump format
6. Link metadata and modules
7. Index normalized documents
8. Tune tokenization and result formatting
9. Update docs and frontend mappings
10. Add optional neural indexing support

## Definition of Done
1C embedding support can be considered implemented when:
- a representative 1C dump repository can be indexed without custom manual preprocessing
- `*.bsl` procedures/functions are discoverable as symbols
- `search_chunks` returns meaningful chunks from BSL modules
- `hybrid_search` works across BSL and metadata-derived documents
- `find_similar_code` returns useful similar BSL code
- XML metadata is represented in normalized searchable form
- tests cover repository detection, parsing, chunking, and search flows
- docs list 1C/BSL support and explain any constraints

## Open Questions
- Which exact 1C dump variants should be supported first?
- Should normalized metadata documents be visible as first-class files to MCP users, or only as search artifacts?
- Should aggregate object-level documents be indexed by default, or only raw modules + summaries?
- How much metadata should be folded into code chunks before relevance degrades?
- Is `SymbolKind::Function` sufficient for both procedures and functions, or should 1C-specific distinctions be added later?

## Recommended First Implementation Slice
The best first slice for actual development is:

1. Phase 1: baseline text indexing for unsupported files
2. Phase 2: BSL parser support
3. Phase 3: BSL chunking

This slice produces immediate user value with limited architectural risk and creates the foundation needed for XML-aware 1C ingestion.

## Last Updated
2026-04-29 - Phase 1 completed: unsupported textual files now remain searchable and chunkable.
2026-04-29 - Initial implementation plan for adding 1C code embedding and XML-aware indexing support.
