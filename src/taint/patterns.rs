//! Taint analysis pattern definitions.
//!
//! This module contains pattern definitions for identifying:
//! - Taint sources (user input, file reads, environment variables, etc.)
//! - Taint sinks (SQL queries, command execution, file operations, etc.)
//! - Sanitizers (functions that clean/escape tainted data)

use super::types::{Confidence, SinkKind, SourceKind};

/// Pattern for identifying taint sources
#[derive(Debug, Clone)]
pub struct SourcePattern {
    /// Pattern name
    pub name: String,
    /// Source kind this pattern detects
    pub kind: SourceKind,
    /// Languages this pattern applies to
    pub languages: Vec<String>,
    /// Function/method patterns (regex-like)
    pub function_patterns: Vec<String>,
    /// Object property patterns
    pub property_patterns: Vec<String>,
    /// Confidence level for matches
    pub confidence: Confidence,
}

/// Pattern for identifying taint sinks
#[derive(Debug, Clone)]
pub struct SinkPattern {
    /// Pattern name
    pub name: String,
    /// Sink kind
    pub kind: SinkKind,
    /// Languages this pattern applies to
    pub languages: Vec<String>,
    /// Function/method patterns
    pub function_patterns: Vec<String>,
    /// Which argument is dangerous (0-indexed)
    pub dangerous_arg: usize,
}

/// Pattern for identifying sanitizers
#[derive(Debug, Clone)]
pub struct SanitizerPattern {
    /// Pattern name
    pub name: String,
    /// Function patterns
    pub function_patterns: Vec<String>,
    /// What sinks this sanitizes for
    pub sanitizes_for: Vec<SinkKind>,
    /// Languages
    pub languages: Vec<String>,
}

/// Load default source patterns for common frameworks
#[must_use]
pub fn load_source_patterns() -> Vec<SourcePattern> {
    vec![
        // Python Flask/Django sources
        SourcePattern {
            name: "flask_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["python".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "request.args".to_string(),
                "request.form".to_string(),
                "request.data".to_string(),
                "request.json".to_string(),
                "request.values".to_string(),
                "request.cookies".to_string(),
                "request.headers".to_string(),
                "request.files".to_string(),
            ],
            confidence: Confidence::High,
        },
        SourcePattern {
            name: "django_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["python".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "request.GET".to_string(),
                "request.POST".to_string(),
                "request.COOKIES".to_string(),
                "request.META".to_string(),
                "request.body".to_string(),
            ],
            confidence: Confidence::High,
        },
        // JavaScript/TypeScript Express sources
        SourcePattern {
            name: "express_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["javascript".to_string(), "typescript".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "req.query".to_string(),
                "req.body".to_string(),
                "req.params".to_string(),
                "req.cookies".to_string(),
                "req.headers".to_string(),
            ],
            confidence: Confidence::High,
        },
        // Rust web framework sources
        SourcePattern {
            name: "actix_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["rust".to_string()],
            function_patterns: vec![
                "web::Query".to_string(),
                "web::Form".to_string(),
                "web::Json".to_string(),
                "web::Path".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        },
        // Go http sources
        SourcePattern {
            name: "go_http_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["go".to_string()],
            function_patterns: vec![
                "r.URL.Query".to_string(),
                "r.FormValue".to_string(),
                "r.PostFormValue".to_string(),
                "r.Header.Get".to_string(),
            ],
            property_patterns: vec!["r.Body".to_string()],
            confidence: Confidence::High,
        },
        // File read sources
        SourcePattern {
            name: "file_read".to_string(),
            kind: SourceKind::FileRead,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "open(".to_string(),
                "read(".to_string(),
                "readFile".to_string(),
                "read_to_string".to_string(),
                "fs.readFile".to_string(),
                "ioutil.ReadFile".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::Medium,
        },
        // Environment variable sources
        SourcePattern {
            name: "env_var".to_string(),
            kind: SourceKind::Environment,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "os.environ".to_string(),
                "os.getenv".to_string(),
                "process.env".to_string(),
                "std::env::var".to_string(),
                "env::var".to_string(),
                "os.Getenv".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::Medium,
        },
        // PHP superglobals - user input
        SourcePattern {
            name: "php_superglobals".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["php".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "$_GET".to_string(),
                "$_POST".to_string(),
                "$_REQUEST".to_string(),
                "$_COOKIE".to_string(),
                "$_SERVER".to_string(),
                "$_FILES".to_string(),
            ],
            confidence: Confidence::High,
        },
        // PHP file sources
        SourcePattern {
            name: "php_file_read".to_string(),
            kind: SourceKind::FileRead,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "file_get_contents(".to_string(),
                "fread(".to_string(),
                "fgets(".to_string(),
                "file(".to_string(),
                "readfile(".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::Medium,
        },
        // Java Servlet API sources
        SourcePattern {
            name: "java_servlet_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "getParameter(".to_string(),
                "getParameterValues(".to_string(),
                "getParameterMap(".to_string(),
                "getInputStream(".to_string(),
                "getReader(".to_string(),
                "getHeader(".to_string(),
                "getHeaders(".to_string(),
                "getCookies(".to_string(),
                "getQueryString(".to_string(),
                "getRequestURI(".to_string(),
                "getPathInfo(".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        },
        // Java Spring sources
        SourcePattern {
            name: "java_spring_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "@RequestParam".to_string(),
                "@PathVariable".to_string(),
                "@RequestBody".to_string(),
                "@RequestHeader".to_string(),
                "@CookieValue".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        },
        // C# ASP.NET sources
        SourcePattern {
            name: "csharp_aspnet_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["csharp".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "Request.QueryString".to_string(),
                "Request.Form".to_string(),
                "Request.Cookies".to_string(),
                "Request.Headers".to_string(),
                "Request.Body".to_string(),
                "Request.Path".to_string(),
                "Request.Query".to_string(),
            ],
            confidence: Confidence::High,
        },
        // C# ASP.NET Core sources
        SourcePattern {
            name: "csharp_aspnetcore_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "[FromQuery]".to_string(),
                "[FromBody]".to_string(),
                "[FromRoute]".to_string(),
                "[FromHeader]".to_string(),
                "[FromForm]".to_string(),
            ],
            property_patterns: vec![],
            confidence: Confidence::High,
        },
        // Ruby Rails sources
        SourcePattern {
            name: "ruby_rails_request".to_string(),
            kind: SourceKind::UserInput {
                input_type: "http".to_string(),
            },
            languages: vec!["ruby".to_string()],
            function_patterns: vec![],
            property_patterns: vec![
                "params[".to_string(),
                "request.params".to_string(),
                "request.query_parameters".to_string(),
                "request.body".to_string(),
                "cookies[".to_string(),
                "request.headers".to_string(),
            ],
            confidence: Confidence::High,
        },
    ]
}

/// Load default sink patterns for dangerous operations
#[must_use]
pub fn load_sink_patterns() -> Vec<SinkPattern> {
    vec![
        // SQL sinks
        SinkPattern {
            name: "sql_execute".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "execute(".to_string(),
                "executemany(".to_string(),
                "raw(".to_string(),
                "query(".to_string(),
                "exec(".to_string(),
                "Query(".to_string(),
                "Exec(".to_string(),
                "sqlx::query".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Command execution sinks
        SinkPattern {
            name: "command_exec".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "os.system".to_string(),
                "subprocess.call".to_string(),
                "subprocess.run".to_string(),
                "subprocess.Popen".to_string(),
                "exec(".to_string(),
                "spawn(".to_string(),
                "execSync".to_string(),
                "child_process".to_string(),
                "Command::new".to_string(),
                "std::process::Command".to_string(),
                "exec.Command".to_string(),
            ],
            dangerous_arg: 0,
        },
        // HTML output sinks (XSS)
        SinkPattern {
            name: "html_output".to_string(),
            kind: SinkKind::HtmlOutput,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            function_patterns: vec![
                "innerHTML".to_string(),
                "outerHTML".to_string(),
                "document.write".to_string(),
                "render_template_string".to_string(),
                "dangerouslySetInnerHTML".to_string(),
                "res.send".to_string(),
                "res.write".to_string(),
            ],
            dangerous_arg: 0,
        },
        // File path sinks
        SinkPattern {
            name: "file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
                "go".to_string(),
            ],
            function_patterns: vec![
                "open(".to_string(),
                "readFile".to_string(),
                "writeFile".to_string(),
                "fs.open".to_string(),
                "File::open".to_string(),
                "std::fs::read".to_string(),
                "os.Open".to_string(),
                "ioutil.WriteFile".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Eval sinks
        SinkPattern {
            name: "code_eval".to_string(),
            kind: SinkKind::Eval,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            function_patterns: vec![
                "eval(".to_string(),
                "exec(".to_string(),
                "compile(".to_string(),
                "Function(".to_string(),
                "setTimeout(".to_string(),
                "setInterval(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Deserialization sinks
        SinkPattern {
            name: "deserialization".to_string(),
            kind: SinkKind::Deserialization,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "rust".to_string(),
            ],
            function_patterns: vec![
                "pickle.loads".to_string(),
                "yaml.load".to_string(),
                "yaml.unsafe_load".to_string(),
                "JSON.parse".to_string(),
                "deserialize".to_string(),
                "unmarshal".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Redirect sinks
        SinkPattern {
            name: "redirect".to_string(),
            kind: SinkKind::Redirect,
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
            function_patterns: vec![
                "redirect(".to_string(),
                "location.href".to_string(),
                "location.replace".to_string(),
                "res.redirect".to_string(),
            ],
            dangerous_arg: 0,
        },
        // PHP SQL sinks
        SinkPattern {
            name: "php_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "mysql_query(".to_string(),
                "mysqli_query(".to_string(),
                "mysqli_real_query(".to_string(),
                "pg_query(".to_string(),
                "pg_exec(".to_string(),
                "sqlite_query(".to_string(),
                "->query(".to_string(),
                "->exec(".to_string(),
                "->execute(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // PHP command injection sinks
        SinkPattern {
            name: "php_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "exec(".to_string(),
                "shell_exec(".to_string(),
                "system(".to_string(),
                "passthru(".to_string(),
                "popen(".to_string(),
                "proc_open(".to_string(),
                "pcntl_exec(".to_string(),
                "`".to_string(), // backticks
            ],
            dangerous_arg: 0,
        },
        // PHP XSS sinks
        SinkPattern {
            name: "php_xss".to_string(),
            kind: SinkKind::HtmlOutput,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "echo ".to_string(),
                "print ".to_string(),
                "printf(".to_string(),
                "print_r(".to_string(),
                "var_dump(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // PHP file path sinks
        SinkPattern {
            name: "php_file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "include(".to_string(),
                "include_once(".to_string(),
                "require(".to_string(),
                "require_once(".to_string(),
                "file_get_contents(".to_string(),
                "file_put_contents(".to_string(),
                "fopen(".to_string(),
                "readfile(".to_string(),
                "unlink(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // PHP eval sinks
        SinkPattern {
            name: "php_eval".to_string(),
            kind: SinkKind::Eval,
            languages: vec!["php".to_string()],
            function_patterns: vec![
                "eval(".to_string(),
                "assert(".to_string(),
                "preg_replace(".to_string(), // with /e modifier
                "create_function(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Java SQL sinks
        SinkPattern {
            name: "java_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "executeQuery(".to_string(),
                "executeUpdate(".to_string(),
                "execute(".to_string(),
                "createStatement(".to_string(),
                "prepareStatement(".to_string(),
                "createNativeQuery(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Java command execution sinks
        SinkPattern {
            name: "java_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "Runtime.getRuntime().exec(".to_string(),
                "ProcessBuilder(".to_string(),
                ".exec(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Java file path sinks
        SinkPattern {
            name: "java_file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "new File(".to_string(),
                "new FileInputStream(".to_string(),
                "new FileOutputStream(".to_string(),
                "Files.readAllBytes(".to_string(),
                "Files.write(".to_string(),
                "Paths.get(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Java deserialization sinks
        SinkPattern {
            name: "java_deserialization".to_string(),
            kind: SinkKind::Deserialization,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "ObjectInputStream(".to_string(),
                "readObject(".to_string(),
                "readUnshared(".to_string(),
                "XMLDecoder(".to_string(),
                "XStream(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Java XXE sinks
        SinkPattern {
            name: "java_xxe".to_string(),
            kind: SinkKind::XmlParse,
            languages: vec!["java".to_string(), "kotlin".to_string()],
            function_patterns: vec![
                "DocumentBuilderFactory".to_string(),
                "SAXParserFactory".to_string(),
                "XMLInputFactory".to_string(),
                "TransformerFactory".to_string(),
                "SchemaFactory".to_string(),
            ],
            dangerous_arg: 0,
        },
        // C# SQL sinks
        SinkPattern {
            name: "csharp_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "SqlCommand(".to_string(),
                "ExecuteReader(".to_string(),
                "ExecuteScalar(".to_string(),
                "ExecuteNonQuery(".to_string(),
                "FromSqlRaw(".to_string(),
                "ExecuteSqlRaw(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // C# command execution sinks
        SinkPattern {
            name: "csharp_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "Process.Start(".to_string(),
                "ProcessStartInfo(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // C# file path sinks
        SinkPattern {
            name: "csharp_file_path".to_string(),
            kind: SinkKind::FilePath,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "File.ReadAllText(".to_string(),
                "File.WriteAllText(".to_string(),
                "File.Open(".to_string(),
                "FileStream(".to_string(),
                "StreamReader(".to_string(),
                "StreamWriter(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // C# deserialization sinks
        SinkPattern {
            name: "csharp_deserialization".to_string(),
            kind: SinkKind::Deserialization,
            languages: vec!["csharp".to_string()],
            function_patterns: vec![
                "BinaryFormatter(".to_string(),
                "Deserialize(".to_string(),
                "JsonConvert.DeserializeObject(".to_string(),
                "XmlSerializer(".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Ruby SQL sinks
        SinkPattern {
            name: "ruby_sql".to_string(),
            kind: SinkKind::SqlQuery,
            languages: vec!["ruby".to_string()],
            function_patterns: vec![
                ".execute(".to_string(),
                ".exec_query(".to_string(),
                ".find_by_sql(".to_string(),
                ".where(".to_string(),
                "ActiveRecord::Base.connection".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Ruby command execution sinks
        SinkPattern {
            name: "ruby_command".to_string(),
            kind: SinkKind::CommandExec,
            languages: vec!["ruby".to_string()],
            function_patterns: vec![
                "system(".to_string(),
                "exec(".to_string(),
                "`".to_string(), // backticks
                "%x(".to_string(),
                "IO.popen(".to_string(),
                "Open3.".to_string(),
            ],
            dangerous_arg: 0,
        },
        // Ruby eval sinks
        SinkPattern {
            name: "ruby_eval".to_string(),
            kind: SinkKind::Eval,
            languages: vec!["ruby".to_string()],
            function_patterns: vec![
                "eval(".to_string(),
                "instance_eval(".to_string(),
                "class_eval(".to_string(),
                "module_eval(".to_string(),
            ],
            dangerous_arg: 0,
        },
    ]
}

/// Load default sanitizer patterns
#[must_use]
pub fn load_sanitizer_patterns() -> Vec<SanitizerPattern> {
    vec![
        // SQL sanitizers (parameterized queries)
        SanitizerPattern {
            name: "parameterized_query".to_string(),
            function_patterns: vec![
                "execute(?, ".to_string(),
                "execute(%s".to_string(),
                "query($".to_string(),
                "prepared".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
        },
        // HTML escaping sanitizers
        SanitizerPattern {
            name: "html_escape".to_string(),
            function_patterns: vec![
                "escape(".to_string(),
                "html.escape".to_string(),
                "encodeURIComponent".to_string(),
                "htmlspecialchars".to_string(),
                "sanitize".to_string(),
                "DOMPurify".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
        },
        // Path sanitizers
        SanitizerPattern {
            name: "path_sanitize".to_string(),
            function_patterns: vec![
                "os.path.basename".to_string(),
                "path.basename".to_string(),
                "realpath".to_string(),
                "normpath".to_string(),
                "secure_filename".to_string(),
            ],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec![
                "python".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
            ],
        },
        // Command sanitizers
        SanitizerPattern {
            name: "shell_escape".to_string(),
            function_patterns: vec![
                "shlex.quote".to_string(),
                "shellescape".to_string(),
                "escapeshellarg".to_string(),
            ],
            sanitizes_for: vec![SinkKind::CommandExec],
            languages: vec!["python".to_string()],
        },
        // PHP sanitizers
        SanitizerPattern {
            name: "php_sql_sanitize".to_string(),
            function_patterns: vec![
                "prepare(".to_string(),
                "bindParam(".to_string(),
                "bindValue(".to_string(),
                "mysql_real_escape_string(".to_string(),
                "mysqli_real_escape_string(".to_string(),
                "pg_escape_string(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["php".to_string()],
        },
        SanitizerPattern {
            name: "php_html_sanitize".to_string(),
            function_patterns: vec![
                "htmlspecialchars(".to_string(),
                "htmlentities(".to_string(),
                "strip_tags(".to_string(),
                "filter_var(".to_string(),
                "filter_input(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["php".to_string()],
        },
        SanitizerPattern {
            name: "php_path_sanitize".to_string(),
            function_patterns: vec!["basename(".to_string(), "realpath(".to_string()],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec!["php".to_string()],
        },
        SanitizerPattern {
            name: "php_command_sanitize".to_string(),
            function_patterns: vec!["escapeshellarg(".to_string(), "escapeshellcmd(".to_string()],
            sanitizes_for: vec![SinkKind::CommandExec],
            languages: vec!["php".to_string()],
        },
        // Java sanitizers
        SanitizerPattern {
            name: "java_sql_sanitize".to_string(),
            function_patterns: vec![
                "PreparedStatement".to_string(),
                "setString(".to_string(),
                "setInt(".to_string(),
                "setParameter(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["java".to_string(), "kotlin".to_string()],
        },
        SanitizerPattern {
            name: "java_html_sanitize".to_string(),
            function_patterns: vec![
                "ESAPI.encoder()".to_string(),
                "HtmlUtils.htmlEscape".to_string(),
                "StringEscapeUtils.escapeHtml".to_string(),
                "Encode.forHtml".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["java".to_string(), "kotlin".to_string()],
        },
        SanitizerPattern {
            name: "java_path_sanitize".to_string(),
            function_patterns: vec![
                "FilenameUtils.getName".to_string(),
                "normalize(".to_string(),
                "getCanonicalPath(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec!["java".to_string(), "kotlin".to_string()],
        },
        // C# sanitizers
        SanitizerPattern {
            name: "csharp_sql_sanitize".to_string(),
            function_patterns: vec![
                "SqlParameter".to_string(),
                "AddWithValue(".to_string(),
                "Parameters.Add(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["csharp".to_string()],
        },
        SanitizerPattern {
            name: "csharp_html_sanitize".to_string(),
            function_patterns: vec![
                "HttpUtility.HtmlEncode".to_string(),
                "WebUtility.HtmlEncode".to_string(),
                "AntiXssEncoder".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["csharp".to_string()],
        },
        // Ruby sanitizers
        SanitizerPattern {
            name: "ruby_sql_sanitize".to_string(),
            function_patterns: vec![
                "sanitize_sql".to_string(),
                "quote(".to_string(),
                "prepare(".to_string(),
                "where(".to_string(), // when used with hash/array params
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["ruby".to_string()],
        },
        SanitizerPattern {
            name: "ruby_html_sanitize".to_string(),
            function_patterns: vec![
                "h(".to_string(),
                "html_escape(".to_string(),
                "sanitize(".to_string(),
                "ERB::Util.html_escape".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["ruby".to_string()],
        },
        SanitizerPattern {
            name: "ruby_command_sanitize".to_string(),
            function_patterns: vec!["Shellwords.escape(".to_string(), "shellescape(".to_string()],
            sanitizes_for: vec![SinkKind::CommandExec],
            languages: vec!["ruby".to_string()],
        },
        // Rust sanitizers
        SanitizerPattern {
            name: "rust_path_sanitize".to_string(),
            function_patterns: vec![
                "canonicalize(".to_string(),
                "validate_path(".to_string(),
                ".canonicalize()".to_string(),
                "Path::new(".to_string(),
                ".file_name()".to_string(),
                ".file_stem()".to_string(),
            ],
            sanitizes_for: vec![SinkKind::FilePath, SinkKind::FileWrite],
            languages: vec!["rust".to_string()],
        },
        SanitizerPattern {
            name: "rust_sql_sanitize".to_string(),
            function_patterns: vec![
                "query_as!".to_string(),
                "query!".to_string(),
                ".bind(".to_string(),
                "execute!".to_string(),
            ],
            sanitizes_for: vec![SinkKind::SqlQuery],
            languages: vec!["rust".to_string()],
        },
        SanitizerPattern {
            name: "rust_html_sanitize".to_string(),
            function_patterns: vec![
                "html_escape(".to_string(),
                "Escape::new(".to_string(),
                "encode(".to_string(),
            ],
            sanitizes_for: vec![SinkKind::HtmlOutput],
            languages: vec!["rust".to_string()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_patterns_loaded() {
        let patterns = load_source_patterns();
        assert!(!patterns.is_empty());

        // Verify Flask request pattern exists
        let flask_pattern = patterns.iter().find(|p| p.name == "flask_request");
        assert!(flask_pattern.is_some());
        let flask = flask_pattern.unwrap();
        assert!(flask
            .property_patterns
            .contains(&"request.args".to_string()));
        assert_eq!(flask.confidence, Confidence::High);
    }

    #[test]
    fn test_sink_patterns_loaded() {
        let patterns = load_sink_patterns();
        assert!(!patterns.is_empty());

        // Verify SQL sink pattern exists
        let sql_pattern = patterns.iter().find(|p| p.name == "sql_execute");
        assert!(sql_pattern.is_some());
        let sql = sql_pattern.unwrap();
        assert_eq!(sql.kind, SinkKind::SqlQuery);
        assert!(sql.function_patterns.contains(&"execute(".to_string()));
    }

    #[test]
    fn test_sanitizer_patterns_loaded() {
        let patterns = load_sanitizer_patterns();
        assert!(!patterns.is_empty());

        // Verify HTML escape sanitizer exists
        let html_pattern = patterns.iter().find(|p| p.name == "html_escape");
        assert!(html_pattern.is_some());
        let html = html_pattern.unwrap();
        assert!(html.sanitizes_for.contains(&SinkKind::HtmlOutput));
    }
}
