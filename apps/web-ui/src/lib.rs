pub fn app_html() -> String {
        r#"<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>ironmesh Client</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 2rem; }
        main { max-width: 760px; margin: 0 auto; }
        code { background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 0.2rem; }
    </style>
</head>
<body>
    <main>
        <h1>ironmesh Web UI</h1>
        <p>This interface is served by the CLI client and is also reusable by mobile wrappers.</p>
        <p>Use the CLI for object operations: <code>put</code>, <code>get</code>, and <code>cache-list</code>.</p>
    </main>
</body>
</html>
"#
        .to_string()
}
