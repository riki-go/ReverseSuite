// ReverseSuite desktop wrapper.
//
// 1. generate a session token
// 2. spawn the Python sidecar (`reversesuite-backend serve --root ... --port 0 --token ...`)
// 3. show a 1200x800 window immediately, injecting the token into sessionStorage
// 4. when the sidecar reports PORT=<n> on stderr, navigate to that origin
// 5. kill the sidecar when the app exits
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::Write;
use std::sync::Mutex;

use rand::distributions::Alphanumeric;
use rand::Rng;
use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

struct Backend(Mutex<Option<CommandChild>>);

fn log_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let dir = std::path::Path::new(&base).join("ReverseSuite");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("desktop.log")
}

fn write_session(port: u16, token: &str) {
    let path = log_path().with_file_name("session.json");
    let body = format!("{{\"url\":\"http://127.0.0.1:{}/\",\"port\":{},\"token\":\"{}\"}}", port, port, token);
    if let Ok(mut fh) = std::fs::File::create(&path) {
        let _ = fh.write_all(body.as_bytes());
    }
}


fn log(line: &str) {
    if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(log_path()) {
        let _ = writeln!(fh, "{}", line);
    }
}

fn new_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn parse_port(line: &str) -> Option<u16> {
    let idx = line.find("PORT=")?;
    let rest = &line[idx + 5..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn main() {
    log("=== start ===");
    let token = new_token();
    let state_token = token.clone();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Backend(Mutex::new(None)))
        .setup(move |app| {
            let js_token = serde_json::to_string(&token).unwrap_or_else(|_| "\"\"".to_string());
            let script = format!(
                "window.__rs_token={t};try{{sessionStorage.setItem('rs-token',{t});}}catch(e){{}}",
                t = js_token
            );
            // A webview needs an interactive desktop session; when the app is started
            // from a service/session-0 context the build fails. Keep going headless so
            // the backend still comes up and session.json points at it.
            let window_result = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("ReverseSuite")
                .inner_size(1200.0, 800.0)
                .min_inner_size(900.0, 600.0)
                .initialization_script(&script)
                .build();
            match &window_result {
                Ok(_) => log("window built on bundled shell"),
                Err(err) => log(&format!("window build failed (headless mode): {}", err)),
            }

            log("spawning sidecar (unrestricted local paths + URL fetch)");
            let sidecar = app
                .shell()
                .sidecar("reversesuite-backend")?
                .args(["serve", "--port", "0", "--parent-pid",
                       &std::process::id().to_string(), "--token", &state_token]);
            let (mut rx, child) = sidecar.spawn()?;
            log(&format!("sidecar pid {}", child.pid()));
            *app.state::<Backend>().0.lock().unwrap() = Some(child);

            let handle = app.handle().clone();
            let session_token_for_file = state_token.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stderr(bytes) => {
                            let line = String::from_utf8_lossy(&bytes).to_string();
                            log(&format!("stderr: {}", line.trim_end()));
                            if let Some(port) = parse_port(&line) {
                                let url = format!("http://127.0.0.1:{}/", port);
                                log(&format!("backend url {}", url));
                                write_session(port, &session_token_for_file);
                                if let Some(window) = handle.get_webview_window("main") {
                                    match url.parse() {
                                        Ok(parsed) => {
                                            if let Err(err) = window.navigate(parsed) {
                                                log(&format!("navigate failed: {}", err));
                                            }
                                        }
                                        Err(err) => log(&format!("bad url: {}", err)),
                                    }
                                } else {
                                    log("window missing at navigate time");
                                }
                            }
                        }
                        CommandEvent::Stdout(bytes) => {
                            let line = String::from_utf8_lossy(&bytes).to_string();
                            log(&format!("stdout: {}", line.trim_end()));
                        }
                        CommandEvent::Terminated(payload) => {
                            log(&format!("sidecar terminated code={:?}", payload.code));
                            break;
                        }
                        other => {
                            log(&format!("event: {:?}", other));
                        }
                    }
                }
                log("sidecar event loop finished");
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building ReverseSuite desktop");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            log("exit: killing sidecar");
            if let Some(child) = app_handle.state::<Backend>().0.lock().unwrap().take() {
                let _ = child.kill();
            }
        }
    });
}