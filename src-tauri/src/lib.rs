// use fedimint_core::invite_code::InviteCode;
// use std::str::FromStr;
// use serde_json::json;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// #[tauri::command]
// fn hello_world() -> String {
//   "Hello, world!".to_string()
// }
