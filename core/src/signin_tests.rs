//! Automated acceptance tests 1–6 from the sign-in build spec (mock HTTP, MemoryStore).

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::api::App;
    use crate::cloud::dropbox::DropboxPipe;
    use crate::cloud::google::GoogleDrivePipe;
    use crate::cloud::http::MockHttp;
    use crate::cloud::index::{RemoteFile, RemoteIndex};
    use crate::keychain::MemoryStore;
    use crate::oauth::config::{install_byok_config, load_builtin_oauth};
    use crate::oauth::flow::{begin_sign_in, complete_sign_in};
    use crate::oauth::tokens::{load_provider_token, Provider};
    use crate::pipe::{Pipe, BOX_FILE};
    use crate::sealed::SyncKey;

    fn fixture_oauth(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("oauth.json"),
            br#"{
              "dropbox": {"app_key":"test-dropbox","flow":"pkce","scopes":["files.metadata.read","files.content.read","files.content.write"],"access":"app_folder"},
              "google": {"client_id":"test-google","client_file":"google-client.json","flow":"pkce","scopes":["https://www.googleapis.com/auth/drive.file"]}
            }"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("google-client.json"),
            br#"{"installed":{"client_id":"test-google","client_secret":"test-secret","redirect_uris":["http://127.0.0.1"]}}"#,
        )
        .unwrap();
        // SAFETY: test-only env for fixture config paths.
        unsafe { std::env::set_var("MOVEIT_OAUTH_DIR", dir) };
    }

    fn oauth_pair() -> (crate::oauth::config::OAuthFile, std::path::PathBuf) {
        let oauth = load_builtin_oauth().unwrap();
        let dir = std::env::var("MOVEIT_OAUTH_DIR").map(std::path::PathBuf::from).unwrap();
        (oauth, dir)
    }

    fn simulate_redirect(redirect_uri: &str, state: &str, code: &str) {
        let port = redirect_uri.rsplit(':').next().unwrap_or("80");
        std::thread::spawn({
            let state = state.to_string();
            let code = code.to_string();
            let port = port.to_string();
            move || {
                std::thread::sleep(Duration::from_millis(40));
                let req = format!(
                    "GET /?code={code}&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                );
                if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{port}")) {
                    let _ = stream.write_all(req.as_bytes());
                }
            }
        });
    }

    fn sign_in_provider(store: &MemoryStore, http: &MockHttp, provider: Provider, byok: bool) {
        let (oauth, dir) = oauth_pair();
        let start = begin_sign_in(provider, &oauth, &dir).unwrap();
        http.push_ok_json(r#"{"access_token":"access-test","expires_in":3600,"refresh_token":"refresh-abc"}"#);
        simulate_redirect(&start.redirect.redirect_uri, &start.state, "auth-code");
        complete_sign_in(store, provider, byok, &oauth, &dir, http, start).unwrap();
    }

    fn app_with(state: &Path, store: Arc<MemoryStore>, http: Arc<MockHttp>) -> App {
        App::open(state)
            .unwrap()
            .with_key_store(store.clone())
            .with_token_store(store)
            .with_http(http)
            .with_app_config_dir(state.join("config"))
    }

    #[test]
    fn both_providers_complete_pkce_sign_in() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        for provider in [Provider::Google, Provider::Dropbox] {
            sign_in_provider(&store, &http, provider, false);
            assert!(load_provider_token(&*store, provider, false).unwrap().is_some());
        }
    }

    #[test]
    fn google_sealed_box_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let key = SyncKey::generate().unwrap();
        let sealed = key.seal_small(&[1u8; 12], b"roundtrip").unwrap();
        let http = Arc::new(MockHttp::default());
        let place_a = tmp.path().join("a");
        let place_b = tmp.path().join("b");
        std::fs::create_dir_all(&place_a).unwrap();
        crate::pipe::write_named_box(&place_a, BOX_FILE, &sealed).unwrap();

        http.push_ok_json(r#"{"files":[]}"#);
        http.push_ok_json(r#"{"id":"fid1","name":"moveit-box.json","md5Checksum":"etag1"}"#);
        let pipe_a = GoogleDrivePipe::new(place_a, http.clone(), "tok".into()).unwrap();
        pipe_a.publish("note").unwrap();

        http.push_ok_json(r#"{"files":[{"id":"fid1","name":"moveit-box.json","md5Checksum":"etag1"}]}"#);
        http.push_bytes(200, sealed.clone());
        let pipe_b = GoogleDrivePipe::new(place_b.clone(), http, "tok".into()).unwrap();
        pipe_b.refresh().unwrap();
        let back = std::fs::read(place_b.join(BOX_FILE)).unwrap();
        assert_eq!(back, sealed);
        assert_eq!(key.open_small(&[1u8; 12], &back).unwrap(), b"roundtrip");
    }

    #[test]
    fn dropbox_sealed_box_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let key = SyncKey::generate().unwrap();
        let sealed = key.seal_small(&[2u8; 12], b"dropbox").unwrap();
        let http = Arc::new(MockHttp::default());
        let place_a = tmp.path().join("a");
        let place_b = tmp.path().join("b");
        std::fs::create_dir_all(&place_a).unwrap();
        crate::pipe::write_named_box(&place_a, BOX_FILE, &sealed).unwrap();

        http.push_ok_json(r#"{"entries":[]}"#);
        http.push_ok_json(r#"{}"#);
        http.push_ok_json(
            r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r1"}]}"#,
        );
        let pipe_a = DropboxPipe::new(place_a, http.clone(), "tok".into()).unwrap();
        pipe_a.publish("note").unwrap();

        http.push_ok_json(
            r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r1"}]}"#,
        );
        http.push_bytes(200, sealed.clone());
        let pipe_b = DropboxPipe::new(place_b.clone(), http, "tok".into()).unwrap();
        pipe_b.refresh().unwrap();
        let back = std::fs::read(place_b.join(BOX_FILE)).unwrap();
        assert_eq!(back, sealed);
    }

    #[test]
    fn tokens_survive_app_restart() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(&store, &http, Provider::Google, false);

        http.clear_recorded();
        let app = app_with(tmp.path(), store.clone(), http.clone());
        assert!(app.cloud_connected("google", false).unwrap());
        assert!(http.recorded().is_empty(), "restart check must not hit the network");
    }

    #[test]
    fn disconnect_stops_api_access() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(&store, &http, Provider::Dropbox, false);
        http.clear_recorded();

        let mut app = app_with(tmp.path(), store.clone(), http.clone());
        app.use_cloud_pipe("dropbox", false).unwrap();
        http.clear_recorded();
        app.pipe_sign_out("dropbox").unwrap();
        assert!(load_provider_token(&*store, Provider::Dropbox, false).unwrap().is_none());
        http.clear_recorded();
        assert!(app.use_cloud_pipe("dropbox", false).is_err());
        assert!(http.recorded().is_empty(), "not-connected publish path makes no calls");
    }

    #[test]
    fn byok_tokens_and_builtin_switch() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let byok_src = tmp.path().join("user-oauth.json");
        std::fs::write(&byok_src, std::fs::read(tmp.path().join("oauth.json")).unwrap()).unwrap();

        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        let state = tmp.path().join("state");
        install_byok_config(&byok_src, &state.join("config")).unwrap();
        sign_in_provider(&store, &http, Provider::Google, true);
        assert!(load_provider_token(&*store, Provider::Google, true).unwrap().is_some());

        let mut app = app_with(&state, store.clone(), http);
        app.abandon_byok().unwrap();
        assert!(load_provider_token(&*store, Provider::Google, true).unwrap().is_none());
        assert!(!state.join("config").join("oauth-byok.json").exists());
    }

    #[test]
    fn lost_race_refuses_publish() {
        let tmp = tempfile::tempdir().unwrap();
        let http = Arc::new(MockHttp::default());
        let place = tmp.path().join("staging");
        std::fs::create_dir_all(&place).unwrap();
        crate::pipe::write_named_box(&place, BOX_FILE, b"sealed").unwrap();
        let mut files = RemoteIndex::default();
        files.files.insert(
            BOX_FILE.to_string(),
            RemoteFile {
                id: "id1".into(),
                etag: None,
                modified: None,
                rev: Some("rev-old".into()),
            },
        );
        crate::cloud::index::save_index(&place, &files).unwrap();

        http.push_ok_json(
            r#"{"entries":[{".tag":"file","name":"moveit-box.json","rev":"rev-new","id":"id1"}]}"#,
        );
        let pipe = DropboxPipe::new(place, http, "access".into()).unwrap();
        assert_eq!(pipe.publish("x").unwrap_err(), crate::Error::Busy);
    }

    #[test]
    fn loopback_ignores_bad_state_then_accepts_good_redirect() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = MockHttp::default();
        let store = MemoryStore::default();
        let (oauth, dir) = oauth_pair();
        let start = begin_sign_in(Provider::Google, &oauth, &dir).unwrap();
        simulate_redirect(&start.redirect.redirect_uri, "wrong-state", "code");
        std::thread::spawn({
            let uri = start.redirect.redirect_uri.clone();
            let state = start.state.clone();
            move || {
                std::thread::sleep(Duration::from_millis(80));
                simulate_redirect(&uri, &state, "good-code");
            }
        });
        http.push_ok_json(r#"{"access_token":"a","expires_in":60,"refresh_token":"r"}"#);
        complete_sign_in(&store, Provider::Google, false, &oauth, &dir, &http, start).unwrap();
    }
}
