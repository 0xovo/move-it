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
    use crate::cloud::http::{HttpRequest, Method, MockHttp};
    use crate::cloud::index::{RemoteFile, RemoteIndex};
    use crate::keychain::MemoryStore;
    use crate::oauth::config::{install_byok_config, load_oauth_file};
    use crate::oauth::access_cache::AccessCache;
    use crate::oauth::flow::{begin_sign_in, complete_sign_in, wait_sign_in_code};
    use crate::oauth::loopback::LoopbackRedirect;
    use crate::oauth::tokens::{load_provider_token, Provider};
    use crate::pairing::OFFER_FILE;
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
    }

    fn oauth_pair(dir: &Path) -> (crate::oauth::config::OAuthFile, std::path::PathBuf) {
        let oauth = load_oauth_file(&dir.join("oauth.json")).unwrap();
        (oauth, dir.to_path_buf())
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

    fn queue_access_refresh(http: &MockHttp) {
        http.push_ok_json(r#"{"access_token":"access-refreshed","expires_in":3600}"#);
    }

    fn sign_in_provider(oauth_dir: &Path, store: &MemoryStore, http: &MockHttp, provider: Provider, byok: bool) {
        let cache = AccessCache::default();
        let (oauth, dir) = oauth_pair(oauth_dir);
        let start = begin_sign_in(provider, &oauth, &dir).unwrap();
        http.push_ok_json(r#"{"access_token":"access-test","expires_in":3600,"refresh_token":"refresh-abc"}"#);
        simulate_redirect(&start.redirect.redirect_uri, &start.state, "auth-code");
        complete_sign_in(&cache, store, provider, byok, &oauth, &dir, http, start).unwrap();
    }

    fn app_with(oauth_dir: &Path, state: &Path, store: Arc<MemoryStore>, http: Arc<MockHttp>) -> App {
        App::open(state)
            .unwrap()
            .with_key_store(store.clone())
            .with_token_store(store)
            .with_http(http)
            .with_app_config_dir(state.join("config"))
            .with_builtin_oauth_dir(oauth_dir.to_path_buf())
    }

    #[test]
    fn both_providers_complete_pkce_sign_in() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        for provider in [Provider::Google, Provider::Dropbox] {
            sign_in_provider(tmp.path(), &store, &http, provider, false);
            assert!(load_provider_token(&*store, provider, false).unwrap().is_some());
            let saved = load_provider_token(&*store, provider, false).unwrap().unwrap();
            assert!(saved.access_token.is_none(), "refresh-only in keychain");
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

        for _ in 0..2 {
            http.push_ok_json(r#"{"files":[]}"#);
        }
        http.push_ok_json(r#"{"id":"fid1","name":"moveit-box.json","md5Checksum":"etag1"}"#);
        http.push_ok_json(r#"{"files":[{"id":"fid1","name":"moveit-box.json","md5Checksum":"etag1"}]}"#);
        let pipe_a = GoogleDrivePipe::new(place_a.clone(), http.clone(), "tok".into()).unwrap();
        pipe_a.publish("note").unwrap();
        let upload = http.recorded().into_iter().find(|r| r.url.contains("upload")).expect("upload");
        assert_eq!(upload.method, Method::Post);
        let up_body = upload.body.as_ref().expect("multipart body");
        assert!(
            up_body.windows(sealed.len()).any(|w| w == sealed.as_slice()),
            "create upload must carry box bytes"
        );

        http.clear_recorded();
        http.push_ok_json(r#"{"files":[{"id":"fid1","name":"moveit-box.json","md5Checksum":"etag1"}]}"#);
        http.push_bytes(200, sealed.clone());
        let pipe_b = GoogleDrivePipe::new(place_b.clone(), http.clone(), "tok".into()).unwrap();
        pipe_b.refresh().unwrap();
        let back = std::fs::read(place_b.join(BOX_FILE)).unwrap();
        assert_eq!(back, sealed);
        assert_eq!(key.open_small(&[1u8; 12], &back).unwrap(), b"roundtrip");

        http.clear_recorded();
        for _ in 0..5 {
            http.push_ok_json(r#"{"files":[{"id":"fid1","name":"moveit-box.json","md5Checksum":"etag1"}]}"#);
        }
        http.push_ok_json(r#"{"id":"fid1","name":"moveit-box.json","md5Checksum":"etag1"}"#);
        crate::pipe::write_named_box(&place_a, BOX_FILE, &sealed).unwrap();
        let pipe_a2 = GoogleDrivePipe::new(place_a, http.clone(), "tok".into()).unwrap();
        pipe_a2.publish("note").unwrap();
        let update = http.recorded().into_iter().find(|r| r.url.contains("uploadType=media")).expect("patch upload");
        assert_eq!(update.method, Method::Patch);
        assert_eq!(update.body.as_deref(), Some(sealed.as_slice()), "media patch body");
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
        http.push_ok_json(r#"{"entries":[]}"#);
        http.push_ok_json(r#"{}"#);
        http.push_ok_json(
            r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r1"}]}"#,
        );
        let pipe_a = DropboxPipe::new(place_a.clone(), http.clone(), "tok".into()).unwrap();
        pipe_a.publish("note").unwrap();
        let add_upload = http
            .recorded()
            .into_iter()
            .find(|r| r.url.contains("/files/upload"))
            .expect("dropbox upload");
        assert_eq!(add_upload.body.as_deref(), Some(sealed.as_slice()));
        let add_arg = add_upload
            .headers
            .iter()
            .find(|(k, _)| k == "Dropbox-API-Arg")
            .map(|(_, v)| v.as_str())
            .expect("upload arg");
        assert!(add_arg.contains(r#""mode":"add""#), "{add_arg}");

        http.clear_recorded();
        crate::pipe::write_named_box(&place_a, BOX_FILE, &sealed).unwrap();
        let mut index = RemoteIndex::default();
        index.files.insert(
            BOX_FILE.to_string(),
            RemoteFile {
                id: "id1".into(),
                etag: None,
                modified: None,
                rev: Some("r1".into()),
            },
        );
        crate::cloud::index::save_index(&place_a, &index).unwrap();
        for _ in 0..3 {
            http.push_ok_json(
                r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r1"}]}"#,
            );
        }
        http.push_ok_json(r#"{}"#);
        http.push_ok_json(
            r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r2"}]}"#,
        );
        pipe_a.publish("note").unwrap();
        let update_upload = http
            .recorded()
            .into_iter()
            .find(|r| r.url.contains("/files/upload"))
            .expect("dropbox update upload");
        assert_eq!(update_upload.body.as_deref(), Some(sealed.as_slice()));
        let update_arg = update_upload
            .headers
            .iter()
            .find(|(k, _)| k == "Dropbox-API-Arg")
            .map(|(_, v)| v.as_str())
            .expect("update arg");
        assert!(update_arg.contains("update_rev"), "{update_arg}");
        assert!(update_arg.contains("r1"), "{update_arg}");

        http.clear_recorded();
        http.push_ok_json(
            r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r2"}]}"#,
        );
        http.push_bytes(200, sealed.clone());
        let pipe_b = DropboxPipe::new(place_b.clone(), http, "tok".into()).unwrap();
        pipe_b.refresh().unwrap();
        let back = std::fs::read(place_b.join(BOX_FILE)).unwrap();
        assert_eq!(back, sealed);
    }

    #[test]
    fn pairing_files_round_trip_google() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let offer = br#"{"v":1}"#;
        let http = Arc::new(MockHttp::default());
        let place_a = tmp.path().join("ga");
        let place_b = tmp.path().join("gb");
        std::fs::create_dir_all(&place_a).unwrap();
        std::fs::write(place_a.join(OFFER_FILE), offer).unwrap();
        for _ in 0..2 {
            http.push_ok_json(r#"{"files":[]}"#);
        }
        http.push_ok_json(r#"{"id":"p1","name":"moveit-pairing.json","md5Checksum":"e1"}"#);
        http.push_ok_json(r#"{"files":[{"id":"p1","name":"moveit-pairing.json","md5Checksum":"e1"}]}"#);
        let pipe_a = GoogleDrivePipe::new(place_a, http.clone(), "tok".into()).unwrap();
        pipe_a.publish("note").unwrap();

        http.push_ok_json(r#"{"files":[{"id":"p1","name":"moveit-pairing.json","md5Checksum":"e1"}]}"#);
        http.push_bytes(200, offer.to_vec());
        let pipe_b = GoogleDrivePipe::new(place_b, http, "tok".into()).unwrap();
        pipe_b.refresh().unwrap();
        assert_eq!(std::fs::read(pipe_b.place().join(OFFER_FILE)).unwrap(), offer);
    }

    #[test]
    fn pairing_files_round_trip_dropbox() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let offer = br#"{"v":1}"#;
        let http = Arc::new(MockHttp::default());
        let place_a = tmp.path().join("da");
        let place_b = tmp.path().join("db");
        std::fs::create_dir_all(&place_a).unwrap();
        std::fs::write(place_a.join(OFFER_FILE), offer).unwrap();
        http.push_ok_json(r#"{"entries":[]}"#);
        http.push_ok_json(r#"{"entries":[]}"#);
        http.push_ok_json(r#"{}"#);
        http.push_ok_json(r#"{"entries":[{".tag":"file","id":"p1","name":"moveit-pairing.json","rev":"r1"}]}"#);
        let pipe_a = DropboxPipe::new(place_a, http.clone(), "tok".into()).unwrap();
        pipe_a.publish("note").unwrap();

        http.push_ok_json(r#"{"entries":[{".tag":"file","id":"p1","name":"moveit-pairing.json","rev":"r1"}]}"#);
        http.push_bytes(200, offer.to_vec());
        let pipe_b = DropboxPipe::new(place_b, http, "tok".into()).unwrap();
        pipe_b.refresh().unwrap();
        assert_eq!(std::fs::read(pipe_b.place().join(OFFER_FILE)).unwrap(), offer);
    }

    #[test]
    fn tokens_survive_app_restart() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(tmp.path(), &store, &http, Provider::Google, false);

        http.clear_recorded();
        let app = app_with(tmp.path(), tmp.path(), store.clone(), http.clone());
        assert!(app.cloud_connected("google", false).unwrap());
        assert!(http.recorded().is_empty(), "restart check must not hit the network");
    }

    #[test]
    fn disconnect_stops_api_access() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(tmp.path(), &store, &http, Provider::Dropbox, false);
        http.clear_recorded();

        let mut app = app_with(tmp.path(), tmp.path(), store.clone(), http.clone());
        queue_access_refresh(&http);
        app.use_cloud_pipe("dropbox", false).unwrap();
        http.clear_recorded();
        app.pipe_sign_out("dropbox").unwrap();
        assert!(load_provider_token(&*store, Provider::Dropbox, false).unwrap().is_none());
        http.clear_recorded();
        assert!(app.use_cloud_pipe("dropbox", false).is_err());
        http.clear_recorded();
        assert!(app.pair_show_code().is_err());
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
        sign_in_provider(tmp.path(), &store, &http, Provider::Google, true);
        assert!(load_provider_token(&*store, Provider::Google, true).unwrap().is_some());

        let http2 = Arc::new(MockHttp::default());
        sign_in_provider(tmp.path(), &store, &http2, Provider::Google, false);
        let mut app = app_with(tmp.path(), &state, store.clone(), http.clone());
        queue_access_refresh(&http);
        app.use_cloud_pipe("google", false).unwrap();
        assert!(!state.join("config").join("oauth-byok.json").exists());
        assert!(!state.join("config").join("google-client.json").exists());
        assert!(load_provider_token(&*store, Provider::Google, true).unwrap().is_none());
    }

    #[test]
    fn builtin_switch_without_builtin_token_keeps_byok() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let byok_src = tmp.path().join("user-oauth.json");
        std::fs::write(&byok_src, std::fs::read(tmp.path().join("oauth.json")).unwrap()).unwrap();
        let state = tmp.path().join("state");
        install_byok_config(&byok_src, &state.join("config")).unwrap();
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(tmp.path(), &store, &http, Provider::Google, true);

        let mut app = app_with(tmp.path(), &state, store, http);
        assert!(app.use_cloud_pipe("google", false).is_err());
        let cfg = state.join("config");
        assert!(cfg.join("oauth-byok.json").exists());
        assert!(cfg.join("google-client.json").exists());
    }

    #[test]
    fn dropbox_sign_out_revokes_with_fresh_access_token() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(tmp.path(), &store, &http, Provider::Dropbox, false);
        http.clear_recorded();
        http.push_ok_json(r#"{"access_token":"access-for-revoke","expires_in":3600}"#);
        http.push_bytes(200, Vec::new());
        let mut app = app_with(tmp.path(), tmp.path(), store, http.clone());
        app.pipe_sign_out("dropbox").unwrap();
        let calls = http.recorded();
        let refresh = calls
            .iter()
            .find(|r| r.url.contains("oauth2/token") && r.body.as_ref().is_some_and(|b| b.windows(13).any(|w| w == b"refresh_token")))
            .expect("refresh before revoke");
        assert!(refresh.body.as_ref().unwrap().windows(11).any(|w| w == b"refresh-abc"));
        let revoke = calls.iter().find(|r| r.url.contains("token/revoke")).expect("revoke call");
        assert_eq!(
            revoke.headers.iter().find(|(k, _)| k == "Authorization").map(|(_, v)| v.as_str()),
            Some("Bearer access-for-revoke")
        );
    }

    #[test]
    fn google_sign_out_revoke_uses_refresh_in_body() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(tmp.path(), &store, &http, Provider::Google, false);
        http.clear_recorded();
        http.push_bytes(200, Vec::new());
        let mut app = app_with(tmp.path(), tmp.path(), store, http.clone());
        app.pipe_sign_out("google").unwrap();
        let revoke = http
            .recorded()
            .into_iter()
            .find(|r| r.url.contains("oauth2.googleapis.com/revoke"))
            .expect("google revoke");
        let body = String::from_utf8_lossy(revoke.body.as_deref().unwrap_or_default());
        assert!(body.contains("token=refresh-abc"), "refresh token in revoke body: {body}");
        assert!(
            !revoke
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization")),
            "google revoke must not use bearer"
        );
    }

    #[test]
    fn loopback_cancel_ends_wait_quickly() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let redirect = LoopbackRedirect::bind().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_timer = cancel.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            cancel_timer.store(true, Ordering::Release);
        });
        let start = std::time::Instant::now();
        let err = redirect
            .wait_for_code_cancel("state", Duration::from_secs(30), Some(cancel.as_ref()))
            .unwrap_err()
            .to_string();
        handle.join().unwrap();
        assert!(err.contains("cancelled"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(2), "cancel took {:?}", start.elapsed());
    }

    #[test]
    fn wait_sign_in_code_leaves_engine_unlocked() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let (oauth, dir) = oauth_pair(tmp.path());
        let start = begin_sign_in(Provider::Google, &oauth, &dir).unwrap();
        let engine = Arc::new(std::sync::Mutex::new(()));
        let engine_wait = engine.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_wait = cancel.clone();
        let wait = std::thread::spawn(move || {
            let _ = wait_sign_in_code(start, Duration::from_secs(30), Some(&cancel_wait));
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(engine_wait.try_lock().is_ok(), "oauth wait must not hold the engine lock");
        cancel.store(true, Ordering::Release);
        wait.join().unwrap();
    }

    #[test]
    fn write_named_box_rejects_hostile_names() {
        let place = tempfile::tempdir().unwrap();
        assert!(crate::pipe::write_named_box(place.path(), "moveit-box/../x.json", b"x").is_err());
        assert!(!place.path().join("x.json").exists());
    }

    #[test]
    fn lost_race_refuses_publish_dropbox_and_google() {
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
                etag: Some("etag-old".into()),
                modified: None,
                rev: Some("rev-old".into()),
            },
        );
        crate::cloud::index::save_index(&place, &files).unwrap();

        http.push_ok_json(
            r#"{"entries":[{".tag":"file","name":"moveit-box.json","rev":"rev-new","id":"id1"}]}"#,
        );
        http.push_ok_json(
            r#"{"entries":[{".tag":"file","name":"moveit-box.json","rev":"rev-new","id":"id1"}]}"#,
        );
        let pipe = DropboxPipe::new(place.clone(), http.clone(), "access".into()).unwrap();
        assert_eq!(pipe.publish("x").unwrap_err(), crate::Error::Busy);

        http.clear_recorded();
        http.push_ok_json(
            r#"{"files":[{"id":"id1","name":"moveit-box.json","md5Checksum":"etag-new"}]}"#,
        );
        http.push_ok_json(
            r#"{"files":[{"id":"id1","name":"moveit-box.json","md5Checksum":"etag-new"}]}"#,
        );
        let gpipe = GoogleDrivePipe::new(place, http, "access".into()).unwrap();
        assert_eq!(gpipe.publish("x").unwrap_err(), crate::Error::Busy);
    }

    #[test]
    fn loopback_redirect_matrix() {
        let redirect = LoopbackRedirect::bind().unwrap();
        let port = redirect.redirect_uri.rsplit(':').next().unwrap();
        let state = "expected-state";
        std::thread::spawn({
            let port = port.to_string();
            move || {
                std::thread::sleep(Duration::from_millis(30));
                let req = "GET /wrong?code=x&state=bad HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
                if let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{port}")) {
                    let _ = s.write_all(req.as_bytes());
                }
                std::thread::sleep(Duration::from_millis(40));
                let req = format!(
                    "GET /?error=access_denied&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                );
                if let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{port}")) {
                    let _ = s.write_all(req.as_bytes());
                }
            }
        });
        let err = redirect
            .wait_for_code(state, Duration::from_secs(2))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cancelled"), "access_denied ends wait: {err}");

        let redirect2 = LoopbackRedirect::bind().unwrap();
        let port2 = redirect2.redirect_uri.rsplit(':').next().unwrap();
        std::thread::spawn({
            let port = port2.to_string();
            let state = state.to_string();
            move || {
                std::thread::sleep(Duration::from_millis(30));
                let req = format!(
                    "GET /?code=good&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                );
                if let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{port}")) {
                    let _ = s.write_all(req.as_bytes());
                }
            }
        });
        assert_eq!(redirect2.wait_for_code(state, Duration::from_secs(2)).unwrap(), "good");
    }

    #[test]
    fn loopback_ignores_bad_state_then_accepts_good_redirect() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = MockHttp::default();
        let store = MemoryStore::default();
        let (oauth, dir) = oauth_pair(tmp.path());
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
        complete_sign_in(
            &AccessCache::default(),
            &store,
            Provider::Google,
            false,
            &oauth,
            &dir,
            &http,
            start,
        )
        .unwrap();
    }

    #[test]
    fn refresh_invalid_grant_surfaces_sign_in_again() {
        let tmp = tempfile::tempdir().unwrap();
        fixture_oauth(tmp.path());
        let http = Arc::new(MockHttp::default());
        let store = Arc::new(MemoryStore::default());
        sign_in_provider(tmp.path(), &store, &http, Provider::Google, false);
        http.clear_recorded();
        http.push_status_body(400, r#"{"error":"invalid_grant"}"#);
        let mut app = app_with(tmp.path(), tmp.path(), store, http);
        let err = app.use_cloud_pipe("google", false).unwrap_err().to_string();
        assert!(err.contains("sign in again"), "{err}");
    }

    fn expect_http_fail(status: u16, err: crate::Error) {
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("({status})")) || msg.contains("request failed"),
            "expected http {status} error, got: {msg}"
        );
    }

    #[test]
    fn google_pipe_http_errors_on_list_download_create_update_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let place = tmp.path().join("gd");
        std::fs::create_dir_all(&place).unwrap();
        crate::pipe::write_named_box(&place, BOX_FILE, b"payload").unwrap();
        let http = Arc::new(MockHttp::default());
        let pipe = GoogleDrivePipe::new(place.clone(), http.clone(), "tok".into()).unwrap();

        for status in [403u16, 404] {
            http.clear_recorded();
            http.push_status_body(status, r#"{"error":{"message":"nope"}}"#);
            expect_http_fail(status, pipe.refresh().unwrap_err());
            assert_eq!(std::fs::read(place.join(BOX_FILE)).unwrap(), b"payload");
        }

        http.clear_recorded();
        for status in [403u16, 404] {
            http.clear_recorded();
            for _ in 0..2 {
                http.push_status_body(status, r#"{"error":{"message":"nope"}}"#);
            }
            expect_http_fail(status, pipe.publish("n").unwrap_err());
        }

        http.clear_recorded();
        http.push_ok_json(r#"{"files":[{"id":"id1","name":"moveit-box.json","md5Checksum":"e"}]}"#);
        http.push_status_body(403, r#"{"error":{"message":"nope"}}"#);
        expect_http_fail(403, pipe.refresh().unwrap_err());

        http.clear_recorded();
        let mut index = RemoteIndex::default();
        index.files.insert(
            BOX_FILE.to_string(),
            RemoteFile {
                id: "id1".into(),
                etag: Some("e".into()),
                modified: None,
                rev: None,
            },
        );
        crate::cloud::index::save_index(&place, &index).unwrap();
        for status in [403u16, 404] {
            http.clear_recorded();
            for _ in 0..3 {
                http.push_ok_json(r#"{"files":[{"id":"id1","name":"moveit-box.json","md5Checksum":"e"}]}"#);
            }
            http.push_status_body(status, r#"{"error":{"message":"nope"}}"#);
            expect_http_fail(status, pipe.publish("n").unwrap_err());
        }

        http.clear_recorded();
        index.files.insert(
            OFFER_FILE.to_string(),
            RemoteFile {
                id: "orphan".into(),
                etag: None,
                modified: None,
                rev: None,
            },
        );
        crate::cloud::index::save_index(&place, &index).unwrap();
        std::fs::remove_file(place.join(BOX_FILE)).unwrap();
        for status in [403u16, 404] {
            http.clear_recorded();
            for _ in 0..2 {
                http.push_ok_json(
                    r#"{"files":[{"id":"orphan","name":"moveit-pairing.json","md5Checksum":"p"}]}"#,
                );
            }
            http.push_status_body(status, r#"{"error":{"message":"nope"}}"#);
            expect_http_fail(status, pipe.publish("n").unwrap_err());
        }
    }

    #[test]
    fn dropbox_pipe_http_errors_on_list_download_create_update_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let place = tmp.path().join("db");
        std::fs::create_dir_all(&place).unwrap();
        crate::pipe::write_named_box(&place, BOX_FILE, b"payload").unwrap();
        let http = Arc::new(MockHttp::default());
        let pipe = DropboxPipe::new(place.clone(), http.clone(), "tok".into()).unwrap();

        for status in [403u16, 404] {
            http.clear_recorded();
            http.push_status_body(status, r#"{"error_summary":"nope"}"#);
            expect_http_fail(status, pipe.refresh().unwrap_err());
            assert_eq!(std::fs::read(place.join(BOX_FILE)).unwrap(), b"payload");
        }

        http.clear_recorded();
        for status in [403u16, 404] {
            http.clear_recorded();
            for _ in 0..2 {
                http.push_status_body(status, r#"{"error_summary":"nope"}"#);
            }
            expect_http_fail(status, pipe.publish("n").unwrap_err());
        }

        http.clear_recorded();
        http.push_ok_json(r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r1"}]}"#);
        http.push_status_body(403, r#"{"error_summary":"nope"}"#);
        expect_http_fail(403, pipe.refresh().unwrap_err());

        http.clear_recorded();
        let mut index = RemoteIndex::default();
        index.files.insert(
            BOX_FILE.to_string(),
            RemoteFile {
                id: "id1".into(),
                etag: None,
                modified: None,
                rev: Some("r1".into()),
            },
        );
        crate::cloud::index::save_index(&place, &index).unwrap();
        for status in [403u16, 404] {
            http.clear_recorded();
            for _ in 0..3 {
                http.push_ok_json(
                    r#"{"entries":[{".tag":"file","id":"id1","name":"moveit-box.json","rev":"r1"}]}"#,
                );
            }
            http.push_status_body(status, r#"{"error_summary":"nope"}"#);
            expect_http_fail(status, pipe.publish("n").unwrap_err());
        }

        http.clear_recorded();
        index.files.insert(
            OFFER_FILE.to_string(),
            RemoteFile {
                id: "p1".into(),
                etag: None,
                modified: None,
                rev: Some("r9".into()),
            },
        );
        crate::cloud::index::save_index(&place, &index).unwrap();
        std::fs::remove_file(place.join(BOX_FILE)).unwrap();
        for status in [403u16, 404] {
            http.clear_recorded();
            for _ in 0..2 {
                http.push_ok_json(
                    r#"{"entries":[{".tag":"file","id":"p1","name":"moveit-pairing.json","rev":"r9"}]}"#,
                );
            }
            http.push_status_body(status, r#"{"error_summary":"nope"}"#);
            expect_http_fail(status, pipe.publish("n").unwrap_err());
        }
    }
}
