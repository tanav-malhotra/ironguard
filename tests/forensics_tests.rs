use std::path::PathBuf;

#[tokio::test]
async fn scan_questions_picks_expected_files() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    tokio::fs::write(d.join("forensic1.txt"), "q1").await.unwrap();
    tokio::fs::write(d.join("Question-2.md"), "q2").await.unwrap();
    tokio::fs::write(d.join("note.txt"), "noop").await.unwrap();

    let desktop = PathBuf::from(d);
    let res = ironguard::forensics::scan_for_questions(&desktop).await.unwrap();
    let names: Vec<String> = res.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
    assert!(names.iter().any(|n| n.contains("forensic1")));
    assert!(names.iter().any(|n| n.to_ascii_lowercase().contains("question-2")));
    assert!(!names.iter().any(|n| n == "note.txt"));
}


