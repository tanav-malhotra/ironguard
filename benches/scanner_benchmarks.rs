// IronGuard Ultimate - Performance Benchmarks
// Benchmark suite for measuring scanner performance in competition scenarios

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ironguard::scanners::*;
use std::time::Duration;
use tokio::runtime::Runtime;

// Benchmark individual scanners
fn bench_user_scanner(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("user_scanner_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let scanner = users::UserScanner::new();
            black_box(scanner.scan().await.unwrap())
        })
    });
}

fn bench_service_scanner(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("service_scanner_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let scanner = services::ServiceScanner::new();
            black_box(scanner.scan().await.unwrap())
        })
    });
}

fn bench_network_scanner(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("network_scanner_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let scanner = network::NetworkScanner::new();
            black_box(scanner.scan().await.unwrap())
        })
    });
}

fn bench_filesystem_scanner(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("filesystem_scanner_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let scanner = filesystem::FileSystemScanner::new();
            black_box(scanner.scan().await.unwrap())
        })
    });
}

fn bench_software_scanner(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("software_scanner_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let scanner = software::SoftwareScanner::new();
            black_box(scanner.scan().await.unwrap())
        })
    });
}

fn bench_system_scanner(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("system_scanner_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let scanner = system::SystemScanner::new();
            black_box(scanner.scan().await.unwrap())
        })
    });
}

// Benchmark complete scanning workflow
fn bench_complete_scan(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("complete_scan_workflow", |b| {
        b.to_async(&rt).iter(|| async {
            let engine = ScannerEngine::new();
            
            // Register all scanners
            engine.register_scanner("users", Box::new(users::UserScanner::new()));
            engine.register_scanner("services", Box::new(services::ServiceScanner::new()));
            engine.register_scanner("network", Box::new(network::NetworkScanner::new()));
            engine.register_scanner("filesystem", Box::new(filesystem::FileSystemScanner::new()));
            engine.register_scanner("software", Box::new(software::SoftwareScanner::new()));
            engine.register_scanner("system", Box::new(system::SystemScanner::new()));
            
            black_box(engine.scan_all(None).await.unwrap())
        })
    });
}

// Benchmark parallel vs sequential scanning
fn bench_parallel_vs_sequential(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("parallel_vs_sequential");
    
    // Sequential scanning
    group.bench_function("sequential_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let user_scanner = users::UserScanner::new();
            let service_scanner = services::ServiceScanner::new();
            let network_scanner = network::NetworkScanner::new();
            
            // Run sequentially
            let _ = user_scanner.scan().await.unwrap();
            let _ = service_scanner.scan().await.unwrap();
            let _ = network_scanner.scan().await.unwrap();
        })
    });
    
    // Parallel scanning
    group.bench_function("parallel_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let user_scanner = users::UserScanner::new();
            let service_scanner = services::ServiceScanner::new();
            let network_scanner = network::NetworkScanner::new();
            
            // Run in parallel
            let (r1, r2, r3) = tokio::join!(
                user_scanner.scan(),
                service_scanner.scan(),
                network_scanner.scan()
            );
            
            black_box((r1.unwrap(), r2.unwrap(), r3.unwrap()))
        })
    });
    
    group.finish();
}

// Benchmark different concurrency levels
fn bench_concurrency_levels(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("concurrency_levels");
    
    for concurrent_scans in [1, 2, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_scans", concurrent_scans),
            concurrent_scans,
            |b, &concurrent_scans| {
                b.to_async(&rt).iter(|| async move {
                    let mut handles = Vec::new();
                    
                    for _ in 0..concurrent_scans {
                        let handle = tokio::spawn(async {
                            let scanner = users::UserScanner::new();
                            scanner.scan().await.unwrap()
                        });
                        handles.push(handle);
                    }
                    
                    let results = futures::future::join_all(handles).await;
                    black_box(results)
                })
            },
        );
    }
    
    group.finish();
}

// Benchmark memory usage patterns
fn bench_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("memory_intensive_scan", |b| {
        b.to_async(&rt).iter(|| async {
            let mut engines = Vec::new();
            
            // Create multiple scanner engines to test memory usage
            for _ in 0..10 {
                let engine = ScannerEngine::new();
                engine.register_scanner("users", Box::new(users::UserScanner::new()));
                engines.push(engine);
            }
            
            // Run scans on all engines
            let mut handles = Vec::new();
            for engine in engines {
                let handle = tokio::spawn(async move {
                    engine.scan_all(None).await.unwrap()
                });
                handles.push(handle);
            }
            
            let results = futures::future::join_all(handles).await;
            black_box(results)
        })
    });
}

// Benchmark configuration loading performance
fn bench_config_loading(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("config_loading", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(ironguard::config::Config::load_with_fallback().await.unwrap())
        })
    });
}

// Benchmark database operations
fn bench_database_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("database_operations");
    
    group.bench_function("store_scan_results", |b| {
        b.to_async(&rt).iter(|| async {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let db_path = temp_dir.path().join("bench.db");
            let db = ironguard::database::Database::new(&db_path).await.unwrap();
            
            let results = ScanResults {
                scan_id: "bench-001".to_string(),
                timestamp: chrono::Utc::now(),
                vulnerabilities: Vec::new(),
                system_info: std::collections::HashMap::new(),
                total_score: 0,
                categories: std::collections::HashMap::new(),
            };
            
            black_box(db.store_scan_results(&results).await.unwrap())
        })
    });
    
    group.bench_function("retrieve_scan_results", |b| {
        b.to_async(&rt).iter(|| async {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let db_path = temp_dir.path().join("bench.db");
            let db = ironguard::database::Database::new(&db_path).await.unwrap();
            
            // Store a result first
            let results = ScanResults {
                scan_id: "bench-002".to_string(),
                timestamp: chrono::Utc::now(),
                vulnerabilities: Vec::new(),
                system_info: std::collections::HashMap::new(),
                total_score: 0,
                categories: std::collections::HashMap::new(),
            };
            db.store_scan_results(&results).await.unwrap();
            
            // Benchmark retrieval
            black_box(db.get_scan_results("bench-002").await.unwrap())
        })
    });
    
    group.finish();
}

// Benchmark vulnerability processing
fn bench_vulnerability_processing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("vulnerability_processing", |b| {
        b.to_async(&rt).iter(|| async {
            let mut vulnerabilities = Vec::new();
            
            // Create a large number of vulnerabilities to process
            for i in 0..1000 {
                vulnerabilities.push(Vulnerability {
                    id: format!("vuln-{:04}", i),
                    title: format!("Test Vulnerability {}", i),
                    description: "Test vulnerability description".to_string(),
                    level: VulnerabilityLevel::Medium,
                    category: "Test".to_string(),
                    auto_fixable: i % 2 == 0,
                    score_impact: 10,
                    evidence: Vec::new(),
                    fix_commands: Vec::new(),
                    references: Vec::new(),
                });
            }
            
            // Process vulnerabilities (sort, categorize, etc.)
            vulnerabilities.sort_by(|a, b| b.level.cmp(&a.level));
            
            let auto_fixable: Vec<_> = vulnerabilities
                .iter()
                .filter(|v| v.auto_fixable)
                .collect();
            
            black_box((vulnerabilities, auto_fixable))
        })
    });
}

// Competition scenario benchmarks
fn bench_competition_scenarios(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("competition_scenarios");
    
    // Windows Server scenario
    group.bench_function("windows_server_scenario", |b| {
        b.to_async(&rt).iter(|| async {
            let engine = ScannerEngine::new();
            
            // Register Windows Server-specific scanners
            engine.register_scanner("users", Box::new(users::UserScanner::new()));
            engine.register_scanner("services", Box::new(services::ServiceScanner::new()));
            engine.register_scanner("network", Box::new(network::NetworkScanner::new()));
            engine.register_scanner("system", Box::new(system::SystemScanner::new()));
            
            black_box(engine.scan_all(Some("windows_server".to_string())).await.unwrap())
        })
    });
    
    // Linux Desktop scenario
    group.bench_function("linux_desktop_scenario", |b| {
        b.to_async(&rt).iter(|| async {
            let engine = ScannerEngine::new();
            
            // Register Linux-specific scanners
            engine.register_scanner("users", Box::new(users::UserScanner::new()));
            engine.register_scanner("services", Box::new(services::ServiceScanner::new()));
            engine.register_scanner("network", Box::new(network::NetworkScanner::new()));
            engine.register_scanner("filesystem", Box::new(filesystem::FileSystemScanner::new()));
            
            black_box(engine.scan_all(Some("linux_desktop".to_string())).await.unwrap())
        })
    });
    
    group.finish();
}

// Time-critical scenarios (competition time pressure)
fn bench_time_critical(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("time_critical");
    group.measurement_time(Duration::from_secs(10)); // Shorter measurement time
    
    group.bench_function("quick_scan_and_fix", |b| {
        b.to_async(&rt).iter(|| async {
            let engine = ScannerEngine::new();
            
            // Register essential scanners only
            engine.register_scanner("users", Box::new(users::UserScanner::new()));
            engine.register_scanner("services", Box::new(services::ServiceScanner::new()));
            
            let results = engine.scan_all(None).await.unwrap();
            
            // Simulate quick fix application
            let auto_fixable: Vec<_> = results.vulnerabilities
                .iter()
                .filter(|v| v.auto_fixable)
                .take(5) // Only fix first 5 for speed
                .collect();
            
            black_box((results, auto_fixable))
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_user_scanner,
    bench_service_scanner,
    bench_network_scanner,
    bench_filesystem_scanner,
    bench_software_scanner,
    bench_system_scanner,
    bench_complete_scan,
    bench_parallel_vs_sequential,
    bench_concurrency_levels,
    bench_memory_usage,
    bench_config_loading,
    bench_database_operations,
    bench_vulnerability_processing,
    bench_competition_scenarios,
    bench_time_critical
);

criterion_main!(benches);