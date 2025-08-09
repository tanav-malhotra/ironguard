use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ironguard::{
    config::Config,
    scanners::ScannerEngine,
};

/// Professional performance benchmarks for scanning operations
/// Measures scanning engine initialization and basic performance

fn bench_scanner_engine_initialization(c: &mut Criterion) {
    c.bench_function("engine_initialization", |b| {
        b.iter(|| {
            let config = create_benchmark_config().unwrap();
            black_box(ScannerEngine::new(config).unwrap())
        })
    });
}

fn bench_config_creation(c: &mut Criterion) {
    c.bench_function("config_creation", |b| {
        b.iter(|| {
            black_box(create_benchmark_config().unwrap())
        })
    });
}

fn bench_config_validation(c: &mut Criterion) {
    c.bench_function("config_validation", |b| {
        b.iter(|| {
            let config = create_benchmark_config().unwrap();
            black_box(validate_config(&config))
        })
    });
}

fn create_benchmark_config() -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = Config::default();
    
    // Enable all scanners for comprehensive benchmarking
    config.scanners.users = true;
    config.scanners.services = true;
    config.scanners.network = true;
    config.scanners.filesystem = true;
    config.scanners.software = true;
    config.scanners.system = true;
    
    // Benchmark-appropriate settings
    config.general.timeout = 30;
    config.general.max_concurrent = 4;
    
    Ok(config)
}

fn validate_config(config: &Config) -> bool {
    config.general.timeout > 0 
        && config.general.max_concurrent > 0 
        && config.general.max_concurrent <= 16
}

criterion_group!(
    benches,
    bench_scanner_engine_initialization,
    bench_config_creation,
    bench_config_validation
);

criterion_main!(benches);