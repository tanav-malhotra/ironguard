use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ironguard::{
    config::Config,
    scanners::ScannerEngine,
};

/// Professional throughput analysis benchmarks
/// Measures configuration processing and engine setup efficiency

fn bench_config_processing_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_processing");
    
    for config_complexity in [1, 5, 10, 25].iter() {
        group.throughput(Throughput::Elements(*config_complexity as u64));
        group.bench_with_input(
            BenchmarkId::new("config_operations", config_complexity),
            config_complexity,
            |b, &complexity| {
                b.iter(|| {
                    let configs: Vec<_> = (0..complexity)
                        .map(|_| create_throughput_config().unwrap())
                        .collect();
                    
                    black_box(configs.len())
                })
            },
        );
    }
    group.finish();
}

fn bench_engine_initialization_rate(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_initialization_rate");
    
    for engine_count in [1, 5, 10, 20].iter() {
        group.throughput(Throughput::Elements(*engine_count as u64));
        group.bench_with_input(
            BenchmarkId::new("engines_created", engine_count),
            engine_count,
            |b, &count| {
                b.iter(|| {
                    let engines: Result<Vec<_>, _> = (0..count)
                        .map(|_| {
                            let config = create_throughput_config().unwrap();
                            ScannerEngine::new(config)
                        })
                        .collect();
                    
                    black_box(engines.unwrap().len())
                })
            },
        );
    }
    group.finish();
}

fn bench_config_validation_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_validation_throughput");
    
    for validation_count in [100, 500, 1000, 2500].iter() {
        group.throughput(Throughput::Elements(*validation_count as u64));
        group.bench_with_input(
            BenchmarkId::new("validations_performed", validation_count),
            validation_count,
            |b, &count| {
                b.iter(|| {
                    let config = create_throughput_config().unwrap();
                    let validations: Vec<bool> = (0..count)
                        .map(|_| validate_config_performance(&config))
                        .collect();
                    
                    black_box(validations.len())
                })
            },
        );
    }
    group.finish();
}

fn bench_memory_efficiency_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");
    
    for config_size in [1, 10, 50, 100].iter() {
        group.throughput(Throughput::Bytes((*config_size * 1024) as u64));
        group.bench_with_input(
            BenchmarkId::new("config_size_kb", config_size),
            config_size,
            |b, &size| {
                b.iter(|| {
                    let mut configs = Vec::new();
                    for _ in 0..size {
                        configs.push(create_throughput_config().unwrap());
                    }
                    
                    let efficiency = configs.len() as f64 / size as f64;
                    black_box((configs.len(), efficiency))
                })
            },
        );
    }
    group.finish();
}

fn create_throughput_config() -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = Config::default();
    
    // Optimize for throughput testing
    config.scanners.users = true;
    config.scanners.services = true;
    config.scanners.network = true;
    config.scanners.filesystem = true;
    config.scanners.software = true;
    config.scanners.system = true;
    
    config.general.timeout = 60;
    config.general.max_concurrent = 8;
    
    Ok(config)
}

fn validate_config_performance(config: &Config) -> bool {
    config.general.timeout > 0 
        && config.general.max_concurrent > 0 
        && config.general.max_concurrent <= 32
        && config.scanners.users
        && config.scanners.services
        && config.scanners.network
        && config.scanners.filesystem
        && config.scanners.software
        && config.scanners.system
}

criterion_group!(
    throughput_benches,
    bench_config_processing_throughput,
    bench_engine_initialization_rate,
    bench_config_validation_throughput,
    bench_memory_efficiency_config
);

criterion_main!(throughput_benches);