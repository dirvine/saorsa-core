// Simple gossip benchmark
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("simple");
    group.bench_function("noop", |b| b.iter(|| black_box(42)));
    group.finish();
}

criterion_group!(benches, bench_simple);
criterion_main!(benches);
