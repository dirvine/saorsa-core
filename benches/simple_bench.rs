use criterion::{Criterion, criterion_group, criterion_main};

fn bench_simple_math(c: &mut Criterion) {
    c.bench_function("simple_math", |b| {
        b.iter(|| {
            let result = (0..1000).sum::<i64>();
            criterion::black_box(result);
        });
    });
}

criterion_group!(benches, bench_simple_math);
criterion_main!(benches);
