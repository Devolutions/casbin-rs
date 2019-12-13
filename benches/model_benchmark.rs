use criterion::{criterion_group, criterion_main, Benchmark, Criterion};

use casbin_rs::adapter::FileAdapter;
use casbin_rs::enforcer::Enforcer;
use casbin_rs::management_api::MgmtApi;
use casbin_rs::model::Model;

fn benchmark_basic_model(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/basic_model.conf");
    let adapter = FileAdapter::new("examples/basic_policy.csv");
    let e = Enforcer::new(m, adapter);

    c.bench_function("Basic Model", |b| {
        b.iter(|| e.enforce(vec!["alice", "data1", "read"]))
    });
}

fn benchmark_rbac_model(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/rbac_model.conf");
    let adapter = FileAdapter::new("examples/rbac_policy.csv");
    let e = Enforcer::new(m, adapter);

    c.bench_function("RBAC Model", |b| {
        b.iter(|| e.enforce(vec!["alice", "data2", "read"]))
    });
}

fn benchmark_rbac_model_small(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/rbac_model.conf");
    let adapter = FileAdapter::new("examples/empty_policy.csv");
    let mut e = Enforcer::new(m, adapter);
    e.enable_auto_build_role_links(false);

    // 100 roles, 10 resources.
    for i in 0..100 {
        e.add_policy(vec![
            format!("group{}", i).as_str(),
            format!("data{}", i / 10).as_str(),
            "read",
        ])
        .unwrap();
    }
    // 1000 users.
    for i in 0..1000 {
        e.add_grouping_policy(vec![
            format!("user{}", i).as_str(),
            format!("group{}", i / 10).as_str(),
        ])
        .unwrap();
    }

    e.build_role_links().unwrap();

    c.bench(
        "benches",
        Benchmark::new("RBAC Model - Small", move |b| {
            b.iter(|| e.enforce(vec!["user501", "data9", "read"]))
        })
        .sample_size(20),
    );
}

fn benchmark_rbac_model_medium(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/rbac_model.conf");
    let adapter = FileAdapter::new("examples/empty_policy.csv");
    let mut e = Enforcer::new(m, adapter);
    e.enable_auto_build_role_links(false);

    // 1000 roles, 100 resources.
    for i in 0..1000 {
        e.add_policy(vec![
            format!("group{}", i).as_str(),
            format!("data{}", i / 10).as_str(),
            "read",
        ])
        .unwrap();
    }
    // 10000 users.
    for i in 0..10000 {
        e.add_grouping_policy(vec![
            format!("user{}", i).as_str(),
            format!("group{}", i / 10).as_str(),
        ])
        .unwrap();
    }

    e.build_role_links().unwrap();

    c.bench(
        "benches",
        Benchmark::new("RBAC Model - Medium", move |b| {
            b.iter(|| e.enforce(vec!["user5001", "data150", "read"]))
        })
        .sample_size(10),
    );
}

fn benchmark_rbac_model_large(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/rbac_model.conf");
    let adapter = FileAdapter::new("examples/empty_policy.csv");
    let mut e = Enforcer::new(m, adapter);
    e.enable_auto_build_role_links(false);

    // 10000 roles, 1000 resources.
    for i in 0..10000 {
        e.add_policy(vec![
            format!("group{}", i).as_str(),
            format!("data{}", i / 10).as_str(),
            "read",
        ])
        .unwrap();
    }
    // 100_000 users.
    for i in 0..100_000 {
        e.add_grouping_policy(vec![
            format!("user{}", i).as_str(),
            format!("group{}", i / 10).as_str(),
        ])
        .unwrap();
    }

    e.build_role_links().unwrap();

    c.bench(
        "benches",
        Benchmark::new("RBAC Model - Large", move |b| {
            b.iter(|| e.enforce(vec!["user50001", "data1500", "read"]))
        })
        .sample_size(10),
    );
}

fn benchmark_rbac_model_with_resource_roles(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/rbac_with_resource_roles_model.conf");
    let adapter = FileAdapter::new("examples/rbac_with_resource_roles_policy.csv");
    let e = Enforcer::new(m, adapter);

    c.bench_function("RBAC Model - with resource roles", |b| {
        b.iter(|| e.enforce(vec!["alice", "data1", "read"]))
    });
}

fn benchmark_rbac_model_with_domains(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/rbac_with_domains_model.conf");
    let adapter = FileAdapter::new("examples/rbac_with_domains_policy.csv");
    let e = Enforcer::new(m, adapter);

    c.bench_function("RBAC Model - with domains", |b| {
        b.iter(|| e.enforce(vec!["alice", "domain1", "data1", "read"]))
    });
}

fn benchmark_keymatch_model(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/keymatch_model.conf");
    let adapter = FileAdapter::new("examples/keymatch_policy.csv");
    let e = Enforcer::new(m, adapter);

    c.bench_function("Keymatch Model", |b| {
        b.iter(|| e.enforce(vec!["alice", "/alice_data/resource1", "GET"]))
    });
}

fn benchmark_rbac_model_with_deny(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/rbac_with_deny_model.conf");
    let adapter = FileAdapter::new("examples/rbac_with_deny_policy.csv");
    let e = Enforcer::new(m, adapter);

    c.bench_function("RBAC Model - with deny", |b| {
        b.iter(|| e.enforce(vec!["alice", "data1", "read"]))
    });
}

fn benchmark_priority_model(c: &mut Criterion) {
    let mut m = Model::new();
    m.load_model("examples/priority_model.conf");
    let adapter = FileAdapter::new("examples/priority_policy.csv");
    let e = Enforcer::new(m, adapter);

    c.bench_function("Priority Model", |b| {
        b.iter(|| e.enforce(vec!["alice", "data1", "read"]))
    });
}

criterion_group!(
    benches,
    benchmark_basic_model,
    benchmark_rbac_model,
    benchmark_rbac_model_small,
    benchmark_rbac_model_with_resource_roles,
    benchmark_rbac_model_with_domains,
    benchmark_keymatch_model,
    benchmark_rbac_model_with_deny,
    benchmark_priority_model
);
criterion_group!(
    heavy_benches,
    benchmark_rbac_model_medium,
    benchmark_rbac_model_large
);
criterion_main!(benches, heavy_benches);
