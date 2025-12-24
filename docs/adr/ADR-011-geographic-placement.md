# ADR-011: Geographic-Aware Placement

## Status

Accepted

## Context

Data placement in distributed systems involves trade-offs:

- **Latency**: Storing data close to users improves access speed
- **Reliability**: Geographic distribution protects against regional failures
- **Regulation**: Some data must stay within jurisdictional boundaries (GDPR, etc.)
- **Security**: Diverse placement resists localized attacks

Traditional DHTs (like Kademlia) select storage nodes based solely on key proximity in the XOR metric space, ignoring physical location. This can result in:

- All replicas in the same data center
- Trans-Atlantic latency for local operations
- Regulatory non-compliance
- Vulnerability to regional outages

We needed placement that considers geography while maintaining DHT efficiency.

## Decision

We implement **geographic-aware placement** that layers regional preferences on top of Kademlia routing.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Geographic-Aware Placement                    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Placement Request                      │   │
│  │  key: Key, data: Vec<u8>, constraints: PlacementConstraints│   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Candidate Selection                     │   │
│  │  1. Get K closest nodes (Kademlia XOR distance)          │   │
│  │  2. Expand to 2K candidates if needed                    │   │
│  │  3. Filter by constraints (region, latency, capacity)    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Diversity Enforcement                   │   │
│  │  • Min 3 distinct geographic regions                     │   │
│  │  • Max 2 nodes per /16 subnet                            │   │
│  │  • Balance across regions proportionally                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Weighted Selection                      │   │
│  │  w_i = (τ_i^α) × (p_i^β) × (c_i^γ) × d_i                 │   │
│  │  Select top K by weight                                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Placement Decision                      │   │
│  │  • Primary nodes (store data)                            │   │
│  │  • Witness nodes (attest to storage)                     │   │
│  │  • Regional distribution map                             │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Network Regions

```rust
// src/placement/regions.rs

/// Major geographic regions for diversity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkRegion {
    /// Europe (EU, UK, etc.)
    Europe,

    /// North America (US, Canada)
    NorthAmerica,

    /// South America (Brazil, Argentina, etc.)
    SouthAmerica,

    /// Asia Pacific (Japan, Korea, Australia, etc.)
    AsiaPacific,

    /// Middle East & Africa
    MiddleEastAfrica,

    /// Unknown/Unclassified
    Unknown,
}

impl NetworkRegion {
    /// Get region from IP address using BGP data
    pub fn from_ip(ip: IpAddr, geo_provider: &impl GeoProvider) -> Self {
        geo_provider
            .lookup(ip)
            .map(|info| info.region)
            .unwrap_or(NetworkRegion::Unknown)
    }
}
```

### BGP-Based Geolocation

```rust
// src/bgp_geo_provider.rs

/// GeoIP provider using BGP routing data
pub struct BgpGeoProvider {
    /// IP-to-ASN mappings
    ip_to_asn: IpLookup<u32>,

    /// ASN-to-region mappings
    asn_to_region: HashMap<u32, NetworkRegion>,
}

impl GeoProvider for BgpGeoProvider {
    fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let asn = self.ip_to_asn.lookup(ip)?;
        let region = self.asn_to_region.get(&asn).copied()?;

        Some(GeoInfo {
            ip,
            asn,
            region,
            country: None, // Optional detailed info
        })
    }
}
```

### Placement Constraints

```rust
// src/placement/constraints.rs

/// Constraints for data placement
#[derive(Clone, Debug, Default)]
pub struct PlacementConstraints {
    /// Required regions (data must be in these regions)
    pub required_regions: Option<Vec<NetworkRegion>>,

    /// Forbidden regions (data must NOT be in these regions)
    pub forbidden_regions: Option<Vec<NetworkRegion>>,

    /// Minimum number of distinct regions
    pub min_regions: usize,

    /// Maximum latency to any replica (milliseconds)
    pub max_latency_ms: Option<u64>,

    /// Minimum available storage per node
    pub min_storage_gb: Option<u64>,

    /// Data sovereignty requirements
    pub sovereignty: Option<DataSovereignty>,
}

/// Data sovereignty requirements for regulatory compliance
#[derive(Clone, Debug)]
pub enum DataSovereignty {
    /// GDPR: Data must stay in EU/adequate countries
    Gdpr,

    /// US: Data must stay in US
    UnitedStates,

    /// Custom country list
    Countries(Vec<CountryCode>),

    /// No restrictions
    Global,
}
```

### Weighted Placement Strategy

```rust
// src/placement/weighted_strategy.rs

pub struct WeightedPlacementStrategy {
    config: WeightConfig,
    trust_manager: Arc<EigenTrustManager>,
    geo_router: Arc<GeographicRouter>,
}

#[derive(Clone)]
pub struct WeightConfig {
    /// Exponent for trust score (α)
    pub trust_exponent: f64,  // Default: 2.0

    /// Exponent for performance score (β)
    pub perf_exponent: f64,  // Default: 1.0

    /// Exponent for capacity score (γ)
    pub capacity_exponent: f64,  // Default: 0.5

    /// Diversity bonus range
    pub diversity_bonus_range: (f64, f64),  // Default: (1.0, 2.0)
}

impl WeightedPlacementStrategy {
    /// Select nodes for placement
    pub async fn select(
        &self,
        key: &Key,
        replica_count: usize,
        constraints: &PlacementConstraints,
    ) -> Result<PlacementDecision> {
        // 1. Get candidate nodes (2x replica count for flexibility)
        let candidates = self.get_candidates(key, replica_count * 2).await;

        // 2. Filter by constraints
        let filtered: Vec<_> = candidates
            .into_iter()
            .filter(|n| self.meets_constraints(n, constraints))
            .collect();

        // 3. Compute weights
        let mut weighted: Vec<_> = filtered
            .iter()
            .map(|n| (n, self.compute_weight(n)))
            .collect();

        // 4. Apply diversity bonus
        self.apply_diversity_bonus(&mut weighted, constraints.min_regions);

        // 5. Select top K by weight
        weighted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let selected: Vec<_> = weighted
            .into_iter()
            .take(replica_count)
            .map(|(n, _)| n.clone())
            .collect();

        // 6. Verify diversity requirements met
        self.verify_diversity(&selected, constraints)?;

        Ok(PlacementDecision {
            key: key.clone(),
            nodes: selected,
            regions: self.compute_region_distribution(&selected),
        })
    }

    /// Compute node weight: w_i = (τ_i^α) × (p_i^β) × (c_i^γ) × d_i
    fn compute_weight(&self, node: &NodeInfo) -> f64 {
        let trust = self.trust_manager.get_score(&node.id);
        let perf = node.performance_score;
        let capacity = node.capacity_score;

        trust.powf(self.config.trust_exponent)
            * perf.powf(self.config.perf_exponent)
            * capacity.powf(self.config.capacity_exponent)
    }

    /// Apply diversity bonus to underrepresented regions
    fn apply_diversity_bonus(
        &self,
        weighted: &mut [(NodeInfo, f64)],
        min_regions: usize,
    ) {
        let region_counts = self.count_by_region(weighted);

        for (node, weight) in weighted.iter_mut() {
            let region = self.geo_router.get_region(&node.addr);
            let region_count = region_counts.get(&region).copied().unwrap_or(0);

            // Bonus inversely proportional to region representation
            let bonus = if region_count < 2 {
                self.config.diversity_bonus_range.1  // Max bonus (2.0)
            } else if region_count < 5 {
                1.5
            } else {
                self.config.diversity_bonus_range.0  // No bonus (1.0)
            };

            *weight *= bonus;
        }
    }
}
```

### Region Distribution in Placement

```rust
#[derive(Clone, Debug)]
pub struct PlacementDecision {
    pub key: Key,
    pub nodes: Vec<NodeInfo>,
    pub regions: HashMap<NetworkRegion, usize>,
}

impl PlacementDecision {
    /// Check if placement meets diversity requirements
    pub fn is_diverse(&self, min_regions: usize) -> bool {
        self.regions.len() >= min_regions
    }

    /// Get regional distribution as percentages
    pub fn regional_percentages(&self) -> HashMap<NetworkRegion, f64> {
        let total = self.nodes.len() as f64;
        self.regions
            .iter()
            .map(|(r, c)| (*r, *c as f64 / total))
            .collect()
    }
}
```

## Consequences

### Positive

1. **Latency reduction**: Data stored closer to users
2. **Regulatory compliance**: Data sovereignty constraints respected
3. **Resilience**: Regional failures don't lose all replicas
4. **Attack resistance**: Geographic diversity limits regional attacks
5. **Flexibility**: Constraints are optional and composable

### Negative

1. **Reduced node pool**: Constraints may limit placement options
2. **Geolocation inaccuracy**: BGP data not always precise
3. **Latency for constraints**: More complex selection algorithm
4. **Network imbalance**: Some regions may have fewer nodes

### Neutral

1. **BGP data maintenance**: Must update IP-to-region mappings
2. **Constraint complexity**: More options to configure

## Geolocation Accuracy

BGP-based geolocation has limitations:

| Method | Accuracy | Latency | Privacy |
|--------|----------|---------|---------|
| GPS coordinates | High | Low | Poor (reveals exact location) |
| Commercial GeoIP | Medium-High | Low | Medium |
| BGP/ASN mapping | Medium | Low | Good (only reveals ISP region) |
| Latency triangulation | Medium | High | Good |

We chose BGP/ASN mapping because:
- No external service dependency
- Reasonable accuracy for regional placement
- Privacy-preserving (doesn't reveal precise location)
- Open data sources available

## Alternatives Considered

### Pure Kademlia Placement

Ignore geography entirely.

**Rejected because**:
- No latency optimization
- No regulatory compliance
- Vulnerable to regional failures

### GPS-Based Placement

Use precise coordinates.

**Rejected because**:
- Privacy concerns
- Requires GPS hardware
- Overkill for regional placement

### Commercial GeoIP Services

Use MaxMind or similar.

**Rejected because**:
- External dependency
- Licensing costs
- Potential single point of failure

### Latency-Based Selection Only

Choose lowest-latency nodes.

**Rejected because**:
- Doesn't ensure regional diversity
- May cluster in single region
- No regulatory compliance

## References

- [Geographic Replication in Distributed Storage](https://www.usenix.org/conference/osdi18/presentation/huang-peng)
- [BGP Routing Data](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris)
- [GDPR Data Residency Requirements](https://gdpr.eu/article-44/)
- [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md)
- [ADR-005: S/Kademlia Witness Protocol](./ADR-005-skademlia-witness-protocol.md)
