// Package detect implements the Unified Behavioural Feature Schema (UBFS) over
// a live MCP tool-call stream.
//
// UBFS comes from "Cross-Domain Agent-Misuse Detection: A Unified Behavioural
// Feature Space for Insider Threats and AI-Agent Execution Traces"
// (SSRN 6355658, Zenodo 10.5281/zenodo.18797847). The paper computes it
// offline, over completed traces, to show that detectors transfer between
// insider-threat logs and agent traces.
//
// The paper's other finding is the reason this package exists: structurally
// legitimate misuse — tool misuse, decomposed tasks, distributed distillation —
// evades behavioural monitoring in both domains, and the failure is
// architectural rather than a tuning problem. A detector that runs after the
// fact can only describe what already happened. Computing the same feature
// space *in the request path* is what makes it possible to act on it.
//
// # Honest coverage
//
// UBFS defines 20 features across 7 categories. An MCP proxy can observe some
// of them and not others: token counts and model identities are not visible in
// tool traffic, and features defined relative to a peer or historical baseline
// need a baseline this process does not have on a cold start.
//
// Unobservable features are reported as 0.0, which the schema defines as the
// neutral value under z-score normalisation. Each one says so explicitly in
// Coverage(), so a vector from this package is never mistaken for a complete
// one. Reporting a guess instead would be the same mistake the paper's own
// self-audit caught: a number that looks like evidence but is not.
package detect

import "math"

// Feature is a UBFS feature name. The names and ordering match
// `src/features/ubfs_schema.py` in the threat-to-governance-pipeline
// repository so a vector produced here can be fed to the models trained there.
type Feature string

// Category groups features as the schema does.
type Category string

const (
	CategoryTemporal  Category = "temporal"
	CategoryFrequency Category = "frequency"
	CategoryVolume    Category = "volume"
	CategoryScope     Category = "scope"
	CategorySequence  Category = "sequence"
	CategoryDeviation Category = "deviation"
	CategoryPrivilege Category = "privilege"
)

// The 20 UBFS features, in schema order.
const (
	// TEMPORAL
	FeatActivityHourMean    Feature = "activity_hour_mean"
	FeatSessionDurationNorm Feature = "session_duration_norm"
	FeatAfterHoursRatio     Feature = "after_hours_ratio"
	FeatWeekendActivityFlag Feature = "weekend_activity_flag"

	// FREQUENCY
	FeatPrimaryEventCount    Feature = "primary_event_count"
	FeatSecondaryEventCount  Feature = "secondary_event_count"
	FeatPeripheralEventCount Feature = "peripheral_event_count"
	FeatEventRateZScore      Feature = "event_rate_zscore"

	// VOLUME
	FeatDataVolumeNorm    Feature = "data_volume_norm"
	FeatOutputCountNorm   Feature = "output_count_norm"
	FeatVolumeVariability Feature = "volume_variability"

	// SCOPE
	FeatResourceBreadth Feature = "resource_breadth"
	FeatTargetBreadth   Feature = "target_breadth"
	FeatBreadthRatio    Feature = "breadth_ratio"

	// SEQUENCE
	FeatActionEntropy     Feature = "action_entropy"
	FeatTransitionNovelty Feature = "transition_novelty"
	FeatRepetitionScore   Feature = "repetition_score"

	// DEVIATION
	FeatPeerDistance  Feature = "peer_distance"
	FeatSelfDeviation Feature = "self_deviation"

	// PRIVILEGE
	FeatPrivilegeDeviationIndex Feature = "privilege_deviation_index"
)

// FeatureOrder is the canonical vector layout, matching ubfs_feature_names().
var FeatureOrder = []Feature{
	FeatActivityHourMean, FeatSessionDurationNorm, FeatAfterHoursRatio, FeatWeekendActivityFlag,
	FeatPrimaryEventCount, FeatSecondaryEventCount, FeatPeripheralEventCount, FeatEventRateZScore,
	FeatDataVolumeNorm, FeatOutputCountNorm, FeatVolumeVariability,
	FeatResourceBreadth, FeatTargetBreadth, FeatBreadthRatio,
	FeatActionEntropy, FeatTransitionNovelty, FeatRepetitionScore,
	FeatPeerDistance, FeatSelfDeviation,
	FeatPrivilegeDeviationIndex,
}

// CategoryOf maps each feature to its category.
var CategoryOf = map[Feature]Category{
	FeatActivityHourMean: CategoryTemporal, FeatSessionDurationNorm: CategoryTemporal,
	FeatAfterHoursRatio: CategoryTemporal, FeatWeekendActivityFlag: CategoryTemporal,

	FeatPrimaryEventCount: CategoryFrequency, FeatSecondaryEventCount: CategoryFrequency,
	FeatPeripheralEventCount: CategoryFrequency, FeatEventRateZScore: CategoryFrequency,

	FeatDataVolumeNorm: CategoryVolume, FeatOutputCountNorm: CategoryVolume,
	FeatVolumeVariability: CategoryVolume,

	FeatResourceBreadth: CategoryScope, FeatTargetBreadth: CategoryScope,
	FeatBreadthRatio: CategoryScope,

	FeatActionEntropy: CategorySequence, FeatTransitionNovelty: CategorySequence,
	FeatRepetitionScore: CategorySequence,

	FeatPeerDistance: CategoryDeviation, FeatSelfDeviation: CategoryDeviation,

	FeatPrivilegeDeviationIndex: CategoryPrivilege,
}

// Observability records whether a feature can be computed from MCP traffic.
type Observability int

const (
	// Observable is computed from the tool-call stream.
	Observable Observability = iota
	// NeedsBaseline requires peer or historical data this process may not
	// have; reported as 0.0 until a baseline is supplied.
	NeedsBaseline
	// NotObservable cannot be derived from MCP traffic at all; always 0.0.
	NotObservable
)

// coverage explains, per feature, what this package can and cannot see.
// It exists so Vector.Coverage() can state limits rather than implying that a
// zero means "normal".
var coverage = map[Feature]struct {
	Observability Observability
	Reason        string
}{
	FeatActivityHourMean:    {Observable, "hour of the first tool call"},
	FeatSessionDurationNorm: {Observable, "wall-clock span of the session"},
	FeatAfterHoursRatio:     {Observable, "fraction of calls outside configured business hours"},
	FeatWeekendActivityFlag: {Observable, "session started on a weekend"},

	FeatPrimaryEventCount:    {Observable, "tools/call count"},
	FeatSecondaryEventCount:  {Observable, "non-tool MCP requests (resources, prompts)"},
	FeatPeripheralEventCount: {Observable, "retried and errored calls"},
	FeatEventRateZScore:      {NeedsBaseline, "call rate needs a per-agent baseline to z-score against"},

	FeatDataVolumeNorm:    {Observable, "total bytes of tool arguments and results"},
	FeatOutputCountNorm:   {Observable, "count of tool results returned"},
	FeatVolumeVariability: {Observable, "standard deviation of per-call payload size"},

	FeatResourceBreadth: {Observable, "distinct tool names invoked"},
	FeatTargetBreadth:   {Observable, "distinct targets (paths, hosts, resource URIs) touched"},
	FeatBreadthRatio:    {Observable, "breadth normalised by call count"},

	FeatActionEntropy:     {Observable, "Shannon entropy of the tool-name sequence"},
	FeatTransitionNovelty: {Observable, "fraction of tool-to-tool transitions seen once"},
	FeatRepetitionScore:   {Observable, "degree of repeated calls"},

	FeatPeerDistance:  {NeedsBaseline, "no peer population is available to a single proxy"},
	FeatSelfDeviation: {NeedsBaseline, "requires this agent's own historical baseline"},

	FeatPrivilegeDeviationIndex: {NotObservable, "MCP carries no permission level to compare against"},
}

// Vector is one UBFS observation.
type Vector struct {
	values map[Feature]float64
}

// NewVector returns a zeroed vector. Zero is the schema's neutral value.
func NewVector() *Vector {
	return &Vector{values: make(map[Feature]float64, len(FeatureOrder))}
}

// Set assigns a feature value.
func (v *Vector) Set(f Feature, value float64) {
	// NaN and Inf would propagate silently into every downstream score and
	// turn a comparison into a permanent false. They are clamped to the
	// neutral value instead, which is wrong in a way that is at least visible.
	if math.IsNaN(value) || math.IsInf(value, 0) {
		value = 0
	}
	v.values[f] = value
}

// Get returns a feature value, or 0.0 if unset.
func (v *Vector) Get(f Feature) float64 { return v.values[f] }

// Slice returns the vector in canonical order, ready for a model expecting the
// same layout as the Python implementation.
func (v *Vector) Slice() []float64 {
	out := make([]float64, len(FeatureOrder))
	for i, f := range FeatureOrder {
		out[i] = v.values[f]
	}
	return out
}

// Coverage reports which features this observation actually measured.
//
// Callers exporting a vector as evidence should export this alongside it: a
// 0.0 from an unobservable feature and a 0.0 from a genuinely average one are
// indistinguishable in the vector itself.
func (v *Vector) Coverage() map[Feature]string {
	out := make(map[Feature]string, len(coverage))
	for f, c := range coverage {
		switch c.Observability {
		case Observable:
			out[f] = "observed: " + c.Reason
		case NeedsBaseline:
			out[f] = "neutral (0.0), needs baseline: " + c.Reason
		case NotObservable:
			out[f] = "neutral (0.0), not observable: " + c.Reason
		}
	}
	return out
}

// ObservableFeatures lists the features this package computes for real.
func ObservableFeatures() []Feature {
	var out []Feature
	for _, f := range FeatureOrder {
		if coverage[f].Observability == Observable {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

// shannonEntropy returns the entropy of a distribution, in bits.
//
// Returned normalised to [0,1] by dividing by log2(n), so a session using 3
// tools evenly and one using 30 tools evenly both score 1.0. Without that, the
// value grows with vocabulary size and a threshold tuned on one workload is
// meaningless on another.
func shannonEntropy(counts map[string]int) float64 {
	total := 0
	for _, c := range counts {
		total += c
	}
	if total == 0 || len(counts) <= 1 {
		// A single distinct action carries no uncertainty.
		return 0
	}

	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}

	maxH := math.Log2(float64(len(counts)))
	if maxH == 0 {
		return 0
	}
	return h / maxH
}

// transitionNovelty is the fraction of observed transitions that occurred
// exactly once.
//
// A decomposed task walks a wide, shallow path through the tool graph: many
// distinct transitions, each taken once. A repetitive legitimate workflow
// walks the same few edges repeatedly.
func transitionNovelty(transitions map[string]int) float64 {
	if len(transitions) == 0 {
		return 0
	}
	once := 0
	for _, c := range transitions {
		if c == 1 {
			once++
		}
	}
	return float64(once) / float64(len(transitions))
}

// repetitionScore is the fraction of calls that repeat an already-seen action.
//
// The complement of distinct-ratio: 0.0 when every call is unique, approaching
// 1.0 when one action is called over and over.
func repetitionScore(counts map[string]int, total int) float64 {
	if total <= 1 {
		return 0
	}
	distinct := len(counts)
	return float64(total-distinct) / float64(total-1)
}

// stdDev returns the population standard deviation of xs.
func stdDev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))

	var ss float64
	for _, x := range xs {
		d := x - mean
		ss += d * d
	}
	return math.Sqrt(ss / float64(len(xs)))
}
