/****************************************************************************
 *
 * Attack injection — primitive library, implementation.
 *
 ****************************************************************************/

#include <cmath>

#include "AttackPrimitive.hpp"


namespace attack
{
namespace
{

constexpr double kPi = 3.14159265358979323846;

/**
 * xorshift32 — small, fast, deterministic PRNG.
 *
 * @param state  PRNG state, advanced in place
 * @return       next 32-bit value
 */
uint32_t xorshift32(uint32_t &state)
{
	uint32_t x = (state == 0) ? 0x9E3779B9u : state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	state = x;
	return x;
}

/// Uniform random value in [0, 1).
double uniform(uint32_t &state)
{
	return static_cast<double>(xorshift32(state) >> 8) / 16777216.0;
}

/// Standard normal random value via Box-Muller.
double gaussian(uint32_t &state)
{
	double u1 = uniform(state);
	double u2 = uniform(state);

	if (u1 < 1e-12) {u1 = 1e-12;}

	return std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * kPi * u2);
}

/// Seconds elapsed since the attack start (clamped to >= 0).
double elapsed_s(const AttackSpec &spec, uint64_t now_us)
{
	if (now_us <= spec.start_us) {return 0.0;}

	return static_cast<double>(now_us - spec.start_us) / 1e6;
}

/**
 * Append a sample to the channel's history ring buffer.
 */
void record_history(ChannelState &state, uint64_t now_us, double value)
{
	state.hist_time[state.hist_head] = now_us;
	state.hist_value[state.hist_head] = value;
	state.hist_head = (state.hist_head + 1) % kTimeSeriesCapacity;
	if (state.hist_count < kTimeSeriesCapacity) {state.hist_count++;}
}

/**
 * Value of the newest history sample with timestamp <= target_us.
 * Falls back to the oldest sample if target_us predates the history.
 * Returns false (leaving `out` untouched) when the history is empty.
 */
bool history_lookup(const ChannelState &state, uint64_t target_us, double &out)
{
	if (state.hist_count == 0) {
		return false;
	}

	// Walk backward from the newest sample; history is time-ordered.
	for (size_t i = 0; i < state.hist_count; i++) {
		const size_t idx = (state.hist_head + kTimeSeriesCapacity - 1 - i) % kTimeSeriesCapacity;

		if (state.hist_time[idx] <= target_us) {
			out = state.hist_value[idx];
			return true;
		}
	}

	// target_us predates the oldest sample: fall back to the oldest.
	const size_t oldest = (state.hist_head + kTimeSeriesCapacity - state.hist_count) % kTimeSeriesCapacity;
	out = state.hist_value[oldest];
	return true;
}

/**
 * Capture the [start - a, start] history segment into the REPLAY snapshot.
 * Offsets are relative to (start - a), so the replay lookup can index by
 * phase = (now - start) % a.
 */
void replay_capture(ChannelState &state, const AttackSpec &spec)
{
	const uint64_t period_us = static_cast<uint64_t>(spec.a * 1e6);
	const uint64_t lo = (period_us > spec.start_us) ? 0 : (spec.start_us - period_us);

	state.replay_count = 0;
	state.replay_captured = true;

	if (period_us == 0 || state.hist_count == 0) {
		return;
	}

	const size_t oldest = (state.hist_head + kTimeSeriesCapacity - state.hist_count) % kTimeSeriesCapacity;

	// Skip entries older than the segment start (t < lo).
	size_t begin = 0;

	while (begin < state.hist_count && state.hist_time[(oldest + begin) % kTimeSeriesCapacity] < lo) {
		begin++;
	}

	// Copy entries within [lo, start_us), oldest first. The sample at exactly
	// start_us is the attack's own current input, not "before start".
	for (size_t i = begin; i < state.hist_count; i++) {
		const size_t idx = (oldest + i) % kTimeSeriesCapacity;
		const uint64_t t = state.hist_time[idx];

		if (t >= spec.start_us) {
			break;
		}

		state.replay_offset[state.replay_count] = t - lo;
		state.replay_value[state.replay_count] = state.hist_value[idx];
		state.replay_count++;
	}
}

/**
 * Compute the tampered value for an already-active attack.
 *
 * The caller has already established that `type != NONE` and `now_us` is
 * within the [start_us, end_us) window.
 *
 * @return pass=false only for DROP; `value` is then irrelevant.
 */
AttackResult transform(PrimitiveType type, double truth, const AttackSpec &spec, uint64_t now_us, ChannelState &state)
{
	switch (type) {
	case PrimitiveType::BIAS:
		return AttackResult{true, truth + spec.a};

	case PrimitiveType::SPOOF:
		return AttackResult{true, spec.a};

	case PrimitiveType::NOISE:
		return AttackResult{true, truth + spec.a * gaussian(state.rng_state)};

	case PrimitiveType::SCALING:
		return AttackResult{true, truth * spec.a};

	case PrimitiveType::DRIFT:
		return AttackResult{true, truth + spec.a * elapsed_s(spec, now_us)};

	case PrimitiveType::OSCILLATION:
		return AttackResult{true, truth + spec.a * std::sin(spec.b * elapsed_s(spec, now_us) + spec.c)};

	case PrimitiveType::RANDOM_WALK:
		return AttackResult{true, (state.has_last ? state.last_value : truth) + spec.a * gaussian(state.rng_state)};

	case PrimitiveType::QUANTIZE:
		// Step must have a non-negligible magnitude, otherwise pass through.
		if (std::fabs(spec.a) > 1e-12) {return AttackResult{true, std::round(truth / spec.a) * spec.a};}
		return AttackResult{true, truth};

	case PrimitiveType::CLAMP:
		return AttackResult{true, (truth < spec.a) ? spec.a : ((truth > spec.b) ? spec.b : truth)};

	case PrimitiveType::FREEZE:
		return AttackResult{true, state.has_last ? state.last_value : truth};

	case PrimitiveType::DROP:
		return AttackResult{uniform(state.rng_state) >= spec.a, truth};

	case PrimitiveType::DELAY: {
		const uint64_t delay_us = static_cast<uint64_t>(spec.a * 1e6);
		const uint64_t target_us = (delay_us > now_us) ? 0 : (now_us - delay_us);
		double v = truth;
		history_lookup(state, target_us, v);
		return AttackResult{true, v};
	}

	case PrimitiveType::REPLAY: {
		const uint64_t period_us = static_cast<uint64_t>(spec.a * 1e6);

		if (period_us == 0) {
			return AttackResult{true, truth};  // a <= 0: nothing to replay.
		}

		if (!state.replay_captured) {
			replay_capture(state, spec);
		}

		const uint64_t phase_us = (now_us - spec.start_us) % period_us;
		double v = (state.replay_count > 0) ? state.replay_value[0] : truth;

		for (size_t i = 0; i < state.replay_count; i++) {
			if (state.replay_offset[i] <= phase_us) {
				v = state.replay_value[i];

			} else {
				break;
			}
		}

		return AttackResult{true, v};
	}

	case PrimitiveType::NONE:
		return AttackResult{true, truth};

	default:
		return AttackResult{true, truth};
	}
}

} // namespace

bool AttackLibrary::active(const AttackSpec &spec, uint64_t now_us)
{
	if (spec.type == PrimitiveType::NONE) {
		return false;
	}

	if (now_us < spec.start_us) {
		return false;
	}

	if (spec.end_us != 0 && now_us >= spec.end_us) {
		return false;
	}

	return true;
}

AttackResult AttackLibrary::apply(double truth, const AttackSpec &spec, uint64_t now_us, ChannelState &state)
{
	// Record the clean truth into history on every sample (even while idle) so
	// DELAY / REPLAY have pre-roll data to look back through.
	record_history(state, now_us, truth);

	// Disabled or outside the window: pass through, but keep last_value fresh
	// so FREEZE / RANDOM_WALK start from the current value when activated.
	if (!active(spec, now_us)) {
		state.last_value = truth;
		state.has_last = true;
		return AttackResult{true, truth};
	}

	const AttackResult result = transform(spec.type, truth, spec, now_us, state);

	// Remember the last value that passed through (FREEZE / RANDOM_WALK use it).
	if (result.pass) {
		state.last_value = result.value;
		state.has_last = true;
	}

	return result;
}

} // namespace attack
