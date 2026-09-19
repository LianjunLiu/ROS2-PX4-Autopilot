/****************************************************************************
 *
 * Post-EKF state attack — primitive library, implementation.
 *
 ****************************************************************************/

#include <cmath>

#include "StateAttackPrimitive.hpp"


namespace state_attack
{
namespace
{

constexpr double kPi = 3.14159265358979323846;

/**
 * xorshift32 — small, fast, deterministic PRNG.
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
double elapsed_s(const StateAttackSpec &spec, uint64_t now_us)
{
	if (now_us <= spec.start_us) {return 0.0;}

	return static_cast<double>(now_us - spec.start_us) / 1e6;
}

/**
 * Compute the tampered value for an already-active attack. The caller has
 * already established that `type != NONE` and `now_us` is within the
 * [start_us, end_us) window.
 */
double transform(StatePrimitiveType type, double truth, const StateAttackSpec &spec, uint64_t now_us,
		 StateChannelState &state)
{
	switch (type) {
	case StatePrimitiveType::BIAS:
		return truth + spec.a;

	case StatePrimitiveType::SPOOF:
		return spec.a;

	case StatePrimitiveType::NOISE:
		return truth + spec.a * gaussian(state.rng_state);

	case StatePrimitiveType::SCALING:
		return truth * spec.a;

	case StatePrimitiveType::DRIFT:
		return truth + spec.a * elapsed_s(spec, now_us);

	case StatePrimitiveType::OSCILLATION:
		return truth + spec.a * std::sin(spec.b * elapsed_s(spec, now_us) + spec.c);

	case StatePrimitiveType::RANDOM_WALK:
		return (state.has_last ? state.last_value : truth) + spec.a * gaussian(state.rng_state);

	case StatePrimitiveType::QUANTIZE:
		// Step must have a non-negligible magnitude, otherwise pass through.
		if (std::fabs(spec.a) > 1e-12) {return std::round(truth / spec.a) * spec.a;}
		return truth;

	case StatePrimitiveType::CLAMP:
		return (truth < spec.a) ? spec.a : ((truth > spec.b) ? spec.b : truth);

	case StatePrimitiveType::FREEZE:
		return state.has_last ? state.last_value : truth;

	case StatePrimitiveType::DROP:
		// An in-place state field has no message to drop: degrade to no-op (design §9 #2).
		return truth;

	case StatePrimitiveType::DELAY:
		// Time-series primitives not implemented for the state attack (design §10).
		return truth;
		
	case StatePrimitiveType::REPLAY:
		// Time-series primitives not implemented for the state attack (design §10).
		return truth;

	case StatePrimitiveType::NONE:
	default:
		return truth;
	}
}

} // namespace

bool StateAttackLibrary::active(const StateAttackSpec &spec, uint64_t now_us)
{
	if (spec.type == StatePrimitiveType::NONE) {
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

double StateAttackLibrary::apply(double truth, const StateAttackSpec &spec, uint64_t now_us, StateChannelState &state)
{
	// Disabled or outside the window: pass through, but keep last_value fresh
	// so FREEZE / RANDOM_WALK start from the current value when activated.
	if (!active(spec, now_us)) {
		state.last_value = truth;
		state.has_last = true;
		return truth;
	}

	const double result = transform(spec.type, truth, spec, now_us, state);

	state.last_value = result;
	state.has_last = true;

	return result;
}

} // namespace state_attack
