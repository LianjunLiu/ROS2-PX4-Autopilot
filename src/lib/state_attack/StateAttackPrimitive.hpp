/****************************************************************************
 *
 * Post-EKF state attack — primitive library.
 *
 * Pure "how to tamper with a single state scalar" logic. No uORB / matrix
 * dependency, so it compiles and unit-tests standalone. This is the firmware
 * mirror of the gz_bridge `attack/` library (see attack_injection_design.md):
 * the primitive math is reused verbatim, but the code is independent because
 * firmware cannot link the simulation-side library.
 *
 * Scope vs. the gz_bridge library
 * -------------------------------
 * - The 13 wire type codes (NONE=0 .. REPLAY=13) are kept stable for
 *   protocol compatibility with attack_command semantics.
 * - The 11 point transforms (bias .. freeze) are fully implemented; DROP
 *   degrades to pass-through because an in-place state field has no message
 *   to drop (design §9 #2).
 * - DELAY / REPLAY are time-series transforms and are NOT implemented for the
 *   state attack (design §10): they would need a per-channel history buffer,
 *   so here they pass through. No history buffer is allocated, keeping the
 *   firmware memory footprint tiny (one scalar per channel). To implement
 *   them, follow the gz_bridge `attack/` library's time-series design.
 *
 ****************************************************************************/

#pragma once

#include <cstddef>
#include <cstdint>

namespace state_attack
{

/**
 * Attack shape for one state scalar. The numeric value is the wire number
 * carried by state_attack_command / state_attack_*_status, so it must stay
 * stable once released.
 */
enum class StatePrimitiveType : uint8_t {
	NONE = 0,      ///< Pass-through (attack disabled).
	BIAS,          ///< v = truth + a
	SPOOF,         ///< v = a
	NOISE,         ///< v = truth + N(0, a) (seeded)
	SCALING,       ///< v = truth * a
	DRIFT,         ///< v = truth + a * (t - start) (a = slope)
	OSCILLATION,   ///< v = truth + a * sin(b*(t - start) + c)
	RANDOM_WALK,   ///< v = v_last + N(0, a) (stateful)
	QUANTIZE,      ///< v = round(truth / a) * a (a = step)
	CLAMP,         ///< v = clamp(truth, a, b) (a = min, b = max)
	FREEZE,        ///< v = v_last (stateful)
	DROP,          ///< pass-through: no message to drop here (design §9 #2)
	DELAY,         ///< NOT implemented (design §10) — pass-through
	REPLAY,        ///< NOT implemented (design §10) — pass-through
};

/**
 * State-channel vocabulary. A channel is a plain index; its meaning lives at
 * the injection point (mc_pos_control for nav, mc_att_control for attitude).
 */
enum class StateChannel : uint8_t {
	NAV_POS_X = 0,  ///< NED north position [m]
	NAV_POS_Y,      ///< NED east position [m]
	NAV_POS_Z,      ///< NED down position [m]
	NAV_VEL_X,      ///< NED north velocity [m/s]
	NAV_VEL_Y,      ///< NED east velocity [m/s]
	NAV_VEL_Z,      ///< NED down velocity [m/s]
	NAV_HEADING,    ///< heading [rad], -pi..pi
	ATT_ROLL = 7,   ///< roll [rad]
	ATT_PITCH,      ///< pitch [rad]
	ATT_YAW,        ///< yaw [rad]
	NUM_CHANNELS = 10,
};

/// Number of state-attack channels (nav 7 + attitude 3).
constexpr size_t kNumStateChannels = static_cast<size_t>(StateChannel::NUM_CHANNELS);

/// Array index of a channel in the per-channel tables.
constexpr size_t index_of(StateChannel ch)
{
	return static_cast<size_t>(ch);
}

/**
 * Serializable attack configuration for one channel (travels in
 * state_attack_command; logged for reproducibility). Pure value; runtime state
 * lives in StateChannelState.
 */
struct StateAttackSpec {
	StatePrimitiveType type{StatePrimitiveType::NONE};
	double a{0.0};
	double b{0.0};
	double c{0.0};
	double d{0.0};
	uint64_t start_us{0};   ///< Absolute hrt time the attack becomes active.
	uint64_t end_us{0};     ///< Absolute hrt time the attack ends; 0 = no end.
	uint32_t seed{0};       ///< RNG seed; 0 = per-channel deterministic default.
};

/**
 * Per-channel runtime state, owned by StateAttackManager (not serialized).
 * Intentionally small: no history buffer (DELAY / REPLAY are not implemented).
 */
struct StateChannelState {
	double last_value{0.0};   ///< Last value that passed through (FREEZE / RANDOM_WALK).
	bool has_last{false};     ///< Whether last_value is valid.
	uint32_t rng_state{0};    ///< PRNG state, seeded by StateAttackManager::set().
};

/**
 * Stateless attack math. All per-channel state is passed in via
 * StateChannelState, so this class holds no mutable state of its own.
 */
class StateAttackLibrary
{
public:
	/**
	 * Apply an attack to a scalar truth value, returning the (possibly)
	 * tampered value. There is no "drop" outcome: an in-place state field is
	 * always read, so DROP passes through.
	 */
	static double apply(double truth, const StateAttackSpec &spec, uint64_t now_us, StateChannelState &state);

	/// Whether an attack is currently within its active [start_us, end_us) window.
	static bool active(const StateAttackSpec &spec, uint64_t now_us);
};

} // namespace state_attack
