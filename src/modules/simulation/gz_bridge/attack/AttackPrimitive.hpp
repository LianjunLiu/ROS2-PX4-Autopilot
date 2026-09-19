/****************************************************************************
 *
 * Attack injection — primitive library.
 *
 * Pure "how to tamper with a single scalar value" logic. No PX4 / Gazebo / 
 * uORB dependency, so it compiles and unit-tests standalone.
 *
 * How attack injection works
 * --------------------------
 * The feature tampers with the data the flight controller consumes (GPS
 * fixes and motor outputs) so we can study how it reacts to a compromise.
 * Injection stays out of PX4's own flight code and lives entirely in the
 * gz_bridge process, split into three layers:
 *
 *   Layer A — stateless tampering math. Thirteen primitives
 *       (bias, spoof, noise, scaling, drift, oscillation, random walk,
 *       quantize, clamp, freeze, drop, delay, replay) turn one clean
 *       scalar into a tampered one, or decide to drop it. Eleven are
 *       point transforms; delay / replay are time-series transforms that
 *       read back through the channel's recorded history.
 *
 *   Layer B — thin injection points inside gz_bridge:
 *       GZBridge::navSatCallback     GPS lat/lon/alt + velocity N/E/D
 *       GZMixingInterfaceESC         the 4 motor outputs
 *       Each point feeds its "truth" value to the manager and publishes
 *       whatever comes back (or drops the message).
 *
 *   Layer C — AttackManager: routing + control + status. It owns a
 *       per-channel table of AttackSpec (configuration) + ChannelState
 *       (runtime), consumes uORB `attack_command`, applies attacks on
 *       demand, and publishes `attack_status` at 10 Hz.
 *
 * Data flow: an external node publishes attack_command -> AttackManager
 * resolves the relative window (t0 delay / t1 duration) to absolute hrt
 * time and stores the spec -> each injection point calls apply(truth) every
 * cycle -> the tampered value (or a drop) is what the flight controller
 * sees. Configuration is zero-parameter: it all travels as uORB messages and
 * is logged to ulog, so a run is reproducible from its log alone.
 *
 ****************************************************************************/
#pragma once

#include <cstddef>
#include <cstdint>

namespace attack
{

/**
 * Attack shape: how a single scalar value is tampered with.
 *
 * The numeric value is the wire number carried by attack_command /
 * attack_status, so it must stay stable once released.
 */
enum class PrimitiveType : uint8_t {
	NONE = 0,      ///< Pass-through (attack disabled).
	BIAS,          ///< v = truth + a
	SPOOF,         ///< v = a
	NOISE,         ///< v = truth + N(0, a) (seeded)
	SCALING,       ///< v = truth * a
	DRIFT,         ///< v = truth + a * (t - start) (a = slope)
	OSCILLATION,   ///< v = truth + a * sin(b*(t - start) + c) (a = amplitude, b = angular rate, c = phase)
	RANDOM_WALK,   ///< v = v_last + N(0, a) (stateful)
	QUANTIZE,      ///< v = round(truth / a) * a (a = step)
	CLAMP,         ///< v = clamp(truth, a, b) (a = min, b = max)
	FREEZE,        ///< v = v_last (stateful)
	DROP,          ///< drop this message with probability a (a = drop probability)
	DELAY,         ///< v = value from a seconds ago (a = delay [s])
	REPLAY,        ///< v = loop of the a seconds before start (a = segment length [s])
};

/**
 * Injection-point vocabulary.
 *
 * A channel is a plain index; its meaning lives at the injection point
 * (GZBridge for GPS, GZMixingInterfaceESC for motors).
 */
enum class Channel : uint8_t {
	GPS_LAT = 0,        ///< GPS latitude [deg]
	GPS_LON,            ///< GPS longitude [deg]
	GPS_ALT,            ///< GPS altitude [m]
	GPS_VEL_N,          ///< GPS velocity north [m/s]
	GPS_VEL_E,          ///< GPS velocity east [m/s]
	GPS_VEL_D,          ///< GPS velocity down [m/s]
	MOTOR_0 = 6,        ///< motor 0 speed [rpm]
	MOTOR_1,            ///< motor 1 speed [rpm]
	MOTOR_2,            ///< motor 2 speed [rpm]
	MOTOR_3,            ///< motor 3 speed [rpm]
	NUM_CHANNELS = 10,  ///< number of channels (10)
};

/// Number of attack channels (GPS 6 + motors 4).
constexpr size_t kNumChannels = static_cast<size_t>(Channel::NUM_CHANNELS);

/// Capacity of each channel's time-series buffers (history + replay snapshot).
/// Bounds the max DELAY / REPLAY lookback to ~capacity / sample rate.
constexpr size_t kTimeSeriesCapacity = 4096;

/**
 * Array index of a channel in the per-channel tables (specs / state).
 */
constexpr size_t index_of(Channel ch)
{
	return static_cast<size_t>(ch);
}

/**
 * Motor channel for motor i (MOTOR_0 + i). Out-of-range i yields an invalid
 * channel that AttackManager::apply() safely treats as pass-through.
 */
constexpr Channel motor_channel(unsigned i)
{
	return static_cast<Channel>(static_cast<uint8_t>(Channel::MOTOR_0) + i);
}

/**
 * Serializable attack configuration for one channel.
 *
 * This is the unit that travels in attack_command and is logged for
 * reproducibility. It is a pure value; runtime state lives in ChannelState.
 */
struct AttackSpec {
	PrimitiveType type{PrimitiveType::NONE}; ///< Attack shape (NONE = disabled).
	double a{0.0};                           ///< Parameter a (meaning depends on type).
	double b{0.0};                           ///< Parameter b (meaning depends on type).
	double c{0.0};                           ///< Parameter c (meaning depends on type).
	double d{0.0};                           ///< Parameter d (meaning depends on type).
	uint64_t start_us{0};                    ///< Absolute hrt time the attack becomes active.
	uint64_t end_us{0};                      ///< Absolute hrt time the attack ends; 0 = no end.
	uint32_t seed{0};                        ///< RNG seed for stochastic primitives; 0 = per-channel default.
};

/**
 * Per-channel runtime state, owned by AttackManager (not serialized).
 */
struct ChannelState {
	double last_value{0.0};  ///< Last value that passed through (FREEZE / RANDOM_WALK).
	bool has_last{false};    ///< Whether last_value is valid.
	uint32_t rng_state{0};   ///< PRNG state, seeded by AttackManager::set().

	// Clean "truth" stream, recorded on every apply() call even while idle.
	// Never reset by set(): it is the channel's data, not the attack's state.
	uint64_t hist_time[kTimeSeriesCapacity]{};  ///< Sample timestamps [us], oldest..newest.
	double hist_value[kTimeSeriesCapacity]{};   ///< Sample values, same order as hist_time.
	size_t hist_head{0};                        ///< Next write slot.
	size_t hist_count{0};                       ///< Valid entries (<= capacity).

	// REPLAY loop snapshot, captured once at attack start and then cycled.
	uint64_t replay_offset[kTimeSeriesCapacity]{};  ///< Offset from (start - a), us.
	double replay_value[kTimeSeriesCapacity]{};     ///< Snapshot values.
	size_t replay_count{0};                         ///< Valid snapshot entries.
	bool replay_captured{false};                    ///< Whether the snapshot is valid.
};

/**
 * Result of applying an attack to one value.
 */
struct AttackResult {
	bool pass{true};   ///< false => drop the message (DROP only).
	double value{0.0}; ///< Tampered value; valid when pass is true.
};

/**
 * Stateless attack math.
 *
 * All per-channel state is passed in via ChannelState, so this class holds no
 * mutable state of its own.
 */
class AttackLibrary
{
public:
	/**
	 * Apply an attack to a scalar truth value.
	 *
	 * Every call first records (now_us, truth) into state's history (used
	 * by DELAY / REPLAY) before applying any transform.
	 *
	 * @param truth   the clean value to (possibly) tamper with
	 * @param spec    attack configuration for this channel
	 * @param now_us  current time, hrt_absolute_time() in microseconds
	 * @param state   per-channel runtime state (advanced by stochastic primitives)
	 * @return        pass=false means the message must be dropped (DROP only);
	 *                otherwise `value` is the tampered value
	 */
	static AttackResult apply(double truth, const AttackSpec &spec, uint64_t now_us, ChannelState &state);

	/**
	 * Whether an attack is currently within its active [start_us, end_us) window.
	 */
	static bool active(const AttackSpec &spec, uint64_t now_us);
};

} // namespace attack
