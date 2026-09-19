/****************************************************************************
 *
 * Attack injection — attack manager, implementation.
 *
 ****************************************************************************/

#include "AttackManager.hpp"

#include <drivers/drv_hrt.h>

namespace attack
{
namespace
{

constexpr uint64_t STATUS_PERIOD_US = 100000;  // 10 Hz status publish

/**
 * Deterministic per-channel seed for `seed == 0` commands.
 *
 * The default is reproducible (an experiment reruns identically without
 * remembering a seed) but distinct per channel, so two channels attacked with
 * the same stochastic primitive don't share one identical noise stream and
 * become perfectly correlated (e.g. GPS lat/lon drifting along a straight
 * diagonal instead of a 2-D random walk).
 */
uint32_t default_seed(size_t idx)
{
	constexpr uint32_t kBase = 0x9E3779B9u;
	return kBase + static_cast<uint32_t>(idx);
}

/**
 * Build an AttackSpec from a uORB command, resolving the relative window
 * (t0_us delay, t1_us duration) to absolute hrt times.
 */
AttackSpec make_spec(const attack_command_s &cmd, uint64_t now_us)
{
	AttackSpec spec{};
	spec.type = static_cast<PrimitiveType>(cmd.type);
	spec.a = cmd.param[0];
	spec.b = cmd.param[1];
	spec.c = cmd.param[2];
	spec.d = cmd.param[3];
	spec.seed = cmd.seed;

	spec.start_us = now_us + cmd.t0_us;
	spec.end_us = (cmd.t1_us != 0) ? spec.start_us + cmd.t1_us : 0;
	return spec;
}

} // namespace

AttackManager::~AttackManager()
{
	if (_lock_initialized) {
		pthread_mutex_destroy(&_lock);
	}
}

bool AttackManager::init()
{
	if (pthread_mutex_init(&_lock, nullptr) != 0) {
		return false;
	}

	_lock_initialized = true;

	// Advertise up front so subscribers (logger / DDS) see the topic immediately.
	_status_pub.advertise();
	return true;
}

void AttackManager::set(Channel ch, const AttackSpec &spec)
{
	const size_t idx = index_of(ch);

	if (idx >= kNumChannels) {
		return;
	}

	pthread_mutex_lock(&_lock);

	_specs[idx] = spec;

	// Reset the runtime state. Seeding here (not inside apply()) keeps the
	// stochastic primitives reproducible: seed != 0 uses spec.seed, seed == 0
	// uses the per-channel deterministic default. The history buffer is left
	// intact: it is the channel's data stream, not the current attack's state,
	// and DELAY / REPLAY need its pre-roll.
	ChannelState &state = _state[idx];
	state.last_value = 0.0;
	state.has_last = false;
	state.rng_state = (spec.seed != 0) ? spec.seed : default_seed(idx);
	state.replay_captured = false;
	state.replay_count = 0;

	pthread_mutex_unlock(&_lock);
}

void AttackManager::clear(Channel ch)
{
	AttackSpec none{};  // type == NONE => pass through
	set(ch, none);
}

bool AttackManager::apply(Channel ch, double &value, uint64_t now_us)
{
	const size_t idx = index_of(ch);

	if (idx >= kNumChannels) {
		return true;  // Unknown channel: pass through untouched.
	}

	pthread_mutex_lock(&_lock);
	const AttackResult result = AttackLibrary::apply(value, _specs[idx], now_us, _state[idx]);
	pthread_mutex_unlock(&_lock);

	if (result.pass) {
		value = result.value;
	}

	return result.pass;
}

void AttackManager::update()
{
	const uint64_t now = hrt_absolute_time();

	// Consume the latest command (between polls, the newest one wins).
	attack_command_s cmd{};

	if (_cmd_sub.update(&cmd)) {
		on_command(cmd, now);
	}

	// Publish status at 10 Hz.
	if (now - _last_status_us >= STATUS_PERIOD_US) {
		publish_status(now);
		_last_status_us = now;
	}
}

void AttackManager::on_command(const attack_command_s &cmd, uint64_t now_us)
{
	if (cmd.channel >= kNumChannels) {
		return;  // Unknown channel.
	}

	set(static_cast<Channel>(cmd.channel), make_spec(cmd, now_us));
}

void AttackManager::publish_status(uint64_t now_us)
{
	attack_status_s status{};
	status.timestamp = now_us;

	pthread_mutex_lock(&_lock);

	for (size_t ch = 0; ch < kNumChannels; ch++) {
		status.active[ch] = AttackLibrary::active(_specs[ch], now_us) ? 1 : 0;
		status.type[ch] = static_cast<uint8_t>(_specs[ch].type);
		status.param_a[ch] = _specs[ch].a;
		status.param_b[ch] = _specs[ch].b;
		status.param_c[ch] = _specs[ch].c;
		status.param_d[ch] = _specs[ch].d;
	}

	pthread_mutex_unlock(&_lock);

	_status_pub.publish(status);
}

} // namespace attack
