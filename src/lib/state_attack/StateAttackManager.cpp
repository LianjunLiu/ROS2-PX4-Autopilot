/****************************************************************************
 *
 * Post-EKF state attack — manager, implementation.
 *
 * Explicitly instantiates the manager for the two status topics actually used
 * (see the matching `extern template` declarations in StateAttackManager.hpp).
 *
 ****************************************************************************/

#include "StateAttackManager.hpp"

#include <drivers/drv_hrt.h>
#include <matrix/matrix/math.hpp>

namespace state_attack
{

template <typename StatusMsg>
StateAttackManager<StatusMsg>::StateAttackManager(const orb_metadata *status_meta, uint8_t first_channel, uint8_t num_channels)
	: _status_pub{status_meta}, _first_channel(first_channel), _num_channels(num_channels)
{
}

template <typename StatusMsg>
void StateAttackManager<StatusMsg>::init()
{
	_status_pub.advertise();
}

template <typename StatusMsg>
void StateAttackManager<StatusMsg>::update()
{
	const uint64_t now = hrt_absolute_time();

	state_attack_command_s cmd{};

	if (_cmd_sub.update(&cmd)) {
		on_command(cmd, now);
	}

	publish_status(now);
}

template <typename StatusMsg>
void StateAttackManager<StatusMsg>::apply_position(vehicle_local_position_s &v)
{
	const uint64_t now = hrt_absolute_time();
	_last_sample_us = v.timestamp_sample;

	double x = v.x;
	double y = v.y;
	double z = v.z;
	double vx = v.vx;
	double vy = v.vy;
	double vz = v.vz;
	double heading = v.heading;

	apply_channel(StateChannel::NAV_POS_X, x, now);
	apply_channel(StateChannel::NAV_POS_Y, y, now);
	apply_channel(StateChannel::NAV_POS_Z, z, now);
	apply_channel(StateChannel::NAV_VEL_X, vx, now);
	apply_channel(StateChannel::NAV_VEL_Y, vy, now);
	apply_channel(StateChannel::NAV_VEL_Z, vz, now);
	apply_channel(StateChannel::NAV_HEADING, heading, now);

	v.x = static_cast<float>(x);
	v.y = static_cast<float>(y);
	v.z = static_cast<float>(z);
	v.vx = static_cast<float>(vx);
	v.vy = static_cast<float>(vy);
	v.vz = static_cast<float>(vz);
	v.heading = static_cast<float>(heading);
}

template <typename StatusMsg>
void StateAttackManager<StatusMsg>::apply_attitude(vehicle_attitude_s &v)
{
	const uint64_t now = hrt_absolute_time();
	_last_sample_us = v.timestamp_sample;

	const matrix::Quatf q_in{v.q};
	const matrix::Eulerf e{q_in};

	double roll = e.phi();
	double pitch = e.theta();
	double yaw = e.psi();

	apply_channel(StateChannel::ATT_ROLL, roll, now);
	apply_channel(StateChannel::ATT_PITCH, pitch, now);
	apply_channel(StateChannel::ATT_YAW, yaw, now);

	const matrix::Quatf q_out{
		matrix::Eulerf(static_cast<float>(roll), static_cast<float>(pitch), static_cast<float>(yaw))};

	v.q[0] = q_out(0);
	v.q[1] = q_out(1);
	v.q[2] = q_out(2);
	v.q[3] = q_out(3);
}

template <typename StatusMsg>
void StateAttackManager<StatusMsg>::apply_channel(StateChannel ch, double &value, uint64_t now_us)
{
	const size_t idx = index_of(ch);

	if (idx < kNumStateChannels) {
		value = StateAttackLibrary::apply(value, _specs[idx], now_us, _state[idx]);
	}
}

template <typename StatusMsg>
void StateAttackManager<StatusMsg>::on_command(const state_attack_command_s &cmd, uint64_t now_us)
{
	if (cmd.channel >= kNumStateChannels) {
		return;  // Unknown channel.
	}

	const size_t idx = cmd.channel;
	StateAttackSpec &spec = _specs[idx];
	spec.type = static_cast<StatePrimitiveType>(cmd.type);
	spec.a = cmd.param[0];
	spec.b = cmd.param[1];
	spec.c = cmd.param[2];
	spec.d = cmd.param[3];
	spec.seed = cmd.seed;
	spec.start_us = now_us + cmd.t0_us;
	spec.end_us = (cmd.t1_us != 0) ? spec.start_us + cmd.t1_us : 0;

	// Reset runtime state (reseed the PRNG). seed != 0 uses spec.seed,
	// seed == 0 uses the per-channel deterministic default so reruns match.
	StateChannelState &state = _state[idx];
	state.last_value = 0.0;
	state.has_last = false;
	state.rng_state = (spec.seed != 0) ? spec.seed : default_seed(idx);
}

template <typename StatusMsg>
void StateAttackManager<StatusMsg>::publish_status(uint64_t now_us)
{
	StatusMsg status{};
	status.timestamp = now_us;
	status.timestamp_sample = _last_sample_us;

	for (uint8_t i = 0; i < _num_channels; i++) {
		const size_t idx = _first_channel + i;
		status.active[i] = StateAttackLibrary::active(_specs[idx], now_us) ? 1 : 0;
		status.type[i] = static_cast<uint8_t>(_specs[idx].type);
		status.param_a[i] = _specs[idx].a;
		status.param_b[i] = _specs[idx].b;
		status.param_c[i] = _specs[idx].c;
		status.param_d[i] = _specs[idx].d;
		status.value[i] = _state[idx].last_value;  // controller-seen (unattacked = truth)
	}

	_status_pub.publish(status);
}

template <typename StatusMsg>
uint32_t StateAttackManager<StatusMsg>::default_seed(size_t idx)
{
	return 0x9E3779B9u + static_cast<uint32_t>(idx);
}

// Explicit instantiation for the two status topics actually used by the
// controller modules (see the extern template declarations in the header).
template class StateAttackManager<state_attack_pos_status_s>;
template class StateAttackManager<state_attack_att_status_s>;

} // namespace state_attack
