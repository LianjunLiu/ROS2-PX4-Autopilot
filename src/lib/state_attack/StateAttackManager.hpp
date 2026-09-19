/****************************************************************************
 *
 * Post-EKF state attack — manager.
 *
 * Owns the per-channel attack table (StateChannel -> StateAttackSpec +
 * StateChannelState), consumes uORB `state_attack_command`, applies attacks
 * on demand, and publishes a per-module status topic.
 *
 * One instance lives in each of the two controller modules, differing only in
 * the status message type it publishes and the channel subset it owns:
 *
 *   mc_pos_control: StateAttackManager<state_attack_pos_status_s> {…, 0, 7}
 *   mc_att_control: StateAttackManager<state_attack_att_status_s> {…, 7, 3}
 *
 * Both subscribe to the SAME broadcast `state_attack_command` and maintain the
 * same full 10-channel table, but each applies only its own channels. No
 * mutex: a manager runs entirely inside its module's control loop.
 *
 * The class is a template only so the status publication is type-safe against
 * the concrete status topic. The implementation lives in StateAttackManager.cpp
 * and is explicitly instantiated for the two status types actually used (see
 * the `extern template` declarations below); modules link those instantiations
 * instead of compiling their own copy.
 *
 ****************************************************************************/

#pragma once

#include "StateAttackPrimitive.hpp"

#include <uORB/Publication.hpp>
#include <uORB/Subscription.hpp>
#include <uORB/topics/state_attack_att_status.h>
#include <uORB/topics/state_attack_command.h>
#include <uORB/topics/state_attack_pos_status.h>
#include <uORB/topics/vehicle_attitude.h>
#include <uORB/topics/vehicle_local_position.h>

namespace state_attack
{

template <typename StatusMsg>
class StateAttackManager
{
public:
	StateAttackManager(const orb_metadata *status_meta, uint8_t first_channel, uint8_t num_channels);

	/// Advertise the status topic up front so subscribers (logger / DDS) see it immediately.
	void init();

	/// Consume the latest command and publish the status topic. Call every loop.
	void update();

	/// In-place tamper the 7 nav fields (channels 0..6) of a local position sample.
	void apply_position(vehicle_local_position_s &v);

	/// In-place tamper the 3 attitude channels (7..9) in the Euler domain, then
	/// rebuild a unit quaternion (mutating q components directly would break the
	/// unit norm).
	void apply_attitude(vehicle_attitude_s &v);

private:
	void apply_channel(StateChannel ch, double &value, uint64_t now_us);
	void on_command(const state_attack_command_s &cmd, uint64_t now_us);
	void publish_status(uint64_t now_us);

	static uint32_t default_seed(size_t idx);

	StateAttackSpec _specs[kNumStateChannels]{};
	StateChannelState _state[kNumStateChannels]{};

	uORB::Subscription _cmd_sub{ORB_ID(state_attack_command)};
	uORB::Publication<StatusMsg> _status_pub;

	uint8_t _first_channel{0};
	uint8_t _num_channels{0};
	uint64_t _last_sample_us{0};
};

// Concrete instantiations are compiled in StateAttackManager.cpp. These extern
// declarations stop the two controller modules from instantiating their own
// copies; they link the state_attack library's definitions instead.
extern template class StateAttackManager<state_attack_pos_status_s>;
extern template class StateAttackManager<state_attack_att_status_s>;

} // namespace state_attack
