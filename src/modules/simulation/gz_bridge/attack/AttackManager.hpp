/****************************************************************************
 *
 * Attack injection — attack manager.
 *
 * Owns the per-channel attack table (Channel -> AttackSpec + ChannelState),
 * consumes uORB `attack_command`, applies attacks on demand, and publishes
 * uORB `attack_status` at 10 Hz.
 *
 * Threading: GPS injection runs on a gz-transport callback thread while the
 * motor injection and command handling run on the rate_ctrl work queue, so
 * every table access is guarded by a pthread mutex.
 *
 ****************************************************************************/

#pragma once

#include "AttackPrimitive.hpp"

#include <uORB/PublicationMulti.hpp>
#include <uORB/Subscription.hpp>
#include <uORB/topics/attack_command.h>
#include <uORB/topics/attack_status.h>

#include <pthread.h>

namespace attack
{

/**
 * Routes attack commands to per-channel specifications and applies them.
 */
class AttackManager
{
public:
	AttackManager() = default;
	~AttackManager();

	// Owns a mutex and uORB handles: not copyable / movable.
	AttackManager(const AttackManager &) = delete;
	AttackManager &operator=(const AttackManager &) = delete;

	/**
	 * Initialize the mutex and advertise the status topic.
	 * @return true on success
	 */
	bool init();

	/**
	 * Apply the attack configured for `ch` to `value`.
	 *
	 * @param ch       channel to attack
	 * @param value    in: clean value; out: (possibly) tampered value
	 * @param now_us   current hrt time in microseconds
	 * @return         false => the message must be dropped (DROP primitive fired);
	 *                 true  => `value` is valid and should be used
	 */
	bool apply(Channel ch, double &value, uint64_t now_us);

	/**
	 * Mount / replace the attack spec for a channel (resets its runtime state,
	 * including reseeding the PRNG: `spec.seed` if non-zero, else a per-channel
	 * deterministic default).
	 */
	void set(Channel ch, const AttackSpec &spec);

	/**
	 * Remove the attack on a channel (equivalent to set() with type=NONE).
	 */
	void clear(Channel ch);

	/**
	 * Consume the latest attack_command and publish attack_status at 10 Hz.
	 * Call periodically from the main loop (~100 Hz).
	 */
	void update();

private:
	/**
	 * Resolve a relative-time command (t0_us / t1_us) into an absolute
	 * AttackSpec and route it to the channel.
	 */
	void on_command(const attack_command_s &cmd, uint64_t now_us);

	/**
	 * Snapshot the current table into an attack_status message and publish it.
	 */
	void publish_status(uint64_t now_us);

	AttackSpec   _specs[kNumChannels]{};  ///< Per-channel attack configuration.
	ChannelState _state[kNumChannels]{};  ///< Per-channel runtime state (stochastic primitives).

	uORB::Subscription                 _cmd_sub{ORB_ID(attack_command)};
	uORB::Publication<attack_status_s> _status_pub{ORB_ID(attack_status)};

	pthread_mutex_t _lock{};
	bool _lock_initialized{false};

	uint64_t _last_status_us{0};  ///< hrt time of the last status publish (10 Hz gating).
};

} // namespace attack
