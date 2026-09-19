# Attack injection command (ROS2 -> PX4).
# Instructs the AttackManager to mount / update / clear an attack on one channel.
#
# One message = one channel. Sending a message with type=NONE clears the channel.
# The next sample on that channel reflects the change (GPS ~5-10 Hz, motors high rate).

uint64 timestamp		# time since system start (microseconds)

uint8 channel			# Channel enum value (0..9): GPS_LAT..GPS_VEL_D, MOTOR_0..MOTOR_3
uint8 type			# PrimitiveType enum value (0=NONE -> clear the attack)

float64[4] param		# primitive parameters (a, b, c, d); meaning depends on 'type'

uint64 t0_us			# start delay relative to command arrival (microseconds); 0 = immediately
uint64 t1_us			# duration relative to start (microseconds); 0 = until cleared
uint32 seed			# RNG seed for stochastic primitives; 0 = random
