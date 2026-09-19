# Post-EKF attitude attack status (PX4 -> ROS2 / logger).
# Per-channel snapshot of what the attitude controller actually saw (attacked-or-truth Euler angles),
# published by mc_att_control every loop.

uint64 timestamp		# time since system start (microseconds)
uint64 timestamp_sample		# vehicle_attitude.timestamp_sample this value[] was derived from

uint8[3] active			# per channel: 1 = attack currently active, 0 = inactive
uint8[3] type			# per channel: current PrimitiveType enum value (meaningful when active)

float64[3] param_a		# per channel: primitive parameter a
float64[3] param_b		# per channel: primitive parameter b
float64[3] param_c		# per channel: primitive parameter c
float64[3] param_d		# per channel: primitive parameter d

float64[3] value		# per channel: controller-seen Euler angle (roll/pitch/yaw, rad); unattacked = truth
