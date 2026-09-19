# Attack injection status (PX4 -> ROS2 / logger).
# Snapshot of which channels are currently under attack, published at 10 Hz.

uint64 timestamp		# time since system start (microseconds)

uint8[10] active		# per channel: 1 = attack currently active (now in [start_us, end_us]), 0 = inactive
uint8[10] type			# per channel: current PrimitiveType enum value (meaningful when active)

float64[10] param_a		# per channel: primitive parameter a
float64[10] param_b		# per channel: primitive parameter b
float64[10] param_c		# per channel: primitive parameter c
float64[10] param_d		# per channel: primitive parameter d
