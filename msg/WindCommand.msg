# Wind injection command (ROS2 -> PX4 -> ulog).
#
# Mirrors the gz.msgs.Wind that the ROS2 wind_injector node publishes to
# gz-sim, so the applied wind is also recorded in the ulog for reproducibility.
# This topic is log-only: nothing in PX4 consumes it; the wind itself is applied
# directly by the gz-sim WindEffects plugin.

uint64 timestamp		# time since system start (microseconds)

float64[3] velocity		# wind velocity [m/s], world ENU (x/y/z)
bool enable_wind		# true = wind enabled
