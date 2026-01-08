from dronekit import connect, VehicleMode, LocationGlobalRelative
import time
import math

# --------------------------------------------------
# Connect to simulated drone (TCP)
# --------------------------------------------------
print("Connecting to drone...")
vehicle = connect("tcp:127.0.0.1:5763", wait_ready=True)
print("Connected")

# --------------------------------------------------
# Arm and Takeoff
# --------------------------------------------------
def arm_and_takeoff(target_altitude):
    while not vehicle.is_armable:
        print("Waiting for vehicle to be armable...")
        time.sleep(1)

    vehicle.mode = VehicleMode("GUIDED")
    vehicle.armed = True

    while not vehicle.armed:
        print("Arming...")
        time.sleep(1)

    print("Taking off...")
    vehicle.simple_takeoff(target_altitude)

    while True:
        alt = vehicle.location.global_relative_frame.alt
        print(f"Altitude: {alt:.2f}")
        if alt >= target_altitude * 0.95:
            print("Reached target altitude")
            break
        time.sleep(1)

# --------------------------------------------------
# Move forward relative to HOME (North direction)
# --------------------------------------------------
def get_location_offset_meters(original_location, dNorth, dEast):
    earth_radius = 6378137.0

    dLat = dNorth / earth_radius
    dLon = dEast / (earth_radius * math.cos(math.pi * original_location.lat / 180))

    new_lat = original_location.lat + (dLat * 180 / math.pi)
    new_lon = original_location.lon + (dLon * 180 / math.pi)

    return LocationGlobalRelative(
        new_lat,
        new_lon,
        original_location.alt
    )

# --------------------------------------------------
# MAIN
# --------------------------------------------------
arm_and_takeoff(10)   # Takeoff to 10 meters

home = vehicle.location.global_relative_frame
print("Home location:", home)

# Move 100 meters forward (North)
target_location = get_location_offset_meters(home, dNorth=100, dEast=0)

print("Moving forward 100 meters...")
vehicle.simple_goto(target_location)

time.sleep(15)

print("Movement completed")

# --------------------------------------------------
# Close connection
# --------------------------------------------------
vehicle.close()
print("Disconnected")